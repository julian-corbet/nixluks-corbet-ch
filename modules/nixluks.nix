# modules/nixluks.nix -- declare your LUKS2 volumes, unlock them with one passphrase, back up
# their headers, and catch drift in what cryptsetup reports back. THIN by design, the same
# posture as the sibling nixnas/nixvault/nixfs projects: this module does not reinvent LUKS --
# `cryptsetup` and systemd's own crypttab generator do the actual work. It adds the one thing
# that is fiddly to get right and easy to get wrong by hand: a declared, ordered, auditable chain
# from "these ciphertexts exist" to "they are open, their headers are backed up somewhere private,
# and a live drift in what they actually are gets caught instead of discovered during a recovery".
#
# THIS IS AN EXTRACTION. The serial-unlock-with-keyring-cache mechanism below is lifted, not
# reinvented, from nixnas's modules/storage/connect.nix (`storage.unlock`), generalised so any
# host -- a fleet member, a disaster-recovery vault, a rescue image -- can declare the same chain
# without depending on nixnas's appliance-specific USB/hot-store machinery. Read that file's own
# header for the field-proven design this one lifts out; what follows restates it in
# host-agnostic terms and adds header-backup orchestration and drift verification, which did not
# exist anywhere before this repo.
#
# THE MECHANISM, restated in connect.nix's own words: each declared volume opens SERIALLY via
# `systemd-cryptsetup@<name>.service` (systemd's own crypttab-generator units); the FIRST
# passphrase entered is cached in the kernel keyring and opens the rest silently -- one prompt for
# the whole set. This is systemd's own password cache, not anything nixluks implements: the chain
# below exists ONLY to guarantee the members are opened in a fixed, repeatable order (each unit
# `after`-ordered on the one before it, by `volumes.<name>.order` with the name itself as a
# tie-break -- never left to attribute-definition order, which Nix does not preserve), so the
# cache is reliably warm by the time the second member asks. SERIALISATION IS LOAD-BEARING: two
# members opening in parallel would each prompt independently (parallel systemd jobs do not share
# an in-flight terminal question), so this module never parallelises the chain -- see the
# `systemd.services` chain built from `sortedNames` below, which is the entire mechanism, three
# lines of `after`.
#
# SECURITY MODEL -- this is the point of the repo:
#
# This module NEVER touches key material. It cannot leak a passphrase because it never has one at
# any point in its own code. The passphrase exists in exactly three places, ever:
#   1. the operator's head;
#   2. the LUKS header on disk, as a KDF-wrapped master key (computationally useless without the
#      passphrase, which is the entire premise of LUKS);
#   3. the kernel keyring, transiently, for the duration of the unlock chain above -- systemd's
#      own cache, torn down like any other kernel keyring, never written to disk by this module.
# It is NEVER the Nix store (world-readable -- anything placed there via `pkgs.writeText` or an
# option default is a promise to leak it to every local user), NEVER a rendered NixOS/system-manager
# config, NEVER committed to git, NEVER a keyfile on disk, and NEVER an environment variable (visible
# via /proc/<pid>/environ to anyone who can read it). Every shell tool this module writes
# (`nixluks-unlock`, `nixluks-backup-headers`, `nixluks-verify`) is auditable precisely because none
# of them accept, generate, store, or forward a passphrase anywhere except the interactive terminal
# `systemd-tty-ask-password-agent` / a bare `cryptsetup` prompt already reads from -- the SAME
# channel an operator typing at a console or over an authenticated SSH session already trusts.
#
# What IS declared here is deliberately all non-secret, public metadata about the ciphertext, never
# the key:
#   - which devices are LUKS, named by UUID or by-id (`volumes.<name>.device` -- see
#     lib/device-path.nix for why never a bare /dev/sdX);
#   - the mapper name each opens as (the attribute name itself -- `/dev/mapper/<name>`);
#   - `raiseMode`, the unlock POLICY as a STANCE, never a credential: whether this host's volumes
#     start locked (the rescue/appliance stance -- operator raises them later) or are assumed
#     already opened upstream of this module (the hub/hot-store stance -- see "HOT MODE" below);
#   - unlock ORDER (`volumes.<name>.order`), which only ever changes the sequence of prompts, never
#     what is being unlocked;
#   - header-backup DESTINATIONS (non-secret: a path, not a key -- though see "HEADER BACKUPS ARE
#     SENSITIVE" below for why the path's own permissions still matter);
#   - EXPECTED header shape (`volumes.<name>.expect.*` -- slot count, cipher, KDF): public metadata
#     `cryptsetup luksDump` already reports without a passphrase, asserted here only so a live
#     drift from the declaration is caught, never used to derive or check the passphrase itself.
#
# SAFETY INVARIANT, inherited from connect.nix verbatim in spirit: nixluks only OPENS declared
# volumes and READS BACK / COPIES their headers (`cryptsetup luksDump`, `cryptsetup
# luksHeaderBackup` -- both read-only against the ciphertext, neither one touches the master key or
# needs a passphrase). It never creates, `luksFormat`s, adds/removes a keyslot, or destroys a
# device. This is not just a comment to trust: checks/default.nix's own "STRUCTURALLY SAFE" check
# reads this very file's source text and fails the build if any of `luksFormat`, `luksErase`,
# `luksAddKey`, `luksRemoveKey`, `luksKillSlot`, `wipefs`, or `mkfs.` ever appears in it -- so a
# future edit that added one of those calls would fail CI before it could ship, not rely on a
# reviewer noticing.
#
# HEADER BACKUPS ARE SENSITIVE. A LUKS header backup (`cryptsetup luksHeaderBackup`) is NOT the
# passphrase, but it IS the KDF-wrapped master key plus every keyslot -- with the passphrase (or a
# weak one, brute-forced offline against a copy an attacker can take their time with), it opens the
# volume exactly as completely as the passphrase would against the original header. Treat a header
# backup's DESTINATION as sensitive as the device it came from. `headerBackup.destination` refuses
# to build (an eval-time assertion, not a runtime hope) if it resolves under `/tmp`, `/var/tmp`, or
# `/dev/shm` -- all world-readable or world-writable by convention on a stock Linux install -- and
# `nixluks-backup-headers` itself refuses at RUNTIME, before writing a single byte, if the
# destination's parent directory grants any access to anyone but its owner (see that tool's own
# permission check below, next to `nixluks-backup-headers`'s definition). A vault is exactly the
# right place for one: see "vs nixvault" below.
#
# HOT MODE -- the case connect.nix calls out, generalised: `raiseMode = "preopened"` means
# something upstream of this module (an initrd unlock -- see nixboot's own `remoteUnlock` -- or an
# operator's own earlier manual `cryptsetup open`) has ALREADY opened every declared volume by the
# time stage-2 starts. In that mode `nixluks-storage.target` auto-raises at boot
# (`wantedBy = [ "multi-user.target" ]`) but its `wants`/`after` DELIBERATELY OMIT the
# `systemd-cryptsetup@` units -- re-running an open against an already-open mapper is at best a
# no-op and at worst a SECOND prompt for a passphrase that was already consumed once. The default,
# `raiseMode = "cold"`, is the opposite: every volume is genuinely locked when stage-2 starts, the
# target stays inert until `nixluks-unlock` raises it, and THAT raise pulls in the
# `systemd-cryptsetup@` chain. Either way there is exactly one code path that can ever start a
# given `systemd-cryptsetup@<name>.service` -- never both.
#
# SCOPE -- what this module owns, so no knob has two managers:
#   OWNED : which devices are LUKS2 and what they're called (`volumes`), the order they unlock in,
#           the stance that governs WHEN that unlock happens (`raiseMode`), header-backup
#           orchestration to a declared destination, and drift verification against the live
#           header (`nixluks-verify`).
#   NOT   : unlocking IN THE INITRD to reach switch-root -- that is nixboot's domain (its own
#           `remoteUnlock` already does initrd-SSH + TPM2). nixluks owns everything unlocked AFTER
#           stage-2 starts; a volume nixboot's initrd already opened is declared here with
#           `raiseMode = "preopened"`, never re-opened.
#   NOT   : the medium's geometry -- partitions, sizes, which region plays which role. That is
#           nixstorage's domain: nixstorage declares the geometry, nixluks declares the CRYPTO
#           LAYER on a region nixstorage already named. Geometry -> crypto -> filesystem, three
#           separate declarations, never one module doing all three.
#   NOT   : what goes INSIDE an unlocked volume, or how its contents are assembled, staged, or
#           committed -- that is nixvault's domain when the volume in question is a vault. A vault
#           is not a special case nixluks needs to know about: it is just another member of
#           `volumes`, keyed the same as any other disk, unlocked by the same chain. nixluks owns
#           the KEYING; nixvault owns the CONTENTS.
#   NOT   : importing a ZFS pool, mounting a filesystem, or starting a dependent service once a
#           volume is open -- native NixOS/system-manager `fileSystems` and `systemd.services`
#           already do this well; gate them on `nixluks-storage.target` the same way connect.nix's
#           own header tells an operator to (`"noauto" "x-systemd.wanted-by=nixluks-storage.target"`
#           in the `fileSystems` entry's options).
#
# ONE FILE, BOTH BACKENDS -- exported unchanged as both `nixosModules.default` and
# `systemManagerModules.default` (see flake.nix), the same shape as nixfs's modules/install.nix and
# nixvault's modules/nixvault.nix, and for the identical reason: everything below resolves to
# option surface system-manager supports IDENTICALLY to NixOS, confirmed by reading its actual
# module source (numtide/system-manager, nix/modules/{etc,systemd}.nix), not assumed:
#   - `environment.etc."crypttab"` -- a real system-manager option (nix/modules/etc.nix), the exact
#     same symlink-into-/etc mechanism NixOS itself uses, and the ONLY thing that has to reach
#     `/etc/crypttab` for systemd's own (not NixOS's, not system-manager's) crypttab generator to
#     pick it up -- that generator lives in the systemd package already on the base system either
#     way.
#   - `systemd.services.*` / `systemd.targets.*` (including `overrideStrategy = "asDropin"`, used
#     below to layer an `after=` onto the crypttab-generated units) -- real, fully-supported options
#     (nix/modules/systemd.nix) built from the identical nixpkgs `systemdUtils` code NixOS itself
#     uses.
#   - `assertions` / `warnings` -- real options, enforced at build time exactly like NixOS
#     (nix/lib.nix's `returnIfNoAssertions`).
#   - `environment.systemPackages` -- how every `nixluks-*` tool actually reaches the host's PATH,
#     identical on both backends.
# What this module deliberately never touches is exactly what system-manager cannot do:
# `boot.*` (no bootloader/kernel/initrd surface -- irrelevant anyway, see SCOPE above: the initrd
# is nixboot's domain, not this module's) and `users.*` (no dedicated service account -- every
# `nixluks-*` tool runs as whoever invokes it, root for the ones that touch a real device node,
# same as a bare `cryptsetup` command would need). Nothing in nixluks's actual job -- reading and
# writing crypttab entries, a handful of systemd units, and a few shell tools -- ever needed
# either, unlike nixram's zswap/oomd surface, which genuinely does need a NixOS-only escape hatch
# on one backend (see that project's own system-manager/ split for the case where "one file" is
# NOT the honest answer).
{ config, lib, pkgs, ... }:

let
  cfg = config.nixluks;
  inherit (lib)
    mkEnableOption mkOption mkIf mkMerge types literalExpression
    concatStringsSep concatMapStringsSep mapAttrsToList listToAttrs nameValuePair
    imap0 optional optionals optionalString sort filter filterAttrs attrNames;

  devicePathType = import ../lib/device-path.nix { inherit lib; };

  volNames = attrNames cfg.volumes;

  # Deterministic unlock order: `order` (an explicit int, never attribute-definition order, which
  # Nix does not preserve) with the NAME itself as a tie-break so two volumes can never collide
  # into an undefined sequence even before the "duplicate order" assertion below catches the
  # common case of a copy-pasted declaration. This is the one property connect.nix's header calls
  # load-bearing (the serial chain only keeps the keyring cache warm if the order is fixed and
  # repeatable) -- restated with an explicit field instead of connect.nix's own `attrNames` sort,
  # because a fleet/vault/rescue's volumes are not always nameable in the order they should open.
  byOrder = a: b:
    let oa = cfg.volumes.${a}.order; ob = cfg.volumes.${b}.order;
    in if oa != ob then oa < ob else a < b;
  sortedNames = sort byOrder volNames;

  unlockUnitName = n: "systemd-cryptsetup@${n}.service";
  unlockUnits = map unlockUnitName sortedNames;

  isPreopened = cfg.raiseMode == "preopened";

  # `name -> /dev/mapper/name`, a STABLE mapper the operator (or a downstream fileSystems entry)
  # references. `noauto`: nothing opens at boot from crypttab alone -- nixluks-storage.target pulls
  # these on demand (`cold`) or they are simply already open before this unit graph exists
  # (`preopened`). `nofail`: a missing/degraded disk never fails the target -- non-fatal by design,
  # the same stance connect.nix's own crypttab line takes.
  # ONLY volumes this module actually owns the unlock for. A volume with
  # manageUnlock = false contributes no crypttab line and no ordering edge -- it is
  # present purely so header backup and verification can see it.
  managedNames = filter (n: cfg.volumes.${n}.manageUnlock) sortedNames;

  crypttab = concatStringsSep "\n"
    (map (n: "${n} ${cfg.volumes.${n}.device} none luks,noauto,nofail") managedNames);

  volumesWithBackup = filterAttrs (_: v: v.headerBackup.destination != null) cfg.volumes;
  backupNames = attrNames volumesWithBackup;

  # A destination under one of these is refused outright at eval time -- world-readable or
  # world-writable by Linux convention, and a header backup is sensitive enough (see this file's
  # own "HEADER BACKUPS ARE SENSITIVE" header section) that "convention" is not good enough to
  # trust at runtime alone; `nixluks-backup-headers`'s own `checkPrivateDir` is the runtime half of
  # this same check, for the destinations that pass this eval-time filter but whose parent
  # directory's ACTUAL permissions turn out to be wrong when the tool runs.
  unsafeBackupPrefixes = [ "/tmp/" "/var/tmp/" "/dev/shm/" ];
  isUnsafeBackupPath = p: lib.any (pre: lib.hasPrefix pre p) unsafeBackupPrefixes;

  nixluks-unlock = pkgs.writeShellApplication {
    name = "nixluks-unlock";
    runtimeInputs = [ pkgs.systemd ];
    text = ''
      # nixluks-unlock -- one passphrase opens every declared volume and raises
      # nixluks-storage.target. See modules/nixluks.nix's own header for the full mechanism.
      echo ">> nixluks-unlock: raising nixluks-storage.target"
      systemctl start --no-block nixluks-storage.target

      # Surface each pending password question on THIS terminal. Volumes open serially, in the
      # declared order; after the first answer the kernel-keyring cache opens the rest silently.
      while systemctl list-jobs --no-legend | grep -Eq 'nixluks-storage|cryptsetup'; do
        systemd-tty-ask-password-agent --query || true
        sleep 1
      done

      echo
      failed="$(systemctl list-units --failed --no-legend 'systemd-cryptsetup@*.service' || true)"
      if [ -n "$failed" ]; then
        echo ">> some volumes did NOT open (non-fatal by design -- a missing/degraded disk never fails the set):"
        echo "$failed"
      fi
      echo ">> nixluks-storage.target: $(systemctl is-active nixluks-storage.target || true)"
    '';
  };

  nixluks-backup-headers = pkgs.writeShellApplication {
    name = "nixluks-backup-headers";
    runtimeInputs = [ pkgs.cryptsetup pkgs.coreutils ];
    text = ''
      # nixluks-backup-headers -- copies each declared volume's LUKS header (the KDF-wrapped
      # master key and every keyslot, never the passphrase, never anything decrypted) to its
      # declared destination. Needs no passphrase: `cryptsetup luksHeaderBackup` reads the
      # ciphertext header only. Needs root (or CAP_DAC_READ_SEARCH) to read the raw device node,
      # the same as any other tool touching a block device directly.
      #
      # `writeShellApplication` turns `errexit` ON by default; turned back OFF here on purpose --
      # one volume's backup failing (a disconnected disk, a bad destination) must never abort the
      # loop before the OTHER declared volumes get their turn. `fail` is accumulated explicitly
      # instead, and checked once at the end.
      set +o errexit
      fail=0
      ${concatMapStringsSep "\n" (n: ''
        echo "== ${n} (role: ${if cfg.volumes.${n}.role == null then "unspecified" else cfg.volumes.${n}.role}) -> ${cfg.volumes.${n}.headerBackup.destination}"
        dest="${cfg.volumes.${n}.headerBackup.destination}"
        destdir="$(dirname "$dest")"
        if [ ! -d "$destdir" ]; then
          echo "FAIL  ${n}: destination directory $destdir does not exist -- create it (mode 0700) before backing up into it"
          fail=1
        else
          # Refuse a destination directory that grants ANY access to group or other -- a header
          # backup contains the wrapped master key; see this module's own "HEADER BACKUPS ARE
          # SENSITIVE" header section for why this is refused, not merely warned about.
          mode="$(stat -c '%a' "$destdir")"
          other_bits="''${mode: -1}"
          group_bits="''${mode: -2:1}"
          if [ "$other_bits" != "0" ] || [ "$group_bits" != "0" ]; then
            echo "FAIL  ${n}: $destdir is mode $mode -- grants group or other access. A header backup is as sensitive as the passphrase-protected device it came from (with the passphrase, it opens everything); refusing to write one anywhere but a directory only its owner can read. chmod 0700 $destdir and retry."
            fail=1
          elif cryptsetup luksHeaderBackup --header-backup-file "$dest" "${cfg.volumes.${n}.device}"; then
            chmod 0600 "$dest"
            echo "PASS  ${n}: header backed up to $dest (mode 0600)"
          else
            echo "FAIL  ${n}: cryptsetup luksHeaderBackup against ${cfg.volumes.${n}.device} did not succeed -- see its own error output above"
            fail=1
          fi
        fi
      '') backupNames}
      if [ "$fail" -ne 0 ]; then
        echo "nixluks-backup-headers: at least one destination was refused -- see FAIL lines above. Nothing was written for that volume; existing backups for OTHER volumes above still ran."
        exit 1
      fi
    '';
  };

  # The expected-shape comparison, shared between the boot-time verify service and the standalone
  # CLI tool below -- one script, not two copies that could drift from each other.
  verifyScript = ''
    # `writeShellApplication` turns `errexit` ON by default; turned back OFF here on purpose --
    # a failed readback (a missing disk, a `luksDump` that errors) is DATA this script reports on
    # a line of its own, never an engine crash that skips every volume declared after it.
    set +o errexit
    fail=0

    ${concatMapStringsSep "\n" (n:
      let
        v = cfg.volumes.${n};
        roleLabel = if v.role == null then "unspecified" else v.role;
      in ''
        echo "== ${n} (role: ${roleLabel}, device: ${v.device})"
        if [ ! -e "${v.device}" ]; then
          echo "WARN  ${n}: ${v.device} does not exist right now -- disk absent/not attached (non-fatal, same stance as an unlock target that never fails the whole set for one missing member)"
        elif ! cryptsetup isLuks "${v.device}" 2>/dev/null; then
          echo "FAIL  ${n}: ${v.device} exists but is not a LUKS device at all"
          fail=1
        else
          json="$(cryptsetup luksDump --dump-json-metadata "${v.device}" 2>/dev/null || true)"
          if [ -z "$json" ]; then
            echo "FAIL  ${n}: ${v.device} is LUKS but not LUKS2 (or this cryptsetup lacks --dump-json-metadata) -- nixluks targets LUKS2 only"
            fail=1
          else
            ${optionalString (v.expect.cipher != null) ''
              live_cipher="$(echo "$json" | jq -r '.segments["0"].encryption // "unknown"')"
              if [ "$live_cipher" = "${v.expect.cipher}" ]; then
                echo "PASS  ${n}: cipher = ${v.expect.cipher}"
              else
                echo "FAIL  ${n}: expected cipher ${v.expect.cipher}, live header reports $live_cipher"
                fail=1
              fi
            ''}
            ${optionalString (v.expect.slotCount != null) ''
              live_slots="$(echo "$json" | jq -r '.keyslots | length')"
              if [ "$live_slots" -eq ${toString v.expect.slotCount} ]; then
                echo "PASS  ${n}: slot count = ${toString v.expect.slotCount}"
              else
                echo "FAIL  ${n}: expected ${toString v.expect.slotCount} occupied keyslot(s), live header has $live_slots -- a keyslot was added or removed by hand outside this declaration, or a rotation only half-happened"
                fail=1
              fi
            ''}
            ${optionalString (v.expect.kdf != null) ''
              live_kdfs="$(echo "$json" | jq -r '.keyslots[].kdf.type' | sort -u | tr '\n' ',' | sed 's/,$//')"
              if [ "$live_kdfs" = "${v.expect.kdf}" ]; then
                echo "PASS  ${n}: every occupied keyslot uses kdf = ${v.expect.kdf}"
              else
                echo "FAIL  ${n}: expected every keyslot to use kdf = ${v.expect.kdf}, live header has: $live_kdfs -- a keyslot with a weaker or different KDF exists that this declaration does not account for"
                fail=1
              fi
            ''}
            ${optionalString (v.expect.cipher == null && v.expect.slotCount == null && v.expect.kdf == null) ''
              echo "SKIP  ${n}: no expected header shape declared (volumes.${n}.expect.*) -- nothing to compare"
            ''}
          fi
        fi
      ''
    ) sortedNames}

    if [ "$fail" -ne 0 ]; then
      echo "nixluks-verify: at least one declared volume's live header did not match its declaration. See FAIL lines above -- this is exactly the class of drift (a keyslot added by hand, a rotation that only half-happened) that is invisible until a recovery is already underway. Treat it as urgent."
      exit 1
    fi
    echo "nixluks-verify: every declared volume's live header matched its declaration (or was absent, or had nothing declared to check)."
  '';

  nixluks-verify = pkgs.writeShellApplication {
    name = "nixluks-verify";
    runtimeInputs = [ pkgs.cryptsetup pkgs.jq pkgs.coreutils pkgs.gnused ];
    text = verifyScript;
  };

  volumeModule = { name, ... }: {
    options = {
      device = mkOption {
        type = devicePathType;
        example = literalExpression ''"/dev/disk/by-uuid/f47ac10b-58cc-4372-a567-0e02b2c3d479"'';
        description = ''
          Which LUKS2 container this is, by a STABLE path -- `/dev/disk/by-id/…` (this physical
          disk instance) or `/dev/disk/by-uuid/…` (this LUKS container's own UUID, follows the
          ciphertext even onto a different physical disk). NEVER a bare `/dev/sdX` or
          `/dev/nvme0n1pN` -- kernel enumeration order is not guaranteed stable across a reboot.
          Opens at `/dev/mapper/${name}` (the attribute name IS the mapper name).
        '';
      };
      order = mkOption {
        type = types.int;
        example = 10;
        description = ''
          Where this volume sits in the SERIAL unlock chain, lowest first (ties broken by name).
          Only ever changes which prompt comes first -- the first passphrase entered is cached in
          the kernel keyring and opens every later volume in the chain silently, so put whichever
          volume the operator is most likely to have the passphrase memorised for first. Every
          volume needs its own value; two volumes sharing one is a build failure (see
          checks/default.nix), not a silently-resolved tie.
        '';
      };
      role = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "primary data pool";
        description = ''
          Free-text label for what this volume IS, for a human reading `nixluks-verify` output or
          a rescue runbook -- nixluks never branches on this value, it only prints it back.
        '';
      };
      manageUnlock = mkOption {
        type = types.bool;
        default = true;
        example = false;
        description = ''
          Whether nixluks OWNS this volume's unlock: its `/etc/crypttab` line and its
          place in the serialised `systemd-cryptsetup@` ordering chain.

          Set false to use nixluks for header backup and drift verification ONLY,
          on a volume whose unlock some other module already owns.

          THIS EXISTS BECAUSE THE ALTERNATIVE FAILS SILENTLY. `environment.etc` is a
          mergeable `lines` type, so declaring a volume here that another module also
          declares does NOT produce a build error -- it produces a crypttab with TWO
          entries for the same mapper name, and two independent `after=` chains racing
          to open one device. That is "two owners of one fact", and it is precisely
          what a consolidation onto this module is supposed to eliminate rather than
          introduce.

          The concrete case: a host whose initrd already unlocks every member from one
          passphrase (see the HOT MODE section) wants this module's
          `nixluks-backup-headers` and `nixluks-verify` without a second unlock path.
          Both of those tools only ever touch the raw `.device` path, never
          `/dev/mapper/<name>`, so they work perfectly well with `manageUnlock = false`.

          Renaming the mapper to dodge the collision instead is WORSE, not better: it
          creates a genuinely separate dm-crypt mapping over the same physical device.
        '';
      };

      headerBackup.destination = mkOption {
        type = types.nullOr types.path;
        default = null;
        example = literalExpression ''"/mnt/vault/luksHeaderBackups/archive0.img"'';
        description = ''
          Where `nixluks-backup-headers` writes this volume's `cryptsetup luksHeaderBackup`
          output. Contains the KDF-wrapped master key (not the passphrase, but with the
          passphrase it opens everything -- see this module's own "HEADER BACKUPS ARE SENSITIVE"
          header section) -- refused outright under `/tmp`, `/var/tmp`, or `/dev/shm`, and refused
          again at runtime if the destination directory grants group/other access. `null`
          (default): this volume's header is never backed up by this module. A vault (nixvault or
          otherwise) mounted locally is exactly the right kind of destination -- see this file's
          own "vs nixvault" SCOPE note: a vault is just another declared member of the unlock
          chain, and its mountpoint is a perfectly good place for the OTHER volumes' header
          backups to land.
        '';
      };
      expect = {
        cipher = mkOption {
          type = types.nullOr types.str;
          default = null;
          example = "aes-xts-plain64";
          description = ''
            Expected cipher spec, exactly as `cryptsetup luksDump --dump-json-metadata` reports it
            (segment 0's `encryption` field). Public metadata -- readable without a passphrase --
            checked here only so `nixluks-verify` catches a live header that no longer matches what
            was declared. `null`: don't check.
          '';
        };
        slotCount = mkOption {
          type = types.nullOr types.ints.positive;
          default = null;
          example = 2;
          description = ''
            Expected number of OCCUPIED key slots. Catches BOTH drift directions: a keyslot added
            by hand (drift up -- an unaccounted-for way in) and a rotation that removed the old
            slot without the new one ever landing (drift down -- fewer live copies of the master
            key than intended, discovered by this check instead of during the next recovery).
            `null`: don't check.
          '';
        };
        kdf = mkOption {
          type = types.nullOr (types.enum [ "argon2id" "argon2i" "pbkdf2" ]);
          default = null;
          example = "argon2id";
          description = ''
            Expected key-derivation function every OCCUPIED keyslot must use (LUKS2's own default
            is `argon2id`). Catches a keyslot added by hand with a weaker KDF sitting alongside
            the intended ones. `null`: don't check.
          '';
        };
      };
    };
  };
in
{
  options.nixluks = {
    enable = mkEnableOption "declaring which LUKS2 volumes this host unlocks post-boot, in what order, with header-backup and drift-verification wired to the same declaration";

    volumes = mkOption {
      type = types.attrsOf (types.submodule volumeModule);
      default = { };
      description = ''
        LUKS2 volumes this host knows about, as `name -> { device, order, ... }`. The attribute
        name IS the mapper name (`/dev/mapper/<name>`) and appears verbatim in `/etc/crypttab`.
        See modules/nixluks.nix's own header for the full mechanism and security model.
      '';
    };

    raiseMode = mkOption {
      type = types.enum [ "cold" "preopened" ];
      default = "cold";
      description = ''
        The unlock POLICY as a STANCE, never a credential -- how this host's declared volumes
        reach the open state:
          "cold" (default): every declared volume is LOCKED (`noauto`) when stage-2 starts.
            `nixluks-storage.target` stays inert until the operator runs `nixluks-unlock`, which
            raises it: volumes open SERIALLY in declared `order`, one passphrase prompt for the
            whole set. The rescue/appliance stance -- nothing to leak while sealed.
          "preopened": something upstream of this module -- an initrd unlock (see nixboot's own
            `remoteUnlock`) or an operator's earlier manual `cryptsetup open` -- has ALREADY
            opened every declared volume by the time stage-2 starts. `nixluks-storage.target`
            auto-raises at boot and never re-opens an already-open mapper. The hub/hot-store
            stance.
      '';
    };

    headerBackup.schedule = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "daily";
      description = ''
        systemd `OnCalendar=` cadence for running `nixluks-backup-headers` automatically.
        null (the default) means no timer -- the tool stays a manual CLI.

        SET THIS. A header backup that is only taken when someone remembers is the exact
        failure this module's own docs name as its motivation ("a header nobody remembers
        to run again after rotation"), and shipping the mechanism without a trigger fixes
        the mechanism while leaving the remembering. A header predating a passphrase
        rotation still LOOKS like a recovery path and is not one.

        Taking a header backup needs NO passphrase -- `cryptsetup luksHeaderBackup` reads
        the header off the raw device -- so this is genuinely safe to run unattended, and
        there is no reason for it to be manual.
      '';
    };

    verify.enable = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Run `nixluks-verify` after boot: read every declared volume's LIVE header back (no
        passphrase needed -- `cryptsetup luksDump` reads ciphertext metadata only) and compare it
        against `volumes.<name>.expect.*`, failing loudly on drift. A keyslot added by hand, or a
        rotation that only half-happened, shows up here instead of during the next recovery.
      '';
    };
  };

  config = mkIf (cfg.enable && cfg.volumes != { }) (mkMerge [
    {
      assertions =
        (map
          (n: {
            assertion = builtins.match "[a-zA-Z0-9_.-]+" n != null;
            message = ''nixluks.volumes."${n}": the attribute name becomes a systemd unit instance and a /dev/mapper name -- letters, digits, `_`, `.`, `-` only, got "${n}".'';
          })
          volNames)
        ++ (map
          (n: {
            assertion = !(isUnsafeBackupPath cfg.volumes.${n}.headerBackup.destination);
            message = ''nixluks.volumes."${n}".headerBackup.destination = "${cfg.volumes.${n}.headerBackup.destination}" resolves under /tmp, /var/tmp, or /dev/shm -- all world-readable or world-writable by convention. A header backup contains the KDF-wrapped master key (see modules/nixluks.nix's own "HEADER BACKUPS ARE SENSITIVE" section); point this somewhere only its owner can read.'';
          })
          (lib.filter (n: cfg.volumes.${n}.headerBackup.destination != null) volNames))
        ++ (let
              dup = lib.filter (n: lib.length (lib.filter (m: cfg.volumes.${m}.order == cfg.volumes.${n}.order) volNames) > 1) volNames;
            in
              optionals (dup != [ ]) [{
                assertion = false;
                message = ''nixluks.volumes: ${concatStringsSep ", " (map (n: "\"${n}\" (order ${toString cfg.volumes.${n}.order})") dup)} share an `order` value -- the serial unlock chain needs a single unambiguous sequence. Give each a distinct `order`.'';
              }])
        ++ (let
              devDups = lib.filter (n: lib.length (lib.filter (m: cfg.volumes.${m}.device == cfg.volumes.${n}.device) volNames) > 1) volNames;
            in
              optionals (devDups != [ ]) [{
                assertion = false;
                message = ''nixluks.volumes: ${concatStringsSep ", " (map (n: "\"${n}\"") devDups)} declare the SAME device -- each volume must name a distinct LUKS container.'';
              }]);

      environment.etc."crypttab".text = crypttab + "\n";
      environment.systemPackages = [ nixluks-unlock ]
        ++ optional (backupNames != [ ]) nixluks-backup-headers
        ++ optional cfg.verify.enable nixluks-verify;

      # Serialise the unlocks so the keyring cache is always HIT: the first volume in `order`
      # prompts, every later one finds the cached passphrase and opens silently. This dependency
      # chain exists unconditionally (harmless in `preopened` mode -- see below, nothing ever
      # starts these units there); only the TARGET's own dependency on the chain is conditional.
      systemd.services = listToAttrs (imap0
        (i: n: nameValuePair "systemd-cryptsetup@${n}" {
          overrideStrategy = "asDropin";
          after = optional (i > 0) (unlockUnitName (lib.elemAt managedNames (i - 1)));
        })
        managedNames)
      // lib.optionalAttrs (cfg.headerBackup.schedule != null && backupNames != [ ]) {
        nixluks-backup-headers = {
          description = "nixluks: back up the LUKS header of every volume declaring a destination";
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${nixluks-backup-headers}/bin/nixluks-backup-headers";
          };
        };
      };

      # Automatic header backup. Needs no passphrase (luksHeaderBackup reads the raw
      # header), so unlike anything that OPENS a container this is safe on a timer.
      systemd.timers.nixluks-backup-headers =
        mkIf (cfg.headerBackup.schedule != null && backupNames != [ ]) {
          wantedBy = [ "timers.target" ];
          timerConfig = {
            OnCalendar = cfg.headerBackup.schedule;
            Persistent = true;
          };
        };

      # The one switch: "cold" pulls in the cryptsetup chain and stays inert until
      # `nixluks-unlock` starts it; "preopened" auto-raises at boot and depends on NOTHING (the
      # volumes are already open by the time this runs) -- see this file's own "HOT MODE" header
      # section for why these two lists are never both populated at once.
      systemd.targets.nixluks-storage = {
        description = "nixluks volumes (declared LUKS2 members open)";
        wants = optionals (!isPreopened) unlockUnits;
        after = optionals (!isPreopened) unlockUnits;
        wantedBy = optionals isPreopened [ "multi-user.target" ];
      };
    }

    (mkIf cfg.verify.enable {
      # Reuses the EXACT SAME package `nixluks-verify` (above) already ships on PATH -- one
      # script, not a second copy of verifyScript that could drift from the standalone CLI.
      systemd.services.nixluks-verify = {
        description = "nixluks: read every declared volume's live header back and report drift";
        wantedBy = [ "multi-user.target" ];
        after = [ "multi-user.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${nixluks-verify}/bin/nixluks-verify";
        };
      };
    })
  ]);
}
