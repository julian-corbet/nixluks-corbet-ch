# checks/default.nix
#
# EVAL-TIME tests, the same posture as the sibling nixfs/nixvault/nixboot projects: each test
# evaluates a real configuration through NixOS's own eval-config.nix (or system-manager's
# equivalent) and inspects what the module RENDERS or whether the build fails. Nothing here boots
# anything -- `lifecycle-vm-test` (its own file) is the one real runtime test: a
# `pkgs.testers.nixosTest` that exercises the whole unlock chain against real LUKS2 volumes on
# loopback files inside a VM.
#
# The claims worth failing CI over:
#
#   1. `device` and `order` have no default; enabling a volume without either is a hard build
#      failure, never a silent guess -- the same "EVAL SAFETY" posture nixram/nixvault already
#      established for their own host-specific facts.
#   2. Two volumes sharing an `order` value is a hard build failure -- the serial chain has no
#      well-defined behavior for a tie the declaration itself did not break.
#   3. The unlock chain's `after=` ordering follows the DECLARED `order` field, not the attribute
#      name's lexical sort -- proven with a fixture where the two disagree.
#   4. `raiseMode` is the one switch between "cold" (target wants the cryptsetup chain, stays
#      inert until raised) and "preopened" (target auto-raises, depends on the chain not at all) --
#      never both lists populated for the same host.
#   5. A destination under /tmp, /var/tmp, or /dev/shm for `headerBackup.destination` is a hard
#      build failure -- see modules/nixluks.nix's own "HEADER BACKUPS ARE SENSITIVE" section.
#   5b. `volumes.<name>.fromDisk` resolves `device` from a sibling `nixstorage.disks` table
#      entry when named and present; an explicitly-typed `device` still wins over it; and a
#      `fromDisk` naming an entry absent from the table is a hard, clearly-messaged build
#      failure -- never a silent fall-through to some placeholder device string.
#   6. `nixluks-backup-headers` is installed ONLY when at least one volume declares a
#      `headerBackup.destination`; `nixluks-verify` is installed unless `verify.enable = false`;
#      `nixluks-unlock` is always installed once any volume is declared.
#   7. The module's own source text contains NO destructive/creating cryptsetup or filesystem
#      invocation -- the SAFETY INVARIANT made mechanically checkable, not merely asserted in a
#      comment (see "structurally-safe" below).
#   8. Both backends agree -- the NixOS and system-manager evaluations of the same input resolve
#      to the identical tool set, proving modules/nixluks.nix's own "ONE FILE, BOTH BACKENDS"
#      claim rather than merely asserting it in a comment.
#   9. `archPackages` publishes exactly what an Arch host's OWN package manager has to supply
#      (`cryptsetup`, because the crypttab written here is read by the HOST's generator), is empty
#      when the module renders nothing, and is identical on both backends. `aurPackages` exists
#      and is empty.
#  10. `tpm2.installTooling` INSTALLS AND ENROLLS NOTHING: enabling it changes the package set and
#      nothing else -- byte-identical rendered unit commands and crypttab, no `cryptenroll`
#      anywhere in either the module's source or the rendered config. "Installed but never
#      enrolled" is a checked property, not a promise a comment makes.
#  11. /etc/crypttab is claimed ONLY when at least one volume has `manageUnlock = true`. A host
#      declaring volumes purely for header backup writes no crypttab at all -- an empty one is a
#      no-op on NixOS but a demand to take over a boot-critical distro-owned file on the
#      system-manager backend, where `environment.etc` replaces a file wholesale.
{ pkgs, lib, nixpkgs, system, nixluksModule, systemManagerLib }:

let
  evalNixos = extraConfig:
    (import (nixpkgs + "/nixos/lib/eval-config.nix") {
      inherit system;
      modules = [
        nixluksModule
        extraConfig
        {
          boot.loader.grub.enable = false;
          fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
          system.stateVersion = "25.05";
        }
      ];
    }).config;

  # NixOS enforces assertions when `system.build.toplevel` is forced, not on a bare read of
  # `config.assertions` (a passive list); forcing toplevel is also what makes an UNSET required
  # option (no `default`, e.g. `device`/`order`) actually error, since nothing else would force it.
  # `seq` reaches the wrapping throw without deep-forcing the whole system closure.
  nixosBuildFails = extraConfig:
    !(builtins.tryEval (builtins.seq (evalNixos extraConfig).system.build.toplevel true)).success;

  check = name: ok: detail: { inherit name ok detail; };

  isCommentLine = l: builtins.match "[ \t]*#.*" l != null;

  # ── Fixtures ─────────────────────────────────────────────────────────────────────────────────
  validBase = {
    nixluks.enable = true;
    nixluks.volumes.primary = {
      device = "/dev/disk/by-id/test-primary";
      order = 1;
    };
  };

  # Minimal stand-in for a sibling `nixstorage.disks` table (see modules/nixluks.nix's own
  # defensive read, `config.nixstorage.disks or { }`) -- declares just enough option surface to
  # prove the read resolves a real value when present, without pulling in the actual nixstorage
  # flake as a `checks`-only input (that input would still never be a runtime dependency of the
  # module itself -- see this repo's flake.nix header for why `nixpkgs`/`system-manager` are
  # already scoped that way). nixluks NEVER imports nixstorage; this fixture just plays the part
  # of "a host that happens to also have nixstorage imported", the exact shape nixluks reads.
  fakeNixstorageDisksModule = {
    options.nixstorage.disks = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        options.device = lib.mkOption { type = lib.types.str; };
      });
      default = { };
    };
  };

  evalNixosWithFakeDisks = extraConfig:
    (import (nixpkgs + "/nixos/lib/eval-config.nix") {
      inherit system;
      modules = [
        nixluksModule
        fakeNixstorageDisksModule
        extraConfig
        {
          boot.loader.grub.enable = false;
          fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
          system.stateVersion = "25.05";
        }
      ];
    }).config;

  nixosBuildFailsWithFakeDisks = extraConfig:
    !(builtins.tryEval (builtins.seq (evalNixosWithFakeDisks extraConfig).system.build.toplevel true)).success;

  fromDiskBase = {
    nixstorage.disks.disk0.device = "/dev/disk/by-id/test-fromdisk-disk0";
    nixluks.enable = true;
    nixluks.volumes.primary = {
      fromDisk = "disk0";
      order = 1;
    };
  };

  cfg-from-disk = evalNixosWithFakeDisks fromDiskBase;

  cfg-from-disk-explicit-device-wins = evalNixosWithFakeDisks (lib.recursiveUpdate fromDiskBase {
    nixluks.volumes.primary.device = "/dev/disk/by-id/hand-typed-wins";
  });

  cfg-basic = evalNixos validBase;
  cfg-disabled = evalNixos { nixluks.enable = false; };
  cfg-preopened = evalNixos (lib.recursiveUpdate validBase { nixluks.raiseMode = "preopened"; });
  cfg-no-verify = evalNixos (lib.recursiveUpdate validBase { nixluks.verify.enable = false; });

  cfg-with-backup = evalNixos (lib.recursiveUpdate validBase {
    nixluks.volumes.primary.headerBackup.destination = "/mnt/vault/luksHeaderBackups/primary.img";
  });

  # Names deliberately chosen so lexical (attribute-name) order and declared `order` DISAGREE --
  # "aaa…" sorts first alphabetically but is given the LATER order; "zzz…" sorts last
  # alphabetically but is given the EARLIER order. Only a chain that actually reads `order` (not
  # `attrNames`) puts zzz before aaa.
  cfg-order-vs-name = evalNixos {
    nixluks.enable = true;
    nixluks.volumes = {
      aaa-lexically-first-but-declared-second = { device = "/dev/disk/by-id/test-a"; order = 2; };
      zzz-lexically-last-but-declared-first = { device = "/dev/disk/by-id/test-b"; order = 1; };
    };
  };

  toolNames = [ "nixluks-unlock" "nixluks-backup-headers" "nixluks-verify" ];

  hasTool = cfg: name:
    lib.any (p: lib.hasInfix name (p.name or "")) cfg.environment.systemPackages;

  # ── TPM tooling: installed, never enrolled ───────────────────────────────────────────────────
  # The pair below differs in ONE input -- tpm2.installTooling -- so anything that differs in the
  # RESULT beyond the package set is this option doing something it has no business doing.
  cfg-tpm-off = cfg-with-backup;
  cfg-tpm-on = evalNixos (lib.recursiveUpdate validBase {
    nixluks.volumes.primary.headerBackup.destination = "/mnt/vault/luksHeaderBackups/primary.img";
    nixluks.tpm2.installTooling = true;
  });

  # Every command any rendered unit would actually RUN, as plain strings. An enrollment could only
  # ever reach a device through one of these; comparing the whole map between the two configs
  # proves the TPM option adds no unit, no ExecStart, and no change to an existing one.
  unitCommands = cfg:
    lib.mapAttrs
      (_: s: builtins.toJSON (lib.mapAttrs (_: v: toString v)
        (lib.filterAttrs (k: _: lib.hasPrefix "Exec" k) (s.serviceConfig or { }))))
      cfg.systemd.services;

  # Only the units that actually DIFFER. The comparison above is over every unit the whole system
  # renders (a new unit anywhere is exactly what this must catch); printing all of them on failure
  # buries the one line a reader needs under the entire NixOS unit set.
  differingUnits = a: b:
    let
      ca = unitCommands a;
      cb = unitCommands b;
      keys = lib.unique (lib.attrNames ca ++ lib.attrNames cb);
    in
    lib.filter (k: (ca.${k} or null) != (cb.${k} or null)) keys;

  # ── manageUnlock = false everywhere: nixluks must not claim /etc/crypttab at all ──────────────
  # The header-backup-only host. On NixOS an empty crypttab is indistinguishable from none; on the
  # system-manager backend /etc/crypttab is a real distro-owned file that can already carry the
  # root and swap unlock lines, and `environment.etc` replaces a file wholesale.
  unmanagedBase = {
    nixluks.enable = true;
    nixluks.raiseMode = "preopened";
    nixluks.volumes.rootvol = {
      device = "/dev/disk/by-id/test-rootvol";
      order = 1;
      manageUnlock = false;
      headerBackup.destination = "/mnt/vault/luksHeaderBackups/rootvol.img";
    };
    nixluks.volumes.swapvol = {
      device = "/dev/disk/by-id/test-swapvol";
      order = 2;
      manageUnlock = false;
      headerBackup.destination = "/mnt/vault/luksHeaderBackups/swapvol.img";
    };
  };
  cfg-unmanaged = evalNixos unmanagedBase;
  cfg-sm-unmanaged = evalSm unmanagedBase;

  # The same host with ONE volume whose unlock nixluks does own -- the file comes back, carrying
  # that line and only that line.
  cfg-partly-managed = evalNixos (lib.recursiveUpdate unmanagedBase {
    nixluks.volumes.vault = {
      device = "/dev/disk/by-id/test-vault";
      order = 3;
      manageUnlock = true;
    };
  });

  # ── system-manager backend -- proves modules/nixluks.nix's "ONE FILE, BOTH BACKENDS" claim ────
  evalSm = extraConfig:
    (systemManagerLib.makeSystemConfig {
      modules = [
        nixluksModule
        extraConfig
        { nixpkgs.hostPlatform = system; }
      ];
    }).config;

  cfg-sm-basic = evalSm validBase;
  cfg-sm-with-backup = evalSm (lib.recursiveUpdate validBase {
    nixluks.volumes.primary.headerBackup.destination = "/mnt/vault/luksHeaderBackups/primary.img";
  });

  backendParityChecks = [
    (check "backend-parity/unlock-tool-present-on-system-manager-too"
      (hasTool cfg-sm-basic "nixluks-unlock")
      "system-manager systemPackages: ${builtins.toJSON (map (p: p.name or "?") cfg-sm-basic.environment.systemPackages)}")

    (check "backend-parity/verify-tool-present-on-system-manager-too"
      (hasTool cfg-sm-basic "nixluks-verify")
      "system-manager systemPackages: ${builtins.toJSON (map (p: p.name or "?") cfg-sm-basic.environment.systemPackages)}")

    (check "backend-parity/backup-tool-appears-under-system-manager-when-declared"
      (hasTool cfg-sm-with-backup "nixluks-backup-headers")
      "system-manager systemPackages: ${builtins.toJSON (map (p: p.name or "?") cfg-sm-with-backup.environment.systemPackages)}")

    (check "backend-parity/crypttab-content-matches"
      (cfg-sm-basic.environment.etc."crypttab".text == cfg-basic.environment.etc."crypttab".text)
      "system-manager: ${cfg-sm-basic.environment.etc."crypttab".text}, NixOS: ${cfg-basic.environment.etc."crypttab".text}")

    (check "backend-parity/storage-target-renders-on-system-manager-too"
      (cfg-sm-basic.systemd.targets ? "nixluks-storage")
      "system-manager systemd.targets: ${builtins.toJSON (lib.attrNames cfg-sm-basic.systemd.targets)}")

    (check "backend-parity/archPackages-identical"
      (cfg-sm-basic.nixluks.archPackages == cfg-basic.nixluks.archPackages)
      "system-manager: ${builtins.toJSON cfg-sm-basic.nixluks.archPackages}, NixOS: ${builtins.toJSON cfg-basic.nixluks.archPackages}")

    # The case the whole gate exists for, checked on the backend where it MATTERS: a
    # system-manager host declaring volumes purely for header backup must not demand ownership of
    # a distro-owned /etc/crypttab it has nothing to write into.
    (check "backend-parity/no-etc-crypttab-claim-on-system-manager-when-no-unlock-is-managed"
      (!(cfg-sm-unmanaged.environment.etc ? "crypttab"))
      "system-manager environment.etc: ${builtins.toJSON (lib.attrNames cfg-sm-unmanaged.environment.etc)}")
  ];

  # ── The SAFETY INVARIANT, made mechanically checkable: no destructive/creating cryptsetup or
  # filesystem call anywhere in the module's actual CODE (comment lines stripped first, since the
  # module's own "SAFETY INVARIANT" header section necessarily NAMES these operations in prose to
  # explain why they are absent). A future edit that added a real call to one of these inside a
  # `text = ''…'';`/`script = ''…'';` block would fail this check, not rely on a reviewer noticing.
  moduleSource = builtins.readFile ../modules/nixluks.nix;

  # PROSE IS NOT CODE. `#` comment lines were always stripped here, because the module's own
  # SAFETY INVARIANT section has to NAME the operations it forbids in order to explain that they
  # are absent. A multi-line `description = ''…''` block is the same prose in a different syntax --
  # `tpm2.installTooling`'s description exists precisely to say "this never enrolls anything" --
  # and a source grep cannot tell a sentence from a call. So those blocks are dropped too, and
  # NOTHING else is: a `text = ''…''` / `script = ''…''` body, the only place in this module where
  # a real invocation could ever live, is still scanned in full.
  stripDescriptions = lines:
    (lib.foldl'
      (acc: l:
        if acc.inDesc || lib.hasInfix "description = ''" l
        then acc // { inDesc = !(lib.hasInfix "'';" l); }
        else acc // { out = acc.out ++ [ l ]; })
      { inDesc = false; out = [ ]; }
      lines).out;

  codeOnlyLines = stripDescriptions
    (lib.filter (l: !(isCommentLine l)) (lib.splitString "\n" moduleSource));
  codeOnly = lib.concatStringsSep "\n" codeOnlyLines;
  forbiddenOps = [
    "luksFormat"
    "luksErase"
    "luksAddKey"
    "luksRemoveKey"
    "luksKillSlot"
    "wipefs"
    "mkfs."
    "zpool create"
    "zfs create"
    "zfs destroy"
    # Enrollment writes a key slot exactly as `luksAddKey` does, so it belongs in the SAME list --
    # this is what makes `tpm2.installTooling`'s "installed, never enrolled" a property CI holds
    # rather than a claim a description makes. `cryptenroll` (not the full binary name) so
    # `systemd-cryptenroll`, a bare `cryptenroll`, and any wrapper around either all trip it.
    "cryptenroll"
    "luksChangeKey"
    "luksConvertKey"
    "reencrypt"
  ];
  foundForbidden = lib.filter (w: lib.hasInfix w codeOnly) forbiddenOps;

  results = [
    # --- 1. no default is a hard failure, never a silent guess ---------------------------------
    (check "device/unset-fails-the-build"
      (nixosBuildFails { nixluks.enable = true; nixluks.volumes.primary.order = 1; })
      "expected a volume with no device to fail the build, but it succeeded")

    (check "order/unset-fails-the-build"
      (nixosBuildFails { nixluks.enable = true; nixluks.volumes.primary.device = "/dev/disk/by-id/test"; })
      "expected a volume with no order to fail the build, but it succeeded")

    (check "disabled/incomplete-volume-still-builds"
      (!(nixosBuildFails { nixluks.enable = false; nixluks.volumes.primary = { }; }))
      "a disabled module should never force-read device/order -- both assertions and crypttab generation are gated on enable")

    (check "valid/complete-declaration-builds-fine"
      (!(nixosBuildFails validBase))
      "a complete, valid declaration should never fail the build")

    # --- 2. duplicate order is a hard failure ---------------------------------------------------
    (check "order/duplicate-fails-the-build"
      (nixosBuildFails {
        nixluks.enable = true;
        nixluks.volumes = {
          a = { device = "/dev/disk/by-id/test-a"; order = 1; };
          b = { device = "/dev/disk/by-id/test-b"; order = 1; };
        };
      })
      "expected two volumes sharing one `order` value to fail the build, but it succeeded")

    (check "order/distinct-values-build-fine"
      (!(nixosBuildFails {
        nixluks.enable = true;
        nixluks.volumes = {
          a = { device = "/dev/disk/by-id/test-a"; order = 1; };
          b = { device = "/dev/disk/by-id/test-b"; order = 2; };
        };
      }))
      "distinct order values should never fail the build")

    # --- 2b. duplicate device is a hard failure -------------------------------------------------
    (check "device/duplicate-fails-the-build"
      (nixosBuildFails {
        nixluks.enable = true;
        nixluks.volumes = {
          a = { device = "/dev/disk/by-id/same"; order = 1; };
          b = { device = "/dev/disk/by-id/same"; order = 2; };
        };
      })
      "expected two volumes naming the SAME device to fail the build, but it succeeded")

    # --- 2b2. fromDisk resolves device from a sibling nixstorage.disks table -------------------
    (check "device/fromDisk-resolves-from-nixstorage-disks-table"
      (cfg-from-disk.nixluks.volumes.primary.device == "/dev/disk/by-id/test-fromdisk-disk0")
      "got device=${builtins.toJSON (cfg-from-disk.nixluks.volumes.primary.device or null)}, expected the fixture's nixstorage.disks.disk0.device value")

    (check "device/fromDisk-explicit-device-still-wins"
      (cfg-from-disk-explicit-device-wins.nixluks.volumes.primary.device == "/dev/disk/by-id/hand-typed-wins")
      "an explicitly-typed device must win over whatever fromDisk would have resolved to -- got ${builtins.toJSON (cfg-from-disk-explicit-device-wins.nixluks.volumes.primary.device or null)}")

    (check "device/fromDisk-unknown-name-fails-the-build"
      (nixosBuildFailsWithFakeDisks {
        nixstorage.disks.disk0.device = "/dev/disk/by-id/test-fromdisk-disk0";
        nixluks.enable = true;
        nixluks.volumes.primary = {
          fromDisk = "does-not-exist";
          order = 1;
        };
      })
      "expected fromDisk naming an entry absent from nixstorage.disks to fail the build, but it succeeded")

    # --- 2c. an attribute name unsafe as a unit instance / mapper name is a hard failure --------
    (check "name/invalid-characters-fail-the-build"
      (nixosBuildFails {
        nixluks.enable = true;
        nixluks.volumes."bad name!" = { device = "/dev/disk/by-id/test"; order = 1; };
      })
      "expected a volume name with spaces/punctuation to fail the build, but it succeeded")

    # --- 3. the chain follows declared `order`, never attribute-name lexical sort --------------
    (check "chain/order-field-wins-over-attribute-name-sort"
      (cfg-order-vs-name.systemd.services."systemd-cryptsetup@aaa-lexically-first-but-declared-second".after
        == [ "systemd-cryptsetup@zzz-lexically-last-but-declared-first.service" ])
      "got after=${builtins.toJSON cfg-order-vs-name.systemd.services."systemd-cryptsetup@aaa-lexically-first-but-declared-second".after}, expected the zzz… unit (declared order 1) first despite sorting last alphabetically")

    (check "chain/first-in-order-has-no-after"
      (cfg-order-vs-name.systemd.services."systemd-cryptsetup@zzz-lexically-last-but-declared-first".after == [ ])
      "got after=${builtins.toJSON cfg-order-vs-name.systemd.services."systemd-cryptsetup@zzz-lexically-last-but-declared-first".after}, expected [] -- the first volume in declared order should have no `after` dependency on any other cryptsetup unit")

    # --- 4. crypttab renders exactly what was declared, `noauto,nofail` on every line ------------
    (check "crypttab/content-matches-declaration"
      (cfg-basic.environment.etc."crypttab".text == "primary /dev/disk/by-id/test-primary none luks,noauto,nofail\n")
      "got: ${builtins.toJSON cfg-basic.environment.etc."crypttab".text}")

    # --- 5. raiseMode is the one switch, never both lists populated -----------------------------
    (check "raiseMode/cold-target-wants-the-cryptsetup-chain"
      (cfg-basic.systemd.targets.nixluks-storage.wants == [ "systemd-cryptsetup@primary.service" ]
        && cfg-basic.systemd.targets.nixluks-storage.wantedBy == [ ])
      "wants=${builtins.toJSON cfg-basic.systemd.targets.nixluks-storage.wants}, wantedBy=${builtins.toJSON cfg-basic.systemd.targets.nixluks-storage.wantedBy}")

    (check "raiseMode/preopened-target-auto-raises-and-depends-on-nothing"
      (cfg-preopened.systemd.targets.nixluks-storage.wants == [ ]
        && cfg-preopened.systemd.targets.nixluks-storage.wantedBy == [ "multi-user.target" ])
      "wants=${builtins.toJSON cfg-preopened.systemd.targets.nixluks-storage.wants}, wantedBy=${builtins.toJSON cfg-preopened.systemd.targets.nixluks-storage.wantedBy}")

    # --- 6. headerBackup.destination under /tmp, /var/tmp, /dev/shm is a hard failure -----------
    (check "headerBackup/tmp-destination-fails-the-build"
      (nixosBuildFails (lib.recursiveUpdate validBase {
        nixluks.volumes.primary.headerBackup.destination = "/tmp/leaky/primary.img";
      }))
      "expected a /tmp header-backup destination to fail the build, but it succeeded")

    (check "headerBackup/var-tmp-destination-fails-the-build"
      (nixosBuildFails (lib.recursiveUpdate validBase {
        nixluks.volumes.primary.headerBackup.destination = "/var/tmp/leaky/primary.img";
      }))
      "expected a /var/tmp header-backup destination to fail the build, but it succeeded")

    (check "headerBackup/private-destination-builds-fine"
      (!(nixosBuildFails (lib.recursiveUpdate validBase {
        nixluks.volumes.primary.headerBackup.destination = "/mnt/vault/luksHeaderBackups/primary.img";
      })))
      "a private, non-tmp destination should never fail the build")

    # --- 7. tool installation follows declaration, exactly -------------------------------------
    (check "packages/unlock-and-verify-present-by-default"
      (hasTool cfg-basic "nixluks-unlock" && hasTool cfg-basic "nixluks-verify")
      "systemPackages: ${builtins.toJSON (map (p: p.name or "?") cfg-basic.environment.systemPackages)}")

    (check "packages/backup-tool-absent-with-no-destination-declared"
      (!(hasTool cfg-basic "nixluks-backup-headers"))
      "nixluks-backup-headers should not install when no volume declares headerBackup.destination")

    (check "packages/backup-tool-present-once-any-destination-declared"
      (hasTool cfg-with-backup "nixluks-backup-headers")
      "systemPackages: ${builtins.toJSON (map (p: p.name or "?") cfg-with-backup.environment.systemPackages)}")

    (check "packages/disabled-installs-nothing"
      (!(lib.any (p: lib.hasInfix "nixluks" (p.name or "")) cfg-disabled.environment.systemPackages))
      "nixluks.enable = false still installed a nixluks tool")

    # --- 8. verify.enable is the one switch for the boot-time verify service --------------------
    (check "verify/service-present-by-default"
      (cfg-basic.systemd.services ? "nixluks-verify")
      "systemd.services: ${builtins.toJSON (lib.attrNames cfg-basic.systemd.services)}")

    (check "verify/disabled-removes-the-service-and-the-tool"
      (!(cfg-no-verify.systemd.services ? "nixluks-verify") && !(hasTool cfg-no-verify "nixluks-verify"))
      "verify.enable = false should remove both the boot-time service and the standalone tool")

    # --- 9. SCOPE: no ZFS-pool-import surface exists here at all (that is nixstorage's job) -----
    (check "scope/no-zfs-pool-import-option-exists"
      (!(cfg-basic.nixluks ? zfsPools))
      "nixluks must never grow a zfsPools-style option -- pool import is downstream of this module's crypto-layer scope, see modules/nixluks.nix's own SCOPE block")

    # --- 10. the SAFETY INVARIANT, mechanically checked -----------------------------------------
    (check "structurally-safe/no-destructive-or-creating-cryptsetup-calls-in-code"
      (foundForbidden == [ ])
      "found forbidden operation(s) in the module's actual code (comments excluded): ${builtins.toJSON foundForbidden}")

    # --- 11. every installed nixluks-* package is one of the three known tools -- catches a typo'd
    # or accidentally-duplicated tool name before it ships -----------------------------------------
    (check "packages/no-unexpected-tool-names"
      (lib.all
        (p: lib.any (n: lib.hasInfix n (p.name or "")) toolNames)
        (lib.filter (p: lib.hasInfix "nixluks" (p.name or "")) cfg-with-backup.environment.systemPackages))
      "systemPackages: ${builtins.toJSON (map (p: p.name or "?") cfg-with-backup.environment.systemPackages)}, expected only: ${builtins.toJSON toolNames}")

    # --- 12. archPackages publishes what an Arch host's OWN package manager has to supply --------
    (check "archPackages/publishes-cryptsetup"
      (cfg-basic.nixluks.archPackages == [ "cryptsetup" ])
      "got ${builtins.toJSON cfg-basic.nixluks.archPackages}, expected exactly [\"cryptsetup\"] -- the crypttab this module writes is read by the HOST's own generator, whose systemd-cryptsetup does not come from the Nix store")

    (check "archPackages/empty-when-the-module-renders-nothing"
      (cfg-disabled.nixluks.archPackages == [ ]
        && (evalNixos { nixluks.enable = true; }).nixluks.archPackages == [ ])
      "a host with nixluks disabled, or enabled with no volumes declared, must publish no package name at all -- got ${builtins.toJSON cfg-disabled.nixluks.archPackages}")

    (check "archPackages/aur-list-exists-and-is-empty"
      (cfg-basic.nixluks.aurPackages == [ ] && cfg-tpm-on.nixluks.aurPackages == [ ])
      "aurPackages must exist (so a consumer can wire both channels uniformly) and be empty -- nothing nixluks needs lives in the AUR; got ${builtins.toJSON cfg-basic.nixluks.aurPackages}")

    # --- 13. TPM2: tooling installed, NOTHING enrolled ------------------------------------------
    (check "tpm2/tooling-off-by-default"
      (!(hasTool cfg-tpm-off "tpm2-tools")
        && !(lib.elem "tpm2-tools" cfg-tpm-off.nixluks.archPackages))
      "tpm2.installTooling defaults to false; systemPackages: ${builtins.toJSON (map (p: p.name or "?") cfg-tpm-off.environment.systemPackages)}, archPackages: ${builtins.toJSON cfg-tpm-off.nixluks.archPackages}")

    (check "tpm2/tooling-on-reaches-both-delivery-channels"
      (hasTool cfg-tpm-on "tpm2-tools"
        && cfg-tpm-on.nixluks.archPackages == [ "cryptsetup" "tpm2-tools" ])
      "systemPackages: ${builtins.toJSON (map (p: p.name or "?") cfg-tpm-on.environment.systemPackages)}, archPackages: ${builtins.toJSON cfg-tpm-on.nixluks.archPackages}")

    # THE load-bearing one. Enabling the TPM option must change the package set and NOTHING else:
    # same units, same commands inside them, same crypttab. An enrollment could only reach a
    # device through a rendered ExecStart, and there is no new or altered one.
    (check "tpm2/tooling-adds-no-unit-and-no-command"
      (unitCommands cfg-tpm-on == unitCommands cfg-tpm-off
        && cfg-tpm-on.environment.etc."crypttab".text == cfg-tpm-off.environment.etc."crypttab".text)
      "enabling tpm2.installTooling changed something beyond the package set. Units that differ: ${builtins.toJSON (differingUnits cfg-tpm-on cfg-tpm-off)}; with: ${builtins.toJSON (lib.filterAttrs (k: _: lib.elem k (differingUnits cfg-tpm-on cfg-tpm-off)) (unitCommands cfg-tpm-on))}")

    (check "tpm2/no-enroll-invocation-anywhere-in-the-rendered-config"
      (!(lib.hasInfix "cryptenroll" (builtins.toJSON (unitCommands cfg-tpm-on))))
      "a rendered unit command mentions cryptenroll: ${builtins.toJSON (unitCommands cfg-tpm-on)}")

    # --- 14. /etc/crypttab is claimed only when this module actually owns an unlock --------------
    (check "crypttab/not-claimed-when-every-volume-is-manageUnlock-false"
      (!(cfg-unmanaged.environment.etc ? "crypttab"))
      "a header-backup-only host wrote an /etc/crypttab anyway -- environment.etc: ${builtins.toJSON (lib.attrNames cfg-unmanaged.environment.etc)}")

    (check "crypttab/header-backup-only-host-still-gets-its-backup-tool-and-verify"
      (hasTool cfg-unmanaged "nixluks-backup-headers" && hasTool cfg-unmanaged "nixluks-verify")
      "dropping the crypttab claim must not drop anything else -- systemPackages: ${builtins.toJSON (map (p: p.name or "?") cfg-unmanaged.environment.systemPackages)}")

    (check "crypttab/claimed-again-as-soon-as-one-volume-is-managed"
      (cfg-partly-managed.environment.etc."crypttab".text
        == "vault /dev/disk/by-id/test-vault none luks,noauto,nofail\n")
      "got: ${builtins.toJSON (cfg-partly-managed.environment.etc."crypttab".text or null)} -- expected exactly the one managed volume's line, and no line for either manageUnlock = false volume")
  ]
  ++ backendParityChecks;

  failed = builtins.filter (r: !r.ok) results;

  report = lib.concatMapStringsSep "\n" (r: "  - ${r.name}: ${r.detail}") failed;
in
if failed != [ ]
then
  throw ''
    nixluks eval-tests FAILED (${toString (builtins.length failed)}/${toString (builtins.length results)}):
    ${report}
  ''
else {
  # Depending on `passedCount` forces `results`, so the tests genuinely run under `nix flake check`
  # rather than merely being defined.
  eval-tests = pkgs.runCommand "nixluks-eval-tests"
    { passedCount = toString (builtins.length results); }
    ''
      echo "all $passedCount nixluks eval tests passed"
      touch $out
    '';

  # The one REAL runtime test: a pkgs.testers.nixosTest, the house pattern nixram's and
  # nixvault's own checks/ already proved out -- see that file's own header for exactly what it
  # exercises and why.
  lifecycle-vm-test = import ./lifecycle-vm-test.nix {
    inherit pkgs nixluksModule;
  };
}
