# modules/initrd.nix -- open declared nixluks volumes IN THE INITRD (stage 1, before
# switch-root).
#
# A SEPARATE NixOS-only nixosModule, deliberately NOT folded into modules/nixluks.nix and
# deliberately NOT exported as a systemManagerModule (see flake.nix) -- system-manager has no
# `boot.initrd.*` surface AT ALL, and modules/nixluks.nix's own "ONE FILE, BOTH BACKENDS" header
# is explicit that its whole design rests on never needing one. This file exists precisely
# because that constraint is real, not because it was overlooked: the same "one concern needs a
# NixOS-only escape hatch" shape this house style already uses elsewhere (nixboot's own
# modules/nixboot.nix vs modules/system-manager-limine.nix -- one option tree per backend, never
# one file straddling both -- and nixram's documented system-manager/ split for its zswap/oomd
# surface).
#
# THE MECHANISM -- the SAME serial-unlock-with-keyring-cache chain modules/nixluks.nix already
# runs post-boot (systemd-cryptsetup@<name>.service units `after=`-chained on each other, in
# declared `order`, so the FIRST passphrase entered is cached in the kernel keyring and opens
# every later member silently), run ONE STAGE EARLIER: `boot.initrd.luks.devices` instead of
# `environment.etc."crypttab"`, `boot.initrd.systemd.services` instead of `systemd.services`.
# Generalised from nixnas's own `modules/store/location.nix`. Timeout policy is
# declared per consumer; this public mechanism carries no host-specific value.
#
# BOOT-CRITICAL vs DATA, never conflated: a volume declaring `initrdUnlock.critical = true` gets
# an INFINITE device-timeout (`x-systemd.device-timeout=0`) -- a missing/failed unlock correctly
# STOPS the boot, because this volume is `/` or `/nix` or something they depend on. A volume
# declaring `critical = false` (the default) gets `nofail` plus a FINITE wait
# (`initrdUnlock.timeoutSec`) -- a missing/dead disk is skipped, never blocks the boot. Getting
# this backwards for even one volume reproduces one of two real field incidents -- see
# `initrdUnlock.critical`'s own option doc (modules/nixluks.nix) for both.
#
# ALL initrd-enabled volumes -- critical AND non-critical alike -- share ONE keyring-cache chain,
# exactly as nixnas's own location.nix does (`allUnlockNames = attrNames (bootCriticalUnlock //
# dataUnlock)`): the FIRST volume in declared `order` prompts, every later one -- critical or
# not -- finds the cached passphrase and opens silently. Splitting them into two independent
# chains would mean two separate password prompts for what is, by design, ONE operator secret.
#
# WHAT THIS FILE DOES NOT DO: import ZFS pools, mount filesystems, or touch anything about WHY a
# volume needs to be open this early -- that stays with whoever composes this module (a host's
# own `fileSystems."/"` / `fileSystems."/nix"` with `neededForBoot = true`, exactly as nixnas's
# own store/location.nix leaves it). This file only ever answers "is the /dev/mapper/<name> node
# open by the time stage-2 starts", nothing more -- the same narrow-mechanism discipline
# modules/nixluks.nix's own SCOPE section already applies to the post-boot chain.
{ config, lib, ... }:
let
  cfg = config.nixluks;
  inherit (lib) mkIf optional listToAttrs nameValuePair imap0 filter sort attrNames;

  enabledNames = filter (n: cfg.volumes.${n}.initrdUnlock.enable) (attrNames cfg.volumes);

  # Deterministic order: the IDENTICAL rule modules/nixluks.nix's own `byOrder` applies (declared
  # `order`, attribute name as tie-break) -- MUST stay in lockstep with that file's sort, since
  # both chains read the very same `order` field off the very same `volumes` table and a
  # divergent tie-break here would let the two chains disagree about which volume opens first.
  # Proven identical by checks/initrd.nix's own "same order as the post-boot chain" fixture, not
  # merely asserted in this comment.
  byOrder = a: b:
    let oa = cfg.volumes.${a}.order; ob = cfg.volumes.${b}.order;
    in if oa != ob then oa < ob else a < b;
  sortedEnabledNames = sort byOrder enabledNames;

  unlockUnitName = n: "systemd-cryptsetup@${n}.service";
in
{
  config = mkIf (cfg.enable && enabledNames != [ ]) {
    boot.initrd.luks.devices = listToAttrs (map
      (n:
        let v = cfg.volumes.${n};
        in nameValuePair n {
          device = v.device;
          crypttabExtraOpts =
            if v.initrdUnlock.critical
            then [ "x-systemd.device-timeout=0" ]
            else [ "nofail" "x-systemd.device-timeout=${toString v.initrdUnlock.timeoutSec}s" ];
        })
      enabledNames);

    # Serialise EVERY initrd-enabled volume -- critical and non-critical alike -- into one
    # keyring-cache chain: the first in declared `order` prompts, every later one opens silently.
    # Harmless if this host's `raiseMode` is somehow still "cold" at the moment this evaluates --
    # modules/nixluks.nix's own assertion (any volume with initrdUnlock.enable = true requires
    # raiseMode = "preopened") refuses that combination outright before it ever reaches here.
    boot.initrd.systemd.services = listToAttrs (imap0
      (i: n: nameValuePair "systemd-cryptsetup@${n}" {
        overrideStrategy = "asDropin";
        after = optional (i > 0) (unlockUnitName (lib.elemAt sortedEnabledNames (i - 1)));
      })
      sortedEnabledNames);
  };
}
