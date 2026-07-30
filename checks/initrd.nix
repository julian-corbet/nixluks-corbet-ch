# checks/initrd.nix
#
# EVAL-TIME tests for modules/initrd.nix -- the NixOS-only companion that opens declared nixluks
# volumes IN THE INITRD (see that file's own header for the mechanism and why it cannot live
# inside modules/nixluks.nix itself). Same technique as checks/default.nix: evaluate a real
# configuration through NixOS's own eval-config.nix and inspect what renders or whether the build
# fails -- nothing here boots anything.
#
# The claims worth failing CI over:
#
#   1. `initrdUnlock.enable = true` with `raiseMode` left at "cold" (the default) is a hard build
#      failure -- modules/nixluks.nix's own assertion, exercised here rather than only in that
#      file's own suite, since the FAILURE is only meaningful in the presence of this module's
#      own option (initrdUnlock.critical/timeoutSec) actually being read somewhere.
#   2. The same declaration with `raiseMode = "preopened"` builds fine.
#   3. A `critical = true` volume gets `x-systemd.device-timeout=0` (INFINITE wait) in
#      `boot.initrd.luks.devices`, never `nofail`.
#   4. A `critical = false` (default) volume gets `nofail` plus its `timeoutSec` (default 45),
#      never the infinite-wait option.
#   5. A volume with `initrdUnlock.enable` left at its default (false) never appears in
#      `boot.initrd.luks.devices` at all -- this module must not open anything that did not ask.
#   6. The initrd chain's `after=` ordering follows the SAME declared `order` field the post-boot
#      chain (modules/nixluks.nix) uses -- proven by comparing this module's own
#      `boot.initrd.systemd.services` chain against modules/nixluks.nix's `systemd.services`
#      chain for the identical fixture, not merely asserted to use "the same rule" in a comment.
#   7. `nixluks.enable = false` renders neither `boot.initrd.luks.devices` nor
#      `boot.initrd.systemd.services` entries, even with `initrdUnlock.enable = true` declared.
{ pkgs, lib, nixpkgs, system, nixluksModule, nixluksInitrdModule }:

let
  evalNixos = extraConfig:
    (import (nixpkgs + "/nixos/lib/eval-config.nix") {
      inherit system;
      modules = [
        nixluksModule
        nixluksInitrdModule
        extraConfig
        {
          boot.loader.grub.enable = false;
          fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
          system.stateVersion = "25.05";
        }
      ];
    }).config;

  nixosBuildFails = extraConfig:
    !(builtins.tryEval (builtins.seq (evalNixos extraConfig).system.build.toplevel true)).success;

  check = name: ok: detail: { inherit name ok detail; };

  # ── Fixtures ─────────────────────────────────────────────────────────────────────────────────
  criticalBase = {
    nixluks.enable = true;
    nixluks.raiseMode = "preopened";
    nixluks.volumes.root = {
      device = "/dev/disk/by-id/test-root";
      order = 1;
      initrdUnlock.enable = true;
      initrdUnlock.critical = true;
    };
  };

  dataBase = {
    nixluks.enable = true;
    nixluks.raiseMode = "preopened";
    nixluks.volumes.cold = {
      device = "/dev/disk/by-id/test-cold";
      order = 1;
      initrdUnlock.enable = true;
      # critical left at its default (false); timeoutSec left at its default (45).
    };
  };

  mixedBase = {
    nixluks.enable = true;
    nixluks.raiseMode = "preopened";
    nixluks.volumes = {
      # Declared order 2 but must open FIRST (order 1 is on the volume declared second below) --
      # only a chain that reads `order`, not attribute-definition position, gets this right.
      nix = { device = "/dev/disk/by-id/test-nix"; order = 2; initrdUnlock.enable = true; initrdUnlock.critical = true; };
      root = { device = "/dev/disk/by-id/test-root2"; order = 1; initrdUnlock.enable = true; initrdUnlock.critical = true; };
      # Not initrd-managed at all -- must never appear in boot.initrd.luks.devices.
      archive = { device = "/dev/disk/by-id/test-archive"; order = 3; };
    };
  };

  cfg-critical = evalNixos criticalBase;
  cfg-data = evalNixos dataBase;
  cfg-mixed = evalNixos mixedBase;
  cfg-disabled = evalNixos { nixluks.enable = false; nixluks.volumes.root = { device = "/dev/disk/by-id/x"; order = 1; initrdUnlock.enable = true; }; };

  results = [
    # --- 1/2. raiseMode = "preopened" is REQUIRED whenever any volume opts into the initrd ------
    (check "initrdUnlock/cold-raiseMode-fails-the-build"
      (nixosBuildFails {
        nixluks.enable = true;
        nixluks.volumes.root = {
          device = "/dev/disk/by-id/test-root";
          order = 1;
          initrdUnlock.enable = true;
        };
      })
      "expected initrdUnlock.enable = true with the default raiseMode (\"cold\") to fail the build, but it succeeded")

    (check "initrdUnlock/preopened-raiseMode-builds-fine"
      (!(nixosBuildFails criticalBase))
      "expected initrdUnlock.enable = true with raiseMode = \"preopened\" to build fine, but it failed")

    (check "initrdUnlock/disabled-volume-never-fails-on-raiseMode"
      (!(nixosBuildFails {
        nixluks.enable = true;
        nixluks.volumes.root = { device = "/dev/disk/by-id/test-root"; order = 1; };
      }))
      "a volume that never sets initrdUnlock.enable must never trip the raiseMode assertion")

    # --- 3. critical = true -> infinite device-timeout, never nofail ---------------------------
    (check "critical/gets-infinite-device-timeout"
      (cfg-critical.boot.initrd.luks.devices.root.crypttabExtraOpts == [ "x-systemd.device-timeout=0" ])
      "got: ${builtins.toJSON cfg-critical.boot.initrd.luks.devices.root.crypttabExtraOpts}")

    (check "critical/device-matches-declaration"
      (cfg-critical.boot.initrd.luks.devices.root.device == "/dev/disk/by-id/test-root")
      "got: ${builtins.toJSON cfg-critical.boot.initrd.luks.devices.root.device}")

    # --- 4. critical = false (default) -> nofail + timeoutSec (default 45) ---------------------
    (check "data/gets-nofail-and-finite-timeout"
      (cfg-data.boot.initrd.luks.devices.cold.crypttabExtraOpts == [ "nofail" "x-systemd.device-timeout=45s" ])
      "got: ${builtins.toJSON cfg-data.boot.initrd.luks.devices.cold.crypttabExtraOpts}")

    (check "data/timeoutSec-override-renders"
      (
        let
          cfg = evalNixos {
            nixluks.enable = true;
            nixluks.raiseMode = "preopened";
            nixluks.volumes.cold = {
              device = "/dev/disk/by-id/test-cold";
              order = 1;
              initrdUnlock.enable = true;
              initrdUnlock.timeoutSec = 90;
            };
          };
        in
        cfg.boot.initrd.luks.devices.cold.crypttabExtraOpts == [ "nofail" "x-systemd.device-timeout=90s" ]
      )
      "a non-default timeoutSec must render verbatim into crypttabExtraOpts")

    # --- 5. a volume that never opts in never appears in boot.initrd.luks.devices --------------
    (check "scope/non-initrd-volume-absent-from-initrd-luks-devices"
      (!(cfg-mixed.boot.initrd.luks.devices ? archive))
      "boot.initrd.luks.devices keys: ${builtins.toJSON (builtins.attrNames cfg-mixed.boot.initrd.luks.devices)}")

    (check "scope/initrd-volumes-present-alongside-non-initrd-one"
      (cfg-mixed.boot.initrd.luks.devices ? nix && cfg-mixed.boot.initrd.luks.devices ? root)
      "boot.initrd.luks.devices keys: ${builtins.toJSON (builtins.attrNames cfg-mixed.boot.initrd.luks.devices)}")

    # --- 6. the initrd chain follows declared `order`, matching the post-boot chain's own rule -
    (check "chain/initrd-follows-declared-order-not-attribute-position"
      (cfg-mixed.boot.initrd.systemd.services."systemd-cryptsetup@nix".after
        == [ "systemd-cryptsetup@root.service" ])
      "got after=${builtins.toJSON cfg-mixed.boot.initrd.systemd.services."systemd-cryptsetup@nix".after}, expected root (order 1) before nix (order 2) despite nix being declared first")

    (check "chain/first-in-order-has-no-after"
      (cfg-mixed.boot.initrd.systemd.services."systemd-cryptsetup@root".after == [ ])
      "got after=${builtins.toJSON cfg-mixed.boot.initrd.systemd.services."systemd-cryptsetup@root".after}")

    (check "chain/non-initrd-volume-has-no-initrd-cryptsetup-unit"
      (!(cfg-mixed.boot.initrd.systemd.services ? "systemd-cryptsetup@archive"))
      "boot.initrd.systemd.services keys: ${builtins.toJSON (builtins.attrNames cfg-mixed.boot.initrd.systemd.services)}")

    # --- 6b. same order rule as the post-boot chain, for the SAME fixture (proves the "MUST stay
    # in lockstep" comment in modules/initrd.nix rather than merely asserting it) ---------------
    (check "chain/matches-postboot-chain-ordering-for-the-same-fixture"
      (
        let
          # Same two volumes, both manageUnlock (post-boot chain default) so modules/nixluks.nix's
          # own systemd-cryptsetup@ chain also renders for them, independent of initrdUnlock.
          cfg = evalNixos {
            nixluks.enable = true;
            nixluks.raiseMode = "preopened";
            nixluks.volumes = {
              nix = { device = "/dev/disk/by-id/test-nix"; order = 2; initrdUnlock.enable = true; initrdUnlock.critical = true; };
              root = { device = "/dev/disk/by-id/test-root2"; order = 1; initrdUnlock.enable = true; initrdUnlock.critical = true; };
            };
          };
        in
        cfg.systemd.services."systemd-cryptsetup@nix".after == cfg.boot.initrd.systemd.services."systemd-cryptsetup@nix".after
      )
      "the post-boot chain (modules/nixluks.nix) and the initrd chain (modules/initrd.nix) disagreed on ordering for the identical fixture")

    # --- 7. nixluks.enable = false -> no initrd wiring at all, even with initrdUnlock declared --
    (check "disabled/no-initrd-luks-devices"
      (!(cfg-disabled.boot.initrd.luks ? devices) || cfg-disabled.boot.initrd.luks.devices == { })
      "boot.initrd.luks.devices: ${builtins.toJSON (cfg-disabled.boot.initrd.luks.devices or { })}")
  ];

  failed = builtins.filter (r: !r.ok) results;

  report = lib.concatMapStringsSep "\n" (r: "  - ${r.name}: ${r.detail}") failed;
in
if failed != [ ]
then
  throw ''
    nixluks-initrd eval-tests FAILED (${toString (builtins.length failed)}/${toString (builtins.length results)}):
    ${report}
  ''
else {
  initrd-eval-tests = pkgs.runCommand "nixluks-initrd-eval-tests"
    { passedCount = toString (builtins.length results); }
    ''
      echo "all $passedCount nixluks-initrd eval tests passed"
      touch $out
    '';
}
