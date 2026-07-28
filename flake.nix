{
  description = "nixluks -- declare which LUKS2 volumes a host unlocks post-boot, in what order, with header-backup orchestration and drift verification wired to the same declaration; the serial-unlock-with-keyring-cache mechanism generalised out of nixnas so a fleet member, a disaster-recovery vault, or a rescue image can all share it.";

  inputs = {
    # Used by `checks` only. The module itself takes `pkgs` from the consuming evaluation and
    # never references this input, so a consumer that does not follow it pays no second nixpkgs.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Also used by `checks` only (backend-parity eval tests) -- the module itself is exported
    # unchanged for both backends (see modules/nixluks.nix's own "ONE FILE, BOTH BACKENDS"
    # header), so a consumer targeting only one backend pays no cost for the one it doesn't use.
    system-manager.url = "github:numtide/system-manager";
    system-manager.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, system-manager }:
    let
      lib = nixpkgs.lib;
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      nixosModules.nixluks = ./modules/nixluks.nix;
      nixosModules.default = self.nixosModules.nixluks;

      # The system-manager (numtide) equivalent, for the one target this design requires nixluks
      # on that is NOT NixOS. The SAME file, unchanged -- see modules/nixluks.nix's own
      # "ONE FILE, BOTH BACKENDS" header for exactly why that is honest rather than lazy.
      systemManagerModules.nixluks = ./modules/nixluks.nix;
      systemManagerModules.default = self.systemManagerModules.nixluks;

      # The device-path type, exposed so a consumer can validate a device string against the
      # SAME rule this module enforces without pulling in a whole NixOS eval -- same reason nixfs
      # exposes lib.catalogue and nixvault exposes lib.manifest.
      lib.devicePathType = import ./lib/device-path.nix { inherit lib; };

      checks = forAllSystems (system:
        import ./checks {
          pkgs = pkgsFor system;
          inherit lib nixpkgs system;
          nixluksModule = self.nixosModules.nixluks;
          systemManagerLib = system-manager.lib;
        });

      formatter = forAllSystems (system: (pkgsFor system).nixpkgs-fmt);
    };
}
