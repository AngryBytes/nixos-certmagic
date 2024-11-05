{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
  outputs = { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;

      eachSystem = f: lib.listToAttrs
        (map
          (system: lib.nameValuePair system (f system))
          lib.systems.flakeExposed
        );

      pkgsBySystem = eachSystem
        (system: import nixpkgs {
          inherit system;
          overlays = [ self.overlays.default ];
        });

      eachPkgs = f: lib.mapAttrs (name: f) pkgsBySystem;
    in
    {
      overlays.default = import ./overlay.nix;

      nixosModules = {
        default = ./module/default.nix;
        withoutOverlay = ./module/withoutOverlay.nix;
        withOverlay = ./module/withOverlay.nix;
      };

      packages = eachPkgs (pkgs: {
        default = pkgs.nixos-certmagic;
      });

      checks = eachPkgs (pkgs: {
        default = pkgs.testers.runNixOSTest ./check.nix;
      });

      devShells = eachPkgs (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [ go nixpkgs-fmt ];
        };
      });
    };
}
