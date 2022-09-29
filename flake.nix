{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }:
    let
      inherit (builtins) fromTOML readFile;
      dexiosCargoToml = fromTOML (readFile ./dexios/Cargo.toml);

      mkDexios = { lib, rustPlatform, ... }: rustPlatform.buildRustPackage {
        inherit (dexiosCargoToml.package) name version;

        src = lib.cleanSource ./.;

        doCheck = true;

        cargoLock.lockFile = ./Cargo.lock;
      };
    in
    {
      overlays = rec {
        dexios = final: prev: {
          dexios = prev.callPackage mkDexios { };
        };
        default = dexios;
      };
    }
    //
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        dexios = pkgs.callPackage mkDexios { };
      in
      {
        # Executes by `nix build .#<name>`
        packages = {
          inherit dexios;
          default = dexios;
        };
        # the same but deprecated in Nix 2.7
        defaultPackage = self.packages.${system}.default;

        # Executes by `nix run .#<name> -- <args?>` 
        apps = {
          dexios = {
            type = "app";
            program = "${dexios}/bin/dexios";
          };
          default = self.apps.${system}.dexios;
        };
        # Executes by `nix run . -- <args?>`
        # the same but deprecated in Nix 2.7
        defaultApp = self.apps.${system}.default;

        # Used by `nix develop`
        devShell = with pkgs; mkShell {
          packages = [ cargo rustc rustfmt clippy rust-analyzer ];
          RUST_SRC_PATH = rustPlatform.rustLibSrc;
        };
      });
}
