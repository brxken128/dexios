{
  inputs = {
    nixpkgs.url = github:NixOS/nixpkgs/nixpkgs-unstable;
    utils.url = github:numtide/flake-utils;
  };

  outputs = { self, nixpkgs, utils, fenix }:
    utils.lib.eachDefaultSystem (system:
      let
        name = "dexios";
        pkgs = import nixpkgs { inherit system; };
        dexiosCargoToml = with builtins; (fromTOML (readFile ./dexios/Cargo.toml));
      in
      rec {
        # Executes by `nix build .#<name>`
        packages = {
          ${name} = pkgs.rustPlatform.buildRustPackage {
            inherit (dexiosCargoToml.package) name version;

            src = nixpkgs.lib.cleanSource ./.;

            doCheck = true;

            cargoLock.lockFile = ./Cargo.lock;
          };
        };
        # Executes by `nix build .`
        packages.default = packages.${name};
        # the same but deprecated in Nix 2.7
        defaultPackage = packages.default;

        # Executes by `nix run .#<name> -- <args?>` 
        apps = {
          ${name} = utils.lib.mkApp {
            inherit name;
            drv = packages.${name};
          };
        };
        # Executes by `nix run . -- <args?>`
        apps.default = apps.${name};
        # the same but deprecated in Nix 2.7
        defaultApp = apps.default;

        # Used by `nix develop`
        devShell = with pkgs; mkShell {
          packages = [ cargo rustc rustfmt clippy rust-analyzer ];
          RUST_SRC_PATH = rustPlatform.rustLibSrc;
        };
      });
}
