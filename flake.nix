{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils, naersk }:
    utils.lib.eachDefaultSystem (system:
      let
        name = "dexios";
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage naersk { };
      in
      rec {
        # Executes by `nix build .#<name>`
        packages = {
         ${name} = naersk.lib.${system}.buildPackage {
            pname = name;
            root = ./.;
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
          buildInputs = [ cargo rustc rustfmt pre-commit rustPackages.clippy ];
          RUST_SRC_PATH = rustPlatform.rustLibSrc;
        };
      });
}
