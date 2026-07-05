{
  description = "flamberge — command-line DRM removal for ebooks (DeDRM_tools, reimplemented in Rust)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        # `nix build` / `nix profile install github:kessriga/flamberge`
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "flamberge";
          version = "0.1.0";
          src = self;
          # All dependencies are on crates.io, so the lockfile is enough — no
          # vendored-hash to maintain. Builds the workspace and installs the one
          # binary it produces (`flamberge`, from crates/flamberge-cli).
          cargoLock.lockFile = ./Cargo.lock;

          meta = {
            description = "Command-line DRM removal for ebooks (DeDRM_tools, reimplemented in Rust)";
            homepage = "https://github.com/kessriga/flamberge";
            license = pkgs.lib.licenses.mit;
            mainProgram = "flamberge";
          };
        };

        # `nix run github:kessriga/flamberge -- decrypt book.epub ...`
        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/flamberge";
        };
      }
    );
}
