{
  description = "clavifaber - host key-material provisioning for CriomOS";

  inputs = {
    nixpkgs.url = "github:LiGoldragon/nixpkgs?ref=main";

    rust-build = {
      url = "github:LiGoldragon/rust-build";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    ethos-zero = {
      url = "github:LiGoldragon/ethos-zero/4bf73cae8d4f5a2072c76a11cd2f00aa3fe9f8e3";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-build,
      ethos-zero,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forSystems = function: nixpkgs.lib.genAttrs systems (system: function system);

      mkContext =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          rust = rust-build.lib.${system}.fromToolchainFile pkgs {
            file = ./rust-toolchain.toml;
            sha256 = "sha256-mvUGEOHYJpn3ikC5hckneuGixaC+yGrkMM/liDIDgoU=";
          };

          inherit (rust) craneLib toolchain;
          src = rust.cleanCargoSource ./.;
          commonArgs = {
            inherit src;
            strictDeps = true;
            nativeBuildInputs = [
              pkgs.yggdrasil
              pkgs.openssh
            ];
          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        in
        {
          inherit
            pkgs
            toolchain
            craneLib
            src
            commonArgs
            cargoArtifacts
            ;
        };
    in
    {
      packages = forSystems (
        system:
        let
          context = mkContext system;
          clavifaber = context.craneLib.buildPackage (
            context.commonArgs
            // {
              inherit (context) cargoArtifacts;
              pname = "clavifaber";
              meta.mainProgram = "clavifaber";
            }
          );
          testPkiLifecycle = context.pkgs.writeShellApplication {
            name = "test-pki-lifecycle";
            runtimeInputs = [
              clavifaber
              context.pkgs.coreutils
              context.pkgs.gnugrep
              context.pkgs.gnupg
              context.pkgs.openssh
              context.pkgs.openssl
              context.pkgs.yggdrasil
            ];
            text = ''
              exec bash ${./scripts/test-pki-lifecycle} clavifaber
            '';
          };
          testDeploymentSandbox = context.pkgs.writeShellApplication {
            name = "test-deployment-sandbox";
            runtimeInputs = [
              context.pkgs.coreutils
              context.pkgs.gnugrep
              context.pkgs.bubblewrap
              context.pkgs.openssh
            ];
            text = ''
              exec bash ${./scripts/test-deployment-sandbox} ${clavifaber}/bin/clavifaber
            '';
          };
        in
        {
          default = clavifaber;
          inherit testPkiLifecycle testDeploymentSandbox;
        }
      );

      apps = forSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/clavifaber";
        };
        test-pki-lifecycle = {
          type = "app";
          program = "${self.packages.${system}.testPkiLifecycle}/bin/test-pki-lifecycle";
        };
        test-deployment-sandbox = {
          type = "app";
          program = "${self.packages.${system}.testDeploymentSandbox}/bin/test-deployment-sandbox";
        };
      });

      checks = forSystems (
        system:
        let
          context = mkContext system;
        in
        {
          build = context.craneLib.cargoBuild (
            context.commonArgs
            // {
              inherit (context) cargoArtifacts;
            }
          );
          test = context.craneLib.cargoTest (
            context.commonArgs
            // {
              inherit (context) cargoArtifacts;
            }
          );
          fmt = context.craneLib.cargoFmt {
            inherit (context) src;
          };
          clippy = context.craneLib.cargoClippy (
            context.commonArgs
            // {
              inherit (context) cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- -D warnings";
            }
          );
          generated = context.pkgs.runCommand "clavifaber-generated" {
            nativeBuildInputs = [
              ethos-zero.packages.${system}.default
              context.pkgs.diffutils
            ];
          } ''
            mkdir -p "$TMPDIR/generated"
            ethos-zero "Generate.{ ${./ethos/clavifaber.ethos} $TMPDIR/generated }"
            generated=$(find "$TMPDIR/generated" -type f -name '*.rs')
            test "$(printf '%s\n' "$generated" | wc -l)" -eq 1
            diff -u ${./src/generated/clavifaber.rs} "$generated"
            touch "$out"
          '';
        }
      );

      devShells = forSystems (
        system:
        let
          context = mkContext system;
        in
        {
          default = context.pkgs.mkShell {
            packages = [
              context.toolchain
              context.pkgs.gnupg
              context.pkgs.jujutsu
              context.pkgs.nixfmt
              context.pkgs.openssl
              context.pkgs.yggdrasil
            ];
          };
        }
      );

      formatter = forSystems (system: (mkContext system).pkgs.nixfmt);
    };
}
