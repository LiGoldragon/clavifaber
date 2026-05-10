{
  description = "clavifaber - host key-material provisioning for CriomOS";

  inputs = {
    nixpkgs.url = "github:LiGoldragon/nixpkgs?ref=main";

    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";

    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      fenix,
      crane,
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
          toolchain = fenix.packages.${system}.fromToolchainFile {
            file = ./rust-toolchain.toml;
            sha256 = "sha256-gh/xTkxKHL4eiRXzWv8KP7vfjSk61Iq48x47BEDFgfk=";
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;
          src = craneLib.cleanCargoSource ./.;
          commonArgs = {
            inherit src;
            strictDeps = true;
            nativeBuildInputs = [ pkgs.yggdrasil ];
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
