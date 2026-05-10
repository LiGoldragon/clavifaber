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
        in
        {
          default = clavifaber;
          inherit testPkiLifecycle;
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
      });

      checks = forSystems (
        system:
        let
          context = mkContext system;
          clavifaber = self.packages.${system}.default;
          stateWrite = context.pkgs.runCommand "clavifaber-state-write" { } ''
            mkdir -p $out
            export HOME=$TMPDIR/home
            mkdir -p $HOME
            ${clavifaber}/bin/clavifaber "(Converge \"$out/identity\" probus \"$out/publication.nota\" None None \"$out/clavifaber.redb\" None None [])" > $out/converge_reply.nota
            test -f "$out/clavifaber.redb" || (echo "writer did not create clavifaber.redb"; exit 1)
            test -f "$out/publication.nota" || (echo "writer did not write publication.nota"; exit 1)
            grep -q 'true' "$out/converge_reply.nota" || (echo "writer did not record work_performed = true"; cat "$out/converge_reply.nota"; exit 1)
          '';
          stateRead = context.pkgs.runCommand "clavifaber-state-read" { } ''
            cp ${stateWrite}/clavifaber.redb $TMPDIR/clavifaber.redb
            chmod u+w $TMPDIR/clavifaber.redb
            ${clavifaber}/bin/clavifaber "(InspectState \"$TMPDIR/clavifaber.redb\")" > $TMPDIR/inspect_reply.nota
            cat $TMPDIR/inspect_reply.nota
            grep -q 'StateReport' $TMPDIR/inspect_reply.nota || (echo "reader did not get StateReport"; exit 1)
            grep -q 'ConvergeLedger' $TMPDIR/inspect_reply.nota || (echo "reader did not surface a convergence ledger entry"; exit 1)
            touch $out
          '';
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
          state-write = stateWrite;
          state-read = stateRead;
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
