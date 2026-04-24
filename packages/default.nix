{ pkgs, inputs, system, flake, ... }:

let
  toolchain = inputs.fenix.packages.${system}.fromToolchainFile {
    file = flake + "/rust-toolchain.toml";
    sha256 = "sha256-gh/xTkxKHL4eiRXzWv8KP7vfjSk61Iq48x47BEDFgfk=";
  };

  craneLib = (inputs.crane.mkLib pkgs).overrideToolchain toolchain;

  src = craneLib.cleanCargoSource flake;

  commonArgs = {
    inherit src;
    strictDeps = true;
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

  clavifaber-unwrapped = craneLib.buildPackage (commonArgs // {
    inherit cargoArtifacts;
    pname = "clavifaber";
  });
in
pkgs.symlinkJoin {
  name = "clavifaber-0.1.0";
  paths = [ clavifaber-unwrapped ];
  nativeBuildInputs = [ pkgs.makeWrapper ];
  postBuild = ''
    wrapProgram $out/bin/clavifaber \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.gnupg ]}
  '';
}
