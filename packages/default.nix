{ pkgs, flake, ... }:

let
  clavifaber-unwrapped = pkgs.rustPlatform.buildRustPackage {
    pname = "clavifaber";
    version = "0.1.0";
    src = flake;
    cargoLock.lockFile = flake + "/Cargo.lock";
  };
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
