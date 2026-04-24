{
  description = "clavifaber — GPG → X.509 certificate tool for CriomOS WiFi PKI + node-identity complex";

  inputs = {
    # Pinned in lockstep with CriomOS for /nix/store cache reuse.
    nixpkgs.url = "github:NixOS/nixpkgs/b12141ef619e0a9c1c84dc8c684040326f27cdcc";

    blueprint.url = "github:numtide/blueprint";
    blueprint.inputs.nixpkgs.follows = "nixpkgs";

    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";

    crane.url = "github:ipetkov/crane";
  };

  outputs = inputs: inputs.blueprint { inherit inputs; };
}
