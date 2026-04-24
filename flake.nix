{
  description = "clavifaber — GPG → X.509 certificate tool for CriomOS WiFi PKI + node-identity complex";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs?ref=nixos-unstable";

    blueprint.url = "github:numtide/blueprint";
    blueprint.inputs.nixpkgs.follows = "nixpkgs";

    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";

    crane.url = "github:ipetkov/crane";
  };

  outputs =
    inputs:
    let
      blueprintOutputs = inputs.blueprint { inherit inputs; };
      lib = inputs.nixpkgs.lib;
      packageCheckNames =
        system:
        builtins.listToAttrs (
          map (packageName: {
            name = "pkgs-${packageName}";
            value = true;
          }) (builtins.attrNames (blueprintOutputs.packages.${system} or { }))
        );
      derivationChecks = builtins.mapAttrs (
        system: checks:
        lib.filterAttrs (
          name: value:
          lib.isDerivation value
          && (!lib.hasPrefix "pkgs-" name || builtins.hasAttr name (packageCheckNames system))
        ) checks
      ) (blueprintOutputs.checks or { });
    in
    blueprintOutputs
    // {
      checks = derivationChecks;
    };
}
