{
  description = "lnurl2evm";
  inputs = {
    flake-compat.url = "github:edolstra/flake-compat/v1.1.0";
    deployment.url = "git+ssh://git@github.com/SatsBridge/deployment?ref=dev";
  };
  outputs = inputs @ { self, deployment, ... }:
  let
    inherit (deployment) inputs;
    inherit (inputs)
      nixpkgs
      flake-utils;
  in flake-utils.lib.eachDefaultSystem (system:
  let
    pkgs = import nixpkgs {
      inherit system;
    };
  in {
    devShells.default = pkgs.mkShell {
      packages = builtins.attrValues {
        inherit (pkgs) nodejs_23;
        inherit (pkgs.importNpmLock.hooks) linkNodeModulesHook;
      };
      npmDeps = pkgs.importNpmLock.buildNodeModules {
        npmRoot = ./.;
        nodejs = pkgs.nodejs_23;
      };
    };
  });
}
