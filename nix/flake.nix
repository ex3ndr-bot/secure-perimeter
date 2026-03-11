# Nix flake for reproducible container builds
{
  description = "Secure Perimeter - attested workloads";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages = {
          workload = pkgs.dockerTools.buildImage {
            name = "secure-perimeter-workload";
            tag = "latest";
            
            copyToRoot = pkgs.buildEnv {
              name = "workload-env";
              paths = with pkgs; [
                nodejs_22
                coreutils
                cacert
              ];
            };
            
            config = {
              Cmd = [ "node" "/app/dist/main.js" ];
              WorkingDir = "/app";
              Env = [
                "NODE_ENV=production"
                "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              ];
            };
          };
          
          default = self.packages.${system}.workload;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            nodejs_22
            cosign
            kubectl
            k3s
          ];
        };
      });
}
