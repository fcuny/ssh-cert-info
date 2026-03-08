{
  description = "SSH certificate info tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; });
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgsFor.${system};
        in
        {
          default = pkgs.buildGoModule {
            pname = "ssh-cert-info";
            version = "0.1.0";
            src = ./.;
            vendorHash = "sha256-5ve09MlMiDNKY5yheOzQjv++pjT7rEGnXEStKq693xk=";
            meta = {
              description = "Check SSH certificate expiration status";
              license = pkgs.lib.licenses.mit;
              mainProgram = "ssh-cert-info";
            };
          };
        });

      devShells = forAllSystems (system:
        let
          pkgs = nixpkgsFor.${system};
        in
        {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [
              go
              gopls
              gotools
              go-tools
            ];
          };
        });
    };
}
