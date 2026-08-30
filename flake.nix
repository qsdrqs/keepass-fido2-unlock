{
  description = "KeePass FIDO2 unlock support";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    keepassxc-src = {
      url = "github:qsdrqs/keepassxc/fido2-local-unlock";
      flake = false;
    };
  };

  outputs =
    { nixpkgs, keepassxc-src, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      linux-libfido2 = pkgs.callPackage ./nix/linux-libfido2.nix { };
      keepassxc-fido2 = pkgs.callPackage ./nix/keepassxc.nix {
        src = keepassxc-src;
        broker = linux-libfido2;
      };
      keepass-fido2-enroll = pkgs.callPackage ./nix/enroll.nix {
        broker = linux-libfido2;
      };
    in
    {
      packages.${system} = {
        default = keepassxc-fido2;
        inherit keepassxc-fido2 keepass-fido2-enroll linux-libfido2;
      };

      devShells.${system}.default = pkgs.mkShell {
        inputsFrom = [
          keepassxc-fido2
          linux-libfido2
        ];
        packages = [
          pkgs.cargo
          pkgs.clang-tools
          pkgs.clippy
          pkgs.libfido2
          pkgs.openssl.dev
          pkgs.rustPlatform.bindgenHook
          pkgs.rustc
          pkgs.rustfmt
        ];
      };
    };
}
