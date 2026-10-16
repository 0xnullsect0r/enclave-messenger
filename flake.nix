{
  # Enclave's Nix build (nix/default.nix). No flake inputs: nixpkgs is
  # pinned inside by its release tarball and hash, so `nix build` needs
  # nothing but this repository.
  description = "Enclave: private messages without a phone number";

  outputs =
    { self }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAll = f: builtins.listToAttrs (map (system: {
        name = system;
        value = f system;
      }) systems);
      build = forAll (system: import ./nix { inherit system; });
    in
    {
      packages = forAll (system: {
        inherit (build.${system})
          enclave
          enclave-server
          enclave-nym
          lyrebird
          default
          ;
      });
    };
}
