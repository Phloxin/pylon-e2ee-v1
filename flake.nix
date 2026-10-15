{
  description = "pylon-e2ee dev shell";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems =
        f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            # build-wasm.sh. Must match the wasm-bindgen version pinned in Cargo.toml exactly.
            wasm-bindgen-cli
            # nixpkgs' rustc (which the client shell puts first on PATH) links wasm32 with a bare
            # `lld`; rustup's toolchain brings its own rust-lld instead.
            lld
          ];

          shellHook = ''
            echo "pylon-e2ee dev shell — $(rustc --version 2>/dev/null || echo 'rustc NOT FOUND (is rustup on PATH?)')"
          '';
        };
      });
    };
}
