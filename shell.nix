{ pkgs ? import ./pkgs.nix {} }:

with pkgs;

mkShell {
  inputsFrom = lib.attrValues (import ./. { inherit pkgs; });
  RUST_MIN_STACK = 8388608;
}
