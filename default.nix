{ pkgs ? import ./pkgs.nix {} }:

with pkgs;

let
  inherit (rust.packages.nightly) rustPlatform;
in

{
  zerotier = buildRustPackage rustPlatform {
    name = "zerotier";
    src = gitignoreSource ./.;
    cargoDir = ".";
  };
}
