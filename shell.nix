{ pkgs ? import <nixpkgs> {}}: with pkgs;

mkShell {
  buildInputs = [ rustup nodejs-16_x ];
}
