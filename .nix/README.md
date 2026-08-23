# .nix

Nix flake defining the reproducible development shell for this repo: `just`,
`sops`, `age` and `ores-sops` for the encrypted environment files under
`env/enc/` (see `../env/README.md`). Enter it with `nix develop ./.nix`, or let
direnv do it via the top-level `.envrc`.
