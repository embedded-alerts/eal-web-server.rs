# .nix

Nix flake defining the reproducible development environment for this repo
(toolchain plus sops/age/just for the encrypted env files). `flake.nix`
declares the dev shell; `flake.lock` pins input revisions. The top-level
`./shell` helper enters this shell via `nix develop ./.nix`.
