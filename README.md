# eal-mash-web

**Embedded Alerts — MASH web server: Maud + Axum + SeaORM + Supabase + HTMX + WebSockets**

Embedding-native monitoring and alerting that continuously matches user intents against newly ingested documents, feeds, pages, and streams.

This repository was bootstrapped on 2026-08-04. It is designed as an independently deployable component and as a member of the `eal-monorepo` workspace.

## GitHub target

`embedded-alerts/eal-mash-web`

## Baseline

- Rust 2024 edition for backend and native components.
- Axum HTTP/WebSocket transport.
- Supabase/PostgreSQL configuration through `DATABASE_URL`, `SUPABASE_URL`, and environment-only secrets.
- OpenTelemetry-compatible tracing hooks.
- Docker, Nix, and GitHub Actions entry points.
- Contracts live in `eal-interfaces`; shared behavior lives in `eal-libs`.

## Development

```bash
cp .env.example .env 2>/dev/null || true
nix develop  # optional
cargo fmt --check 2>/dev/null || true
cargo test 2>/dev/null || true
```

## Status

Foundation scaffold. Domain behavior, persistence migrations, authentication policy, and production secrets must be reviewed before deployment.

## Environment secrets

Secrets live in this repo **encrypted** with [sops](https://github.com/getsops/sops) + [age](https://github.com/FiloSottile/age):
`env/enc/<dev|prod>.env.enc` is committed; `just env-use <name>` decrypts it to
`env/dec/<name>.env` (gitignored, mode 0600) and symlinks `./.env` to it. The
Nix dev shell provides the tooling, `just env-audit` runs keyless in CI, and
containers decrypt at `docker run` — never at build. See [`env/README.md`](env/README.md).
