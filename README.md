# eal-web-server

**Embedded Alerts — secure Maud/Axum pagelet and WebSocket server**

Embedding-native monitoring and alerting that continuously matches user intents against newly ingested documents, feeds, pages, and streams.

This repository is an independently deployable component and a member of the
Embedded Alerts fleet.

## GitHub target

`embedded-alerts/eal-web-server.rs`

## Baseline

- Rust 2024 edition for backend and native components.
- Axum HTTP/pagelet and tenant-scoped WebSocket transport.
- Official protected Shared Auth introspection with a separate runtime-only
  service credential and strict product authorization checks.
- Exact-pinned ORES lifecycle logging and bounded tracing.
- SeaORM 2 for the dedicated read-only database path.
- Docker, Nix, and GitHub Actions entry points.
- Zed 0.2.3 package intent plus immutable Cargo/Git locks.

Every application route requires a user token either in one unambiguous
`Authorization: Bearer` header or the externally issued `eal_access_token`
cookie. The web server calls protected `/auth/introspect` using the official
client, placing the user token only in the typed request body and the service
credential only in request authorization. It validates active state, issuer,
audience, authorized client, provider provenance, product tenant, application,
actor kind, subject, session, not-before, expiry, and the route-specific scope.

## Four web/API interaction modes

- `direct_db`: verifies the exact `__eal_web_ro` login at startup, opens a
  SeaORM `AccessMode::ReadOnly` transaction, sets transaction-local
  tenant/subject RLS context, and runs the API's immutable `SELECT` projection.
- `stateless_https`: uses a redirect-free client with connect/request timeouts,
  an origin-only validated base URL, and a streamed 256 KiB response cap. The
  API re-introspects the forwarded user token.
- `stateful_mtls_tcp`: reuses a hostname-verified, client-authenticated TLS
  connection; 64 KiB framed operations carry deadlines and are bounded by
  timeouts and queue capacity. Every operation carries the token and the API
  re-introspects it.
- `jetstream_async`: introspects first, then publishes a short-lived HMAC-signed
  actor/tenant request with correlation and dedupe identifiers. A file-backed
  event stream and per-request durable explicit-ack consumer await the reply.
  The user bearer is never placed in broker subjects, headers, payloads, logs,
  or status records. The API owns the transactional inbox/outbox/status state.

Alert creation deliberately uses only the stateless HTTPS path and is
authorized for the write scope at both servers. The direct database identity
has no write path.

## Development

```bash
cp .env.example .env 2>/dev/null || true
nix develop  # optional
cargo fmt --all -- --check
cargo check --locked --all-targets --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
zed validate
```

## Status

The adapters are implemented and locally contract-tested. This is not live
deployment evidence: operators must apply the paired API migration, provision
the least-privilege role and runtime-only credentials, provide mTLS identities,
and exercise Shared Auth, PostgreSQL/RLS, and JetStream in a disposable
environment before rollout.

## Environment secrets

Secrets live in this repo **encrypted** with [sops](https://github.com/getsops/sops) + [age](https://github.com/FiloSottile/age):
`env/enc/<dev|prod>.env.enc` is committed; `just env-use <name>` decrypts it to
`env/dec/<name>.env` (gitignored, mode 0600) and symlinks `./.env` to it. The
Nix dev shell provides the tooling, `just env-audit` runs keyless in CI, and
containers decrypt at `docker run` — never at build. See [`env/README.md`](env/README.md).
