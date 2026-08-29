# Architecture

Maud, Axum, SeaORM, and WebSocket Embedded Alerts web server.

## Fleet

- `eal-interfaces`
- `eal-api-server.rs`
- `eal-web-server.rs`
- `eal-leptos-web`
- `eal-dioxus-web`
- `eal-sync`
- `eal-cli`
- `eal-infra`
- `embedded-alerts-clients`
- `embedded-alerts-libs`
- `embedded-alerts.github.io`
- `embedded-alerts-monorepo`

Interfaces own wire formats; libraries own reusable domain behavior; clients consume versioned contracts; runtimes own deployment behavior; monorepos coordinate pinned revisions. Edge code is allowlisted and never a generic proxy.

## Authentication and authorization

The web server consumes the official Shared Auth Rust client at immutable
revision `a814cf34eeef3429e5dee36f45965b6958d694bb`. Protected introspection sends
the user token only in the strict typed request body and the independent
service credential only as request authorization. Shared Auth establishes the
identity; Embedded Alerts still enforces product tenant, application, scope,
subject, session, and alert-ownership constraints.

HTTP and TCP deliberately preserve the bearer because the API independently
re-introspects each operation. The asynchronous path instead signs the already
verified actor, tenant, operation, correlation, dedupe key, and short deadline
with a separate service key. User bearer tokens are forbidden from the broker.

## Four modes and evidence boundary

Direct reads use a dedicated exact-role check, a database read-only
transaction, transaction-local RLS context, and fixed SELECT-only SQL. HTTP is
redirect-free and response-bounded. TCP authenticates both endpoints and
re-authorizes every bounded frame. JetStream uses file storage, a durable
explicit-ack reply consumer, publish acknowledgements, correlation/dedupe, and
the API's transactional inbox/outbox/status projection.

The implementation and mock/contract tests are source evidence. They do not
prove that external Shared Auth, PostgreSQL/RLS, certificates, or JetStream are
configured in a deployment.
