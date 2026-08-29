# Stack

Rust 1.95 with Maud, Axum pagelets/WebSockets, SeaORM/PostgreSQL, official
Shared Auth protected introspection, exact-pinned ORES logging, reqwest/rustls,
bounded persistent mTLS/TCP, and durable NATS JetStream.

The server exposes four explicit read modes: a dedicated read-only database
identity, redirect-free stateless HTTPS, re-authorized framed mTLS/TCP, and
signed bearer-free asynchronous request/reply. The paired API commit is pinned
immutably so both runtimes share one transport and domain contract.
