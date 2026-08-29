#![forbid(unsafe_code)]
//! The four avenues this web server can use to reach `eal-api-server`.
//!
//! Generated from the fleet-wide contract in
//! <https://github.com/ORESoftware/ores-transport>, which owns the parts that
//! are shared *and* subtle: the envelope, the byte ceilings, absolute
//! deadlines, reply correlation, global backpressure, and the
//! redeliver-versus-terminate decision. This module owns only what is specific
//! to embedded-alerts — the environment prefix, the service slug that names its NATS
//! subjects, and the api route that accepts an envelope.
//!
//! | # | Mode | What happens |
//! |---|------|--------------|
//! | 1 | `direct_read` | this server queries Postgres itself through `eal-lib-core`, read-only |
//! | 2 | `http` | stateless request to the `eal-api-server` cluster |
//! | 3 | `tcp` | framed, held-open connection to the `eal-api-server` cluster |
//! | 4 | `jet_stream` | published to NATS; the api server answers asynchronously |
//!
//! # Finishing the wiring
//!
//! One thing is left to this repository, because only this repository knows
//! what an operation *is*: implement [`ores_transport::DirectReader`] over
//! `eal-lib-core`'s read context, and hand it to [`gateway_from_env`]. See
//! `docs/four-transports.md`.

use ores_transport::{
    DEFAULT_TRANSPORT_TIMEOUT, DirectReader, Gateway, HttpRoute, HttpTransport, NatsTransport,
    PersistentTcpClient, TcpEndpoint, TlsConnector, TransportConfig, TransportMode,
};
use serde::{Serialize, de::DeserializeOwned};
use std::{net::SocketAddr, sync::Arc};

/// Environment prefix for every variable this service reads.
///
/// `EAL_API_URL`, `EAL_NATS_URL`, and the rest; see the
/// table in `ores-transport`'s README.
pub const ENV_PREFIX: &str = "EAL";

/// Service slug, which derives the NATS subjects and JetStream stream names.
///
/// It must match the slug the api server uses, or the two will be publishing
/// and consuming on different subjects while both look healthy.
pub const SERVICE_SLUG: &str = "eal";

/// The api server route that accepts an envelope on avenue 2.
pub const ENVELOPE_PATH: &str = "/v1/operations";

/// A failure while wiring the avenues at startup.
pub type SetupError = Box<dyn std::error::Error + Send + Sync>;

/// Build the gateway for this process from the environment.
///
/// Every avenue past the first is attached only if its variables are set, so a
/// deployment without a NATS cluster is a normal deployment: asking it for
/// `jet_stream` yields `TransportError::NotConfigured` rather than failing to
/// start. A variable that is present and *unsafe* — a plaintext api URL off
/// loopback, half-configured mutual TLS — does fail startup, because that is a
/// misconfiguration wearing a working service's clothes.
///
/// `tls` is the client side of mutual TLS for avenue 3. Pass `None` in a mesh
/// that terminates TLS in a sidecar.
///
/// # Errors
/// [`SetupError`] if a variable is present and unusable, if the stateful
/// address will not parse, or if NATS refuses the connection.
pub async fn gateway_from_env<O, T>(
    direct: Arc<dyn DirectReader<O, T>>,
    tls: Option<TlsConnector>,
) -> Result<Gateway<O, T>, SetupError>
where
    O: Serialize + Send + Sync,
    T: DeserializeOwned + Send,
{
    let config = TransportConfig::from_env(ENV_PREFIX)?;
    let mut gateway = Gateway::new(direct);

    // Avenue 2.
    if let Some(api_url) = config.api_url.as_deref() {
        let client = HttpTransport::client_for(api_url, DEFAULT_TRANSPORT_TIMEOUT)?;
        gateway = gateway.with_http(
            HttpTransport::new(client, api_url, DEFAULT_TRANSPORT_TIMEOUT),
            HttpRoute {
                envelope_path: ENVELOPE_PATH.to_owned(),
            },
        );
    }

    // Avenue 3.
    if let Some(raw) = config.api_tcp_addr.as_deref() {
        let address: SocketAddr = raw.parse()?;
        let endpoint = TcpEndpoint {
            address,
            server_name: config.api_tls_server_name.clone(),
            timeout: DEFAULT_TRANSPORT_TIMEOUT,
        };
        // Mutual TLS only when the config is *complete*; a half-configured
        // connector would fail every call rather than fail to start.
        let client = match (tls, config.uses_mtls()) {
            (Some(connector), true) => PersistentTcpClient::tls(endpoint, connector),
            _ => PersistentTcpClient::plaintext(endpoint),
        };
        gateway = gateway.with_tcp(Arc::new(client));
    }

    // Avenue 4.
    if let Some(nats_url) = config.nats_url.as_deref() {
        let context = ores_transport::connect_nats(nats_url).await?;
        gateway = gateway.with_nats(NatsTransport::new(
            context,
            SERVICE_SLUG,
            DEFAULT_TRANSPORT_TIMEOUT,
        ));
    }

    Ok(gateway)
}

/// The avenues this process can actually serve, for a capabilities endpoint.
///
/// Worth exposing: an operator reading "tcp is missing" from the service
/// itself beats inferring it from a 503 at 3am.
#[must_use]
pub fn advertised_modes<O, T>(gateway: &Gateway<O, T>) -> Vec<&'static str>
where
    O: Serialize + Send + Sync,
    T: DeserializeOwned + Send,
{
    gateway
        .available_modes()
        .into_iter()
        .map(|mode| mode.as_wire())
        .collect()
}

/// Parse a caller-supplied `?mode=` value.
///
/// Refuses an unknown spelling rather than defaulting to one. Silently falling
/// back to HTTP would make an end-to-end suite that thinks it is exercising
/// all four avenues actually exercise one.
#[must_use]
pub fn requested_mode(raw: Option<&str>) -> Option<TransportMode> {
    match raw {
        None => Some(TransportMode::Http),
        Some(value) => TransportMode::from_wire(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_service_slug_matches_the_environment_prefix() {
        // These two drift apart in exactly one way: someone renames the
        // service and updates one of them. Then the web server publishes to
        // subjects the api server does not consume, and both look healthy.
        assert_eq!(SERVICE_SLUG.replace('-', "_").to_uppercase(), ENV_PREFIX);
    }

    #[test]
    fn an_absent_mode_defaults_to_http_and_an_unknown_one_is_refused() {
        assert_eq!(requested_mode(None), Some(TransportMode::Http));
        assert_eq!(requested_mode(Some("tcp")), Some(TransportMode::Tcp));
        assert_eq!(requested_mode(Some("jet_stream")), Some(TransportMode::JetStream));
        assert_eq!(requested_mode(Some("grpc")), None);
        assert_eq!(requested_mode(Some("")), None);
    }
}
