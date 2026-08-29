use std::{str::FromStr, sync::Arc, time::Duration};

use async_nats::{
    ConnectOptions, HeaderMap as NatsHeaderMap, HeaderValue as NatsHeaderValue,
    jetstream::{self, consumer::AckPolicy, stream::StorageType},
};
use bytes::{Bytes, BytesMut};
use eal_api_server::{
    auth::VerifiedActor,
    model::{AlertRule, CreateAlertRule},
    store::read_alerts,
    transport::{
        AsyncCommand, AuthenticatedOperation, COMMAND_STREAM, COMMAND_SUBJECT_WILDCARD,
        EVENT_STREAM, EVENT_SUBJECT_WILDCARD, EventEnvelope, MAX_FRAME_BYTES,
        MAX_OPERATION_DEADLINE_MS, OperationEnvelope, OperationReply, sign_command,
    },
};
use futures_util::{SinkExt, StreamExt};
use reqwest::{Client, StatusCode, Url, redirect::Policy};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use sea_orm::{
    AccessMode, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, IsolationLevel,
    QueryResult, Statement, TransactionTrait,
};
use tokio::{
    net::TcpStream,
    sync::{Mutex, Semaphore},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use uuid::Uuid;

pub const GATEWAY_MODES: [&str; 4] = [
    "direct_db",
    "stateless_https",
    "stateful_mtls_tcp",
    "jetstream_async",
];
const MAX_HTTP_RESPONSE_BYTES: usize = 256 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const TCP_QUEUE_LIMIT: usize = 32;
const MAX_NATS_PAYLOAD_BYTES: usize = 256 * 1024;
const READONLY_ROLE: &str = "__eal_web_ro";

const CURRENT_USER_SQL: &str = "SELECT current_user AS current_user";
const SET_TENANT_SQL: &str = "SELECT set_config('eal.product_tenant', $1, true)";
const SET_SUBJECT_SQL: &str = "SELECT set_config('eal.owner_subject', $1, true)";

type TcpConnection = Framed<TlsStream<TcpStream>, LengthDelimitedCodec>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayMode {
    DirectDatabase,
    StatelessHttps,
    StatefulMtlsTcp,
    JetstreamAsync,
}

impl GatewayMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectDatabase => GATEWAY_MODES[0],
            Self::StatelessHttps => GATEWAY_MODES[1],
            Self::StatefulMtlsTcp => GATEWAY_MODES[2],
            Self::JetstreamAsync => GATEWAY_MODES[3],
        }
    }
}

impl FromStr for GatewayMode {
    type Err = GatewayError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "direct_db" => Ok(Self::DirectDatabase),
            "stateless_https" => Ok(Self::StatelessHttps),
            "stateful_mtls_tcp" => Ok(Self::StatefulMtlsTcp),
            "jetstream_async" => Ok(Self::JetstreamAsync),
            _ => Err(GatewayError::InvalidRequest),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("invalid request")]
    InvalidRequest,
    #[error("gateway mode unavailable")]
    Unavailable,
    #[error("upstream request failed")]
    Upstream,
}

#[derive(Clone)]
pub struct Gateway {
    direct: Option<DatabaseConnection>,
    http: Option<HttpGateway>,
    tcp: Option<TcpGateway>,
    nats: Option<NatsGateway>,
}

#[derive(Clone)]
struct HttpGateway {
    base_url: Url,
    client: Client,
}

#[derive(Clone)]
struct TcpGateway {
    address: String,
    server_name: String,
    connector: TlsConnector,
    connection: Arc<Mutex<Option<TcpConnection>>>,
    queue: Arc<Semaphore>,
}

#[derive(Clone)]
struct NatsGateway {
    context: jetstream::Context,
    command_key: Arc<Vec<u8>>,
    product_tenant: String,
}

impl Gateway {
    pub async fn from_env(product_tenant: String) -> Result<Self, GatewayError> {
        Ok(Self {
            direct: connect_readonly_database().await?,
            http: HttpGateway::from_env()?,
            tcp: TcpGateway::from_env()?,
            nats: NatsGateway::from_env(product_tenant).await?,
        })
    }

    pub fn configured_modes(&self) -> Vec<&'static str> {
        [
            self.direct.as_ref().map(|_| GATEWAY_MODES[0]),
            self.http.as_ref().map(|_| GATEWAY_MODES[1]),
            self.tcp.as_ref().map(|_| GATEWAY_MODES[2]),
            self.nats.as_ref().map(|_| GATEWAY_MODES[3]),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    pub async fn list_alerts(
        &self,
        mode: GatewayMode,
        actor: &VerifiedActor,
        bearer: &str,
    ) -> Result<Vec<AlertRule>, GatewayError> {
        match mode {
            GatewayMode::DirectDatabase => self.read_direct(actor).await,
            GatewayMode::StatelessHttps => {
                self.http
                    .as_ref()
                    .ok_or(GatewayError::Unavailable)?
                    .list_alerts(bearer)
                    .await
            }
            GatewayMode::StatefulMtlsTcp => {
                self.tcp
                    .as_ref()
                    .ok_or(GatewayError::Unavailable)?
                    .list_alerts(actor, bearer)
                    .await
            }
            GatewayMode::JetstreamAsync => {
                self.nats
                    .as_ref()
                    .ok_or(GatewayError::Unavailable)?
                    .list_alerts(actor)
                    .await
            }
        }
    }

    pub async fn create_alert(
        &self,
        bearer: &str,
        input: &CreateAlertRule,
    ) -> Result<AlertRule, GatewayError> {
        self.http
            .as_ref()
            .ok_or(GatewayError::Unavailable)?
            .create_alert(bearer, input)
            .await
    }

    async fn read_direct(&self, actor: &VerifiedActor) -> Result<Vec<AlertRule>, GatewayError> {
        let database = self.direct.as_ref().ok_or(GatewayError::Unavailable)?;
        let transaction = database
            .begin_with_config(
                Some(IsolationLevel::ReadCommitted),
                Some(AccessMode::ReadOnly),
            )
            .await
            .map_err(|_| GatewayError::Upstream)?;
        transaction
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                SET_TENANT_SQL,
                [actor.product_tenant.clone().into()],
            ))
            .await
            .map_err(|_| GatewayError::Upstream)?;
        transaction
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                SET_SUBJECT_SQL,
                [actor.subject.to_string().into()],
            ))
            .await
            .map_err(|_| GatewayError::Upstream)?;
        let alerts = tokio::time::timeout(REQUEST_TIMEOUT, read_alerts(&transaction, actor))
            .await
            .map_err(|_| GatewayError::Upstream)?
            .map_err(|_| GatewayError::Upstream)?;
        transaction
            .commit()
            .await
            .map_err(|_| GatewayError::Upstream)?;
        Ok(alerts)
    }
}

impl HttpGateway {
    fn from_env() -> Result<Option<Self>, GatewayError> {
        let Some(raw) = optional_env("EAL_API_URL") else {
            return Ok(None);
        };
        validate_service_url(&raw)?;
        let base_url = Url::parse(&raw).map_err(|_| GatewayError::InvalidRequest)?;
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| GatewayError::Unavailable)?;
        Ok(Some(Self { base_url, client }))
    }

    async fn list_alerts(&self, bearer: &str) -> Result<Vec<AlertRule>, GatewayError> {
        let url = self
            .base_url
            .join("v1/web/alerts")
            .map_err(|_| GatewayError::Unavailable)?;
        let response = self
            .client
            .get(url)
            .bearer_auth(bearer)
            .send()
            .await
            .map_err(|_| GatewayError::Upstream)?;
        decode_response(response, StatusCode::OK).await
    }

    async fn create_alert(
        &self,
        bearer: &str,
        input: &CreateAlertRule,
    ) -> Result<AlertRule, GatewayError> {
        let url = self
            .base_url
            .join("v1/alerts")
            .map_err(|_| GatewayError::Unavailable)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(bearer)
            .json(input)
            .send()
            .await
            .map_err(|_| GatewayError::Upstream)?;
        decode_response(response, StatusCode::CREATED).await
    }
}

impl TcpGateway {
    fn from_env() -> Result<Option<Self>, GatewayError> {
        let values = [
            optional_env("EAL_API_MTLS_ADDR"),
            optional_env("EAL_API_MTLS_SERVER_NAME"),
            optional_env("EAL_API_CA_FILE"),
            optional_env("EAL_WEB_TLS_CERT_FILE"),
            optional_env("EAL_WEB_TLS_KEY_FILE"),
        ];
        if values.iter().all(Option::is_none) {
            return Ok(None);
        }
        if values.iter().any(Option::is_none) {
            return Err(GatewayError::Unavailable);
        }
        let [address, server_name, ca_file, certificate_file, key_file] =
            values.map(Option::unwrap);
        ServerName::try_from(server_name.clone()).map_err(|_| GatewayError::InvalidRequest)?;
        let mut roots = RootCertStore::empty();
        for certificate in read_certificates(&ca_file)? {
            roots
                .add(certificate)
                .map_err(|_| GatewayError::Unavailable)?;
        }
        if roots.is_empty() {
            return Err(GatewayError::Unavailable);
        }
        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                read_certificates(&certificate_file)?,
                read_private_key(&key_file)?,
            )
            .map_err(|_| GatewayError::Unavailable)?;
        Ok(Some(Self {
            address,
            server_name,
            connector: TlsConnector::from(Arc::new(tls)),
            connection: Arc::new(Mutex::new(None)),
            queue: Arc::new(Semaphore::new(TCP_QUEUE_LIMIT)),
        }))
    }

    async fn list_alerts(
        &self,
        actor: &VerifiedActor,
        bearer: &str,
    ) -> Result<Vec<AlertRule>, GatewayError> {
        let _permit = tokio::time::timeout(
            Duration::from_millis(250),
            self.queue.clone().acquire_owned(),
        )
        .await
        .map_err(|_| GatewayError::Unavailable)?
        .map_err(|_| GatewayError::Unavailable)?;
        let operation_id = Uuid::new_v4();
        let request = AuthenticatedOperation {
            authorization: format!("Bearer {bearer}"),
            envelope: OperationEnvelope {
                version: 1,
                operation_id,
                operation: "list_alerts".to_owned(),
                actor_subject: actor.subject.to_string(),
                product_tenant: actor.product_tenant.clone(),
                deadline_unix_ms: unix_ms()?.saturating_add(MAX_OPERATION_DEADLINE_MS),
            },
        };
        let payload = serde_json::to_vec(&request).map_err(|_| GatewayError::InvalidRequest)?;
        if payload.len() > MAX_FRAME_BYTES {
            return Err(GatewayError::InvalidRequest);
        }
        let mut connection = self.connection.lock().await;
        if connection.is_none() {
            *connection = Some(self.connect().await?);
        }
        let framed = connection.as_mut().ok_or(GatewayError::Unavailable)?;
        if !matches!(
            tokio::time::timeout(REQUEST_TIMEOUT, framed.send(Bytes::from(payload))).await,
            Ok(Ok(()))
        ) {
            *connection = None;
            return Err(GatewayError::Upstream);
        }
        let frame = match tokio::time::timeout(REQUEST_TIMEOUT, framed.next()).await {
            Ok(Some(Ok(frame))) => frame,
            _ => {
                *connection = None;
                return Err(GatewayError::Upstream);
            }
        };
        let reply: OperationReply =
            serde_json::from_slice(&frame).map_err(|_| GatewayError::Upstream)?;
        if reply.operation_id != operation_id || reply.status != "completed" {
            return Err(GatewayError::Upstream);
        }
        serde_json::from_value(reply.result.ok_or(GatewayError::Upstream)?)
            .map_err(|_| GatewayError::Upstream)
    }

    async fn connect(&self) -> Result<TcpConnection, GatewayError> {
        let socket = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.address))
            .await
            .map_err(|_| GatewayError::Upstream)?
            .map_err(|_| GatewayError::Upstream)?;
        let server_name = ServerName::try_from(self.server_name.clone())
            .map_err(|_| GatewayError::InvalidRequest)?;
        let tls =
            tokio::time::timeout(CONNECT_TIMEOUT, self.connector.connect(server_name, socket))
                .await
                .map_err(|_| GatewayError::Upstream)?
                .map_err(|_| GatewayError::Upstream)?;
        Ok(LengthDelimitedCodec::builder()
            .max_frame_length(MAX_FRAME_BYTES)
            .new_framed(tls))
    }
}

impl NatsGateway {
    async fn from_env(product_tenant: String) -> Result<Option<Self>, GatewayError> {
        let url = optional_env("NATS_URL");
        let key = optional_env("EAL_NATS_COMMAND_HMAC_KEY");
        if url.is_none() && key.is_none() {
            return Ok(None);
        }
        let url = url.ok_or(GatewayError::Unavailable)?;
        let command_key = key.ok_or(GatewayError::Unavailable)?.into_bytes();
        validate_nats_url(&url)?;
        if !(32..=1024).contains(&command_key.len()) || command_key.iter().any(u8::is_ascii_control)
        {
            return Err(GatewayError::Unavailable);
        }
        let options = match optional_env("NATS_CREDENTIALS_FILE") {
            Some(path) => ConnectOptions::new()
                .credentials_file(path)
                .await
                .map_err(|_| GatewayError::Unavailable)?,
            None => ConnectOptions::new(),
        };
        let client = tokio::time::timeout(CONNECT_TIMEOUT, options.connect(url))
            .await
            .map_err(|_| GatewayError::Unavailable)?
            .map_err(|_| GatewayError::Unavailable)?;
        let context = jetstream::new(client);
        context
            .get_or_create_stream(jetstream::stream::Config {
                name: COMMAND_STREAM.to_owned(),
                subjects: vec![COMMAND_SUBJECT_WILDCARD.to_owned()],
                storage: StorageType::File,
                max_messages: 100_000,
                max_message_size: MAX_NATS_PAYLOAD_BYTES as i32,
                ..Default::default()
            })
            .await
            .map_err(|_| GatewayError::Unavailable)?;
        context
            .get_or_create_stream(jetstream::stream::Config {
                name: EVENT_STREAM.to_owned(),
                subjects: vec![EVENT_SUBJECT_WILDCARD.to_owned()],
                storage: StorageType::File,
                max_messages: 100_000,
                max_message_size: MAX_NATS_PAYLOAD_BYTES as i32,
                ..Default::default()
            })
            .await
            .map_err(|_| GatewayError::Unavailable)?;
        Ok(Some(Self {
            context,
            command_key: Arc::new(command_key),
            product_tenant,
        }))
    }

    async fn list_alerts(&self, actor: &VerifiedActor) -> Result<Vec<AlertRule>, GatewayError> {
        if actor.product_tenant != self.product_tenant {
            return Err(GatewayError::InvalidRequest);
        }
        let correlation_id = Uuid::new_v4();
        let dedupe_key = format!("list-alerts:{correlation_id}");
        let mut command = AsyncCommand {
            event_id: Uuid::new_v4(),
            correlation_id,
            dedupe_key: dedupe_key.clone(),
            product_tenant: actor.product_tenant.clone(),
            operation: OperationEnvelope {
                version: 1,
                operation_id: correlation_id,
                operation: "list_alerts".to_owned(),
                actor_subject: actor.subject.to_string(),
                product_tenant: actor.product_tenant.clone(),
                deadline_unix_ms: unix_ms()?.saturating_add(MAX_OPERATION_DEADLINE_MS),
            },
            signature: String::new(),
        };
        command.signature =
            sign_command(&command, &self.command_key).map_err(|_| GatewayError::Unavailable)?;
        let payload = serde_json::to_vec(&command).map_err(|_| GatewayError::InvalidRequest)?;
        if payload.len() > MAX_NATS_PAYLOAD_BYTES {
            return Err(GatewayError::InvalidRequest);
        }

        let event_stream = self
            .context
            .get_stream(EVENT_STREAM)
            .await
            .map_err(|_| GatewayError::Unavailable)?;
        let durable = format!("eal-web-{}", correlation_id.simple());
        let consumer = event_stream
            .get_or_create_consumer(
                &durable,
                jetstream::consumer::pull::Config {
                    durable_name: Some(durable.clone()),
                    deliver_policy: jetstream::consumer::DeliverPolicy::New,
                    ack_policy: AckPolicy::Explicit,
                    ack_wait: REQUEST_TIMEOUT,
                    filter_subject: format!("eal.event.{}.v1", actor.product_tenant),
                    max_ack_pending: 32,
                    max_deliver: 4,
                    inactive_threshold: Duration::from_secs(60),
                    ..Default::default()
                },
            )
            .await
            .map_err(|_| GatewayError::Unavailable)?;

        let mut headers = NatsHeaderMap::new();
        headers.insert(
            "Nats-Msg-Id",
            NatsHeaderValue::from_str(&dedupe_key).map_err(|_| GatewayError::InvalidRequest)?,
        );
        self.context
            .publish_with_headers(
                format!("eal.command.{}.v1", actor.product_tenant),
                headers,
                payload.into(),
            )
            .await
            .map_err(|_| GatewayError::Upstream)?
            .await
            .map_err(|_| GatewayError::Upstream)?;

        let result = self
            .await_reply(&consumer, actor, correlation_id, &dedupe_key)
            .await;
        let _ = event_stream.delete_consumer(&durable).await;
        result
    }

    async fn await_reply(
        &self,
        consumer: &jetstream::consumer::Consumer<jetstream::consumer::pull::Config>,
        actor: &VerifiedActor,
        correlation_id: Uuid,
        dedupe_key: &str,
    ) -> Result<Vec<AlertRule>, GatewayError> {
        let mut messages = consumer
            .stream()
            .max_messages_per_batch(32)
            .max_bytes_per_batch(MAX_NATS_PAYLOAD_BYTES)
            .messages()
            .await
            .map_err(|_| GatewayError::Upstream)?;
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        for _ in 0..64 {
            let message = tokio::time::timeout_at(deadline, messages.next())
                .await
                .map_err(|_| GatewayError::Upstream)?
                .ok_or(GatewayError::Upstream)?
                .map_err(|_| GatewayError::Upstream)?;
            if message.payload.len() > MAX_NATS_PAYLOAD_BYTES {
                message
                    .ack_with(jetstream::AckKind::Term)
                    .await
                    .map_err(|_| GatewayError::Upstream)?;
                continue;
            }
            let event: EventEnvelope = match serde_json::from_slice(&message.payload) {
                Ok(event) => event,
                Err(_) => {
                    message
                        .ack_with(jetstream::AckKind::Term)
                        .await
                        .map_err(|_| GatewayError::Upstream)?;
                    continue;
                }
            };
            let matches = event.correlation_id == correlation_id
                && event.product_tenant == actor.product_tenant
                && event.subject == format!("eal.event.{}.v1", actor.product_tenant)
                && event.dedupe_key == format!("reply:{dedupe_key}")
                && event.reply.operation_id == correlation_id;
            message.ack().await.map_err(|_| GatewayError::Upstream)?;
            if !matches {
                continue;
            }
            if event.reply.status != "completed" {
                return Err(GatewayError::Upstream);
            }
            return serde_json::from_value(event.reply.result.ok_or(GatewayError::Upstream)?)
                .map_err(|_| GatewayError::Upstream);
        }
        Err(GatewayError::Upstream)
    }
}

async fn connect_readonly_database() -> Result<Option<DatabaseConnection>, GatewayError> {
    let Some(url) = optional_env("EAL_WEB_READONLY_DATABASE_URL") else {
        return Ok(None);
    };
    let database = tokio::time::timeout(CONNECT_TIMEOUT, Database::connect(url))
        .await
        .map_err(|_| GatewayError::Unavailable)?
        .map_err(|_| GatewayError::Unavailable)?;
    let role = database
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Postgres,
            CURRENT_USER_SQL.to_owned(),
        ))
        .await
        .map_err(|_| GatewayError::Unavailable)?
        .ok_or(GatewayError::Unavailable)?;
    require_readonly_role(role)?;
    Ok(Some(database))
}

fn require_readonly_role(row: QueryResult) -> Result<(), GatewayError> {
    let role: String = row
        .try_get("", "current_user")
        .map_err(|_| GatewayError::Unavailable)?;
    if role == READONLY_ROLE {
        Ok(())
    } else {
        Err(GatewayError::Unavailable)
    }
}

async fn decode_response<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
    expected: StatusCode,
) -> Result<T, GatewayError> {
    if response.status() != expected {
        return Err(GatewayError::Upstream);
    }
    let mut body = BytesMut::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| GatewayError::Upstream)? {
        if body.len().saturating_add(chunk.len()) > MAX_HTTP_RESPONSE_BYTES {
            return Err(GatewayError::Upstream);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| GatewayError::Upstream)
}

pub fn validate_service_url(value: &str) -> Result<(), GatewayError> {
    let url = Url::parse(value).map_err(|_| GatewayError::InvalidRequest)?;
    let host = url.host_str().ok_or(GatewayError::InvalidRequest)?;
    let local_http = url.scheme() == "http"
        && (host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
            || host.ends_with(".svc")
            || host.ends_with(".svc.cluster.local"));
    if (url.scheme() == "https" || local_http)
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && (url.path().is_empty() || url.path() == "/")
    {
        Ok(())
    } else {
        Err(GatewayError::InvalidRequest)
    }
}

pub fn validate_nats_url(value: &str) -> Result<(), GatewayError> {
    let secure = value.starts_with("tls://") && value.len() > "tls://".len();
    let loopback = value.starts_with("nats://127.0.0.1:")
        || value.starts_with("nats://localhost:")
        || value.starts_with("nats://[::1]:");
    if (secure || loopback) && !value.contains('@') {
        Ok(())
    } else {
        Err(GatewayError::InvalidRequest)
    }
}

fn read_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>, GatewayError> {
    CertificateDer::pem_file_iter(path)
        .map_err(|_| GatewayError::Unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GatewayError::Unavailable)
}

fn read_private_key(path: &str) -> Result<PrivateKeyDer<'static>, GatewayError> {
    PrivateKeyDer::from_pem_file(path).map_err(|_| GatewayError::Unavailable)
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn unix_ms() -> Result<u64, GatewayError> {
    let value = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| GatewayError::Unavailable)?
        .as_millis();
    u64::try_from(value).map_err(|_| GatewayError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, response::Redirect, routing::get};

    #[test]
    fn service_url_is_redirect_safe_and_has_no_embedded_credentials() {
        assert!(validate_service_url("https://api.example.test").is_ok());
        assert!(validate_service_url("http://api.ns.svc.cluster.local:8080").is_ok());
        assert!(validate_service_url("http://api.example.test").is_err());
        assert!(validate_service_url("https://user:secret@api.example.test").is_err());
        assert!(validate_service_url("https://api.example.test/base").is_err());
    }

    #[test]
    fn remote_plaintext_nats_is_rejected() {
        assert!(validate_nats_url("tls://nats.example.test:4222").is_ok());
        assert!(validate_nats_url("nats://localhost:4222").is_ok());
        assert!(validate_nats_url("nats://nats.example.test:4222").is_err());
        assert!(validate_nats_url("tls://user:secret@nats.example.test:4222").is_err());
    }

    #[test]
    fn direct_database_session_contract_is_select_only() {
        for sql in [CURRENT_USER_SQL, SET_TENANT_SQL, SET_SUBJECT_SQL] {
            assert!(sql.starts_with("SELECT "));
            for forbidden in ["INSERT ", "UPDATE ", "DELETE ", "ALTER ", "DROP ", ";"] {
                assert!(!sql.contains(forbidden));
            }
        }
    }

    #[tokio::test]
    async fn stateless_client_does_not_follow_redirects() {
        let app = Router::new().route(
            "/v1/web/alerts",
            get(|| async { Redirect::temporary("/attacker-controlled") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let gateway = HttpGateway {
            base_url: Url::parse(&format!("http://{address}/")).unwrap(),
            client: Client::builder().redirect(Policy::none()).build().unwrap(),
        };
        assert!(gateway.list_alerts("end-user-access-token").await.is_err());
        task.abort();
    }
}
