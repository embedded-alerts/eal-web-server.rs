pub mod four_transports;
pub mod web_api_plane;
pub mod auth;
pub mod gateway;
pub mod telemetry;

use std::{env, str::FromStr};

use auth::{AuthError, AuthenticatedActor, WebAuthBoundary};
use axum::{
    Form, Json, Router,
    extract::{
        DefaultBodyLimit, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use eal_api_server::{
    auth::{READ_SCOPE, WRITE_SCOPE},
    model::{AlertRule, CreateAlertRule},
};
use futures_util::{SinkExt, StreamExt};
use gateway::{GATEWAY_MODES, Gateway, GatewayError, GatewayMode};
use maud::{DOCTYPE, Markup, html};
use serde::Deserialize;
use tokio::sync::broadcast;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

const MAX_FORM_BYTES: usize = 32 * 1024;

#[derive(Clone)]
pub struct AppState {
    auth: WebAuthBoundary,
    gateway: Gateway,
    default_mode: GatewayMode,
    events: broadcast::Sender<ScopedEvent>,
}

#[derive(Clone)]
struct ScopedEvent {
    product_tenant: String,
    owner_subject: Uuid,
    message: String,
}

#[derive(Deserialize)]
struct ModeQuery {
    mode: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewAlertForm {
    mode: String,
    name: String,
    query_text: String,
}

#[derive(Debug, thiserror::Error)]
enum WebError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("invalid request")]
    InvalidRequest,
    #[error("service unavailable")]
    Unavailable,
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, Html(format!("<p>{self}</p>"))).into_response()
    }
}

impl From<AuthError> for WebError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::Unauthorized => Self::Unauthorized,
            AuthError::Degraded | AuthError::Configuration => Self::Unavailable,
        }
    }
}

impl From<GatewayError> for WebError {
    fn from(error: GatewayError) -> Self {
        match error {
            GatewayError::InvalidRequest => Self::InvalidRequest,
            GatewayError::Unavailable | GatewayError::Upstream => Self::Unavailable,
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(health))
            .route("/v1/data-plane/capabilities", axum::routing::get(|| async { axum::Json(crate::web_api_plane::capabilities()) }))
        .route("/readyz", get(health))
        .route("/partials/alerts", get(alerts_partial).post(create_alert))
        .route("/ws", get(ws_upgrade))
        .layer(DefaultBodyLimit::max(MAX_FORM_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn run() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let _telemetry = telemetry::init("eal-web-server");
    let auth = WebAuthBoundary::from_env().map_err(anyhow::Error::msg)?;
    let gateway = Gateway::from_env(auth.product_tenant().to_owned())
        .await
        .map_err(anyhow::Error::msg)?;
    let default_mode = env::var("EAL_DEFAULT_GATEWAY_MODE")
        .unwrap_or_else(|_| GATEWAY_MODES[1].to_owned())
        .parse()
        .map_err(anyhow::Error::msg)?;
    let (events, _) = broadcast::channel(256);
    let state = AppState {
        auth,
        gateway,
        default_mode,
        events,
    };
    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_owned());
    let port = env::var("PORT").unwrap_or_else(|_| "8081".to_owned());
    let listener = tokio::net::TcpListener::bind(format!("{host}:{port}")).await?;
    tracing::info!(address = %listener.local_addr()?, "Embedded Alerts web server listening");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn index(
    State(state): State<AppState>,
    Query(query): Query<ModeQuery>,
    headers: HeaderMap,
) -> Result<Html<String>, WebError> {
    let authenticated = state.auth.verify_request(&headers, READ_SCOPE).await?;
    let mode = resolve_mode(&query, state.default_mode)?;
    let alerts = state
        .gateway
        .list_alerts(mode, &authenticated.actor, &authenticated.bearer)
        .await?;
    Ok(Html(layout(alerts_markup(&alerts), mode).into_string()))
}

async fn alerts_partial(
    State(state): State<AppState>,
    Query(query): Query<ModeQuery>,
    headers: HeaderMap,
) -> Result<Html<String>, WebError> {
    let authenticated = state.auth.verify_request(&headers, READ_SCOPE).await?;
    let mode = resolve_mode(&query, state.default_mode)?;
    let alerts = state
        .gateway
        .list_alerts(mode, &authenticated.actor, &authenticated.bearer)
        .await?;
    Ok(Html(alerts_markup(&alerts).into_string()))
}

async fn create_alert(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<NewAlertForm>,
) -> Result<Html<String>, WebError> {
    let authenticated = state.auth.verify_request(&headers, WRITE_SCOPE).await?;
    let mode = GatewayMode::from_str(&form.mode)?;
    let input = CreateAlertRule {
        name: form.name,
        query_text: form.query_text,
        embedding_model: "default".to_owned(),
        similarity_threshold: 0.75,
        source_filters: Vec::new(),
        delivery_channels: vec!["web".to_owned()],
        enabled: true,
    };
    input.validate().map_err(|_| WebError::InvalidRequest)?;
    let alert = state
        .gateway
        .create_alert(&authenticated.bearer, &input)
        .await?;
    let _ = state.events.send(ScopedEvent {
        product_tenant: authenticated.actor.product_tenant.clone(),
        owner_subject: authenticated.actor.subject,
        message: format!("created:{}", alert.id),
    });
    let alerts = state
        .gateway
        .list_alerts(mode, &authenticated.actor, &authenticated.bearer)
        .await?;
    Ok(Html(alerts_markup(&alerts).into_string()))
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "eal-web-server",
        "status": "ok",
        "shared_auth_configured": true,
        "configured_modes": state.gateway.configured_modes(),
        "default_mode": state.default_mode.as_str(),
    }))
}

async fn ws_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebError> {
    let authenticated = state.auth.verify_request(&headers, READ_SCOPE).await?;
    Ok(ws.on_upgrade(move |socket| websocket(socket, state, authenticated)))
}

async fn websocket(socket: WebSocket, state: AppState, authenticated: AuthenticatedActor) {
    let (mut sender, mut receiver) = socket.split();
    let mut events = state.events.subscribe();
    loop {
        tokio::select! {
            message = receiver.next() => match message {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(_)) => break,
            },
            event = events.recv() => match event {
                Ok(event)
                    if event.product_tenant == authenticated.actor.product_tenant
                        && event.owner_subject == authenticated.actor.subject => {
                    if sender.send(Message::Text(event.message.into())).await.is_err() { break; }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => break,
                Err(broadcast::error::RecvError::Closed) => break,
            },
        }
    }
}

fn resolve_mode(query: &ModeQuery, default: GatewayMode) -> Result<GatewayMode, WebError> {
    query
        .mode
        .as_deref()
        .map(GatewayMode::from_str)
        .transpose()
        .map(|mode| mode.unwrap_or(default))
        .map_err(Into::into)
}

fn layout(content: Markup, mode: GatewayMode) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Embedded Alerts" }
                style { "body{font-family:system-ui;max-width:900px;margin:3rem auto;padding:0 1rem}nav{display:flex;flex-wrap:wrap;gap:.5rem;margin:1rem 0}form{display:grid;gap:.75rem}.card{border:1px solid #ddd;border-radius:12px;padding:1rem;margin:.75rem 0}.active{font-weight:700}" }
            }
            body {
                header {
                    h1 { "Embedded Alerts" }
                    p { "Embedding-native monitoring with explicit, bounded API transport choices." }
                }
                nav aria-label="API transport" {
                    @for candidate in GATEWAY_MODES {
                        a href=(format!("/?mode={candidate}")) class=[(candidate == mode.as_str()).then_some("active")] { (candidate) }
                    }
                }
                form method="post" action="/partials/alerts" {
                    input type="hidden" name="mode" value=(mode.as_str());
                    input type="text" name="name" maxlength="160" placeholder="Alert name" required;
                    textarea name="query_text" maxlength="8192" placeholder="What should this alert match?" required {}
                    button type="submit" { "Create alert" }
                }
                section id="alerts" { (content) }
                script { (maud::PreEscaped("const proto=location.protocol==='https:'?'wss':'ws';const ws=new WebSocket(proto+'://'+location.host+'/ws');ws.onmessage=()=>location.reload();")) }
            }
        }
    }
}

fn alerts_markup(alerts: &[AlertRule]) -> Markup {
    html! {
        @if alerts.is_empty() {
            p { "No alert rules yet." }
        }
        @for alert in alerts {
            article class="card" data-id=(alert.id) {
                h2 { (&alert.name) }
                p { (&alert.query_text) }
                small { "model: " (&alert.embedding_model) " · threshold: " (alert.similarity_threshold) }
            }
        }
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_flat_and_modes_are_explicit() {
        assert_eq!(WebError::Unauthorized.to_string(), "unauthorized");
        assert_eq!(WebError::Unavailable.to_string(), "service unavailable");
        assert_eq!(MAX_FORM_BYTES, 32 * 1024);
        for mode in GATEWAY_MODES {
            assert_eq!(GatewayMode::from_str(mode).unwrap().as_str(), mode);
        }
    }
}
