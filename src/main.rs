mod flags;

use std::sync::Arc;

use axum::{
    Router,
    extract::{
        Form, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::{Html, IntoResponse},
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use maud::{DOCTYPE, Markup, html};
use sea_orm::{Database, DatabaseConnection};
use serde::Deserialize;
use tokio::sync::{RwLock, broadcast};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    db: Option<DatabaseConnection>,
    items: Arc<RwLock<Vec<Item>>>,
    events: broadcast::Sender<String>,
    supabase_url: Option<String>,
}

#[derive(Clone)]
struct Item {
    id: Uuid,
    title: String,
    detail: String,
}

#[derive(Deserialize)]
struct NewItem {
    title: String,
    detail: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if let Some(output) = flags::process_control().map_err(anyhow::Error::msg)? {
        print!("{output}");
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_new(
            flags::var("RUST_LOG").unwrap_or_else(|_| "error".to_owned()),
        )?)
        .init();
    let db = match flags::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => Some(Database::connect(url).await?),
        _ => None,
    };
    let (events, _) = broadcast::channel(256);
    let state = AppState {
        db,
        items: Arc::new(RwLock::new(seed_items())),
        events,
        supabase_url: flags::var("SUPABASE_URL").ok(),
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(health))
        .route("/partials/alerts", get(items_partial).post(create_item))
        .route("/ws", get(ws_upgrade))
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    let host = flags::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port = flags::var("PORT").unwrap_or_else(|_| "8081".into());
    let listener = tokio::net::TcpListener::bind(format!("{host}:{port}")).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index(State(state): State<AppState>) -> Html<String> {
    let items = state.items.read().await.clone();
    Html(layout(items_markup(&items)).into_string())
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    axum::Json(
        serde_json::json!({"status":"ok","database":state.db.is_some(),"supabase":state.supabase_url.is_some()}),
    )
}

async fn items_partial(State(state): State<AppState>) -> Html<String> {
    Html(items_markup(&state.items.read().await).into_string())
}

async fn create_item(State(state): State<AppState>, Form(input): Form<NewItem>) -> Html<String> {
    let item = Item {
        id: Uuid::new_v4(),
        title: input.title,
        detail: input.detail,
    };
    state.items.write().await.push(item.clone());
    let _ = state.events.send(format!("created:{}", item.id));
    Html(items_markup(&state.items.read().await).into_string())
}

fn layout(content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Embedded Alerts" }
                script src="https://unpkg.com/htmx.org@2.0.4" {}
                style { "body{font-family:system-ui;max-width:900px;margin:3rem auto;padding:0 1rem} form{display:grid;gap:.75rem} .card{border:1px solid #ddd;border-radius:12px;padding:1rem;margin:.75rem 0}" }
            }
            body {
                header { h1 { "Embedded Alerts" } p { "Embedding-native monitoring and alerting that continuously matches user intents against newly ingested documents, feeds, pages, and streams." } }
                form hx-post="/partials/alerts" hx-target="#items" hx-swap="innerHTML" {
                    input type="text" name="title" placeholder="Title" required;
                    textarea name="detail" placeholder="Details" required {}
                    button type="submit" { "Create AlertRule" }
                }
                section id="items" { (content) }
                script { (maud::PreEscaped("const proto=location.protocol==='https:'?'wss':'ws';const ws=new WebSocket(proto+'://'+location.host+'/ws');ws.onmessage=()=>htmx.ajax('GET','/partials/alerts',{target:'#items'});")) }
            }
        }
    }
}

fn items_markup(items: &[Item]) -> Markup {
    html! { @for item in items { article class="card" data-id=(item.id) { h2 { (item.title) } p { (item.detail) } } } }
}

fn seed_items() -> Vec<Item> {
    vec![Item {
        id: Uuid::new_v4(),
        title: "Foundation ready".into(),
        detail: "Maud + Axum + SeaORM + Supabase configuration + HTMX + WebSockets".into(),
    }]
}

async fn ws_upgrade(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| websocket(socket, state))
}
async fn websocket(socket: WebSocket, state: AppState) {
    let (mut tx, mut rx) = socket.split();
    let mut events = state.events.subscribe();
    loop {
        tokio::select! {
            message = rx.next() => match message { Some(Ok(Message::Close(_))) | None => break, _ => {} },
            event = events.recv() => match event { Ok(event) => if tx.send(Message::Text(event.into())).await.is_err() { break; }, Err(_) => break },
        }
    }
}
