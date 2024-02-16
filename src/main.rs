// Register the module to be 'recognized'
mod middleware;
mod services;

use axum::http::{StatusCode, Uri};
use axum::response::IntoResponse;
use axum::Json;
use axum::{middleware::from_fn, routing::get, Router};
use serde_json::json;
use tracing::Level;

// import the function/any
use crate::middleware::logger;
use crate::services::auth::auth_router;

#[tokio::main]
async fn main() {
    // a builder for `FmtSubscriber`.
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::TRACE)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    // build our application with a single route
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .nest("/auth", auth_router())
        .layer(from_fn(logger::logger_fn))
        .fallback(handle_404);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::debug!("Listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn handle_404(uri: Uri) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "code": "404",
            "error": format!("Uri {} not found", uri)
        })),
    )
}
