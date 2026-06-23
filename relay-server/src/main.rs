//! fluxpeer relay-server binary — thin wrapper over the lib's `serve_from_env`.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    fluxpeer_relay_server::serve_from_env().await
}
