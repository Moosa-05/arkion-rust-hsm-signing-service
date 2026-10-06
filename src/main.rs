use arkion_rust_hsm_signing_service::{
    create_router, AppState, Config, MockSigningProvider, Pkcs11SigningProvider, SigningProvider,
};
use std::sync::Arc;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("Starting Arkion Rust HSM Signing Service (Phase 2 Axum HTTP API)");

    let config = Config::from_env()?;
    info!(config = ?config, "Configuration loaded successfully");

    let provider: Arc<dyn SigningProvider> = if config.pkcs11_lib_path.exists() {
        match Pkcs11SigningProvider::new(&config) {
            Ok(pkcs11_provider) => {
                info!("Successfully connected to PKCS#11 HSM");
                Arc::new(pkcs11_provider)
            }
            Err(e) => {
                warn!(
                    "Failed to initialize PKCS#11 HSM ({e}); falling back to MockSigningProvider"
                );
                Arc::new(MockSigningProvider::new())
            }
        }
    } else {
        warn!(
            "PKCS#11 library path {:?} not found; falling back to MockSigningProvider",
            config.pkcs11_lib_path
        );
        Arc::new(MockSigningProvider::new())
    };

    let state = AppState {
        provider,
        config: config.clone(),
    };

    let app = create_router(state);
    let bind_addr = format!("{}:{}", config.bind_host, config.bind_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    info!(
        "Arkion HSM Signing Service listening on http://{}",
        bind_addr
    );

    axum::serve(listener, app).await?;

    Ok(())
}
