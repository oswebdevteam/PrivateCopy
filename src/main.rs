use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use privatecopy_server::{
    api,
    auth::AuthService,
    config::Config,
    crypto::{EpochKeyring, SecretStore},
    domain::NearAccount,
    near::NearClient,
    oneclick::OneClickClient,
    services::{attestor, indexer},
    signer::SignerRegistry,
    state::{AppState, AppStateParts},
    store::Store,
};
use redis::aio::ConnectionManager;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing()?;
    let config = Arc::new(Config::from_env()?);

    let pool = PgPoolOptions::new()
        .min_connections(1)
        .max_connections(20)
        .connect(&config.database_url)
        .await
        .context("connect to Postgres")?;
    sqlx::migrate!()
        .run(&pool)
        .await
        .context("run database migrations")?;

    let redis_client = redis::Client::open(config.redis_url.as_str()).context("parse Redis URL")?;
    let redis = ConnectionManager::new(redis_client.clone())
        .await
        .context("connect to Redis")?;

    let http = reqwest::Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(config.upstream_timeout)
        .build()
        .context("build HTTP client")?;

    let near = NearClient::new(http.clone(), config.near_rpc_url.clone());
    let oneclick = OneClickClient::new(
        http,
        config.oneclick_url.clone(),
        config.oneclick_api_key.clone(),
    );
    let auth = AuthService::new(
        &config.jwt_secret,
        config.auth_recipient.clone(),
        config.jwt_ttl,
        near.clone(),
    );
    let epochs = EpochKeyring::from_secret(&config.epoch_master_key)?;
    let signers = SignerRegistry::load(config.agent_keys_file.as_deref())?;
    if let Some(account) = config.attestor_account.as_deref() {
        let account: NearAccount = account.parse().context("parse APP_ATTESTOR_ACCOUNT")?;
        signers
            .signer(&account)
            .context("load attestor signing key")?;
    }
    let state = AppState::new(AppStateParts {
        config: Arc::clone(&config),
        store: Store::new(pool),
        redis,
        redis_client,
        oneclick,
        auth,
        secrets: SecretStore::default(),
        epochs,
        signers,
        near,
    });
    tokio::spawn(attestor::run(Arc::clone(&state)));
    tokio::spawn(indexer::run(Arc::clone(&state)));
    let app = api::router(state);
    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("bind {}", config.bind_addr))?;

    info!(address = %config.bind_addr, "server listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("serve HTTP")
}

fn init_tracing() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .try_init()
        .map_err(|error| anyhow::anyhow!("initialize tracing: {error}"))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(%error, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
