use std::sync::Arc;

use redis::aio::ConnectionManager;

use crate::{
    auth::AuthService,
    config::Config,
    crypto::{EpochKeyring, SecretStore},
    near::NearClient,
    oneclick::OneClickClient,
    signer::SignerRegistry,
    store::Store,
};

pub struct AppState {
    pub config: Arc<Config>,
    pub store: Store,
    pub redis: ConnectionManager,
    pub redis_client: redis::Client,
    pub oneclick: OneClickClient,
    pub auth: AuthService,
    pub secrets: SecretStore,
    pub epochs: EpochKeyring,
    pub signers: SignerRegistry,
    pub near: NearClient,
}

pub struct AppStateParts {
    pub config: Arc<Config>,
    pub store: Store,
    pub redis: ConnectionManager,
    pub redis_client: redis::Client,
    pub oneclick: OneClickClient,
    pub auth: AuthService,
    pub secrets: SecretStore,
    pub epochs: EpochKeyring,
    pub signers: SignerRegistry,
    pub near: NearClient,
}

impl AppState {
    #[must_use]
    pub fn new(parts: AppStateParts) -> Arc<Self> {
        Arc::new(Self {
            config: parts.config,
            store: parts.store,
            redis: parts.redis,
            redis_client: parts.redis_client,
            oneclick: parts.oneclick,
            auth: parts.auth,
            secrets: parts.secrets,
            epochs: parts.epochs,
            signers: parts.signers,
            near: parts.near,
        })
    }
}
