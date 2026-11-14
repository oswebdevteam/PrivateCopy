use std::time::{Duration, Instant};

use chrono::{DateTime, Duration as ChronoDuration, Utc};

use crate::{
    domain::{Amount, NearAccount},
    error::AppError,
    oneclick::{
        AccountType, Confidentiality, GenerateIntentRequest, QuoteRequest, QuoteResponse,
        RecipientType, SwapDetails, SwapStatus, SwapType, TypedSwapStatus,
    },
    state::AppState,
};

const POLL_INTERVAL: Duration = Duration::from_millis(1_500);

pub struct SwapParams<'a> {
    pub signer: &'a NearAccount,
    pub refund_to: &'a NearAccount,
    pub recipient: &'a NearAccount,
    pub origin_asset: &'a str,
    pub destination_asset: &'a str,
    pub amount: &'a Amount,
    pub max_slippage_bps: u16,
}

#[derive(Debug)]
pub struct PreparedSwap {
    pub quote: QuoteResponse,
    pub deposit_address: String,
    pub signed_intent: serde_json::Value,
}

#[derive(Debug)]
pub struct SwapExecution {
    pub quote: QuoteResponse,
    pub status: SwapStatus,
    pub deposit_address: String,
    pub amount_in: String,
    pub amount_out: Option<String>,
    pub amount_in_usd: String,
    pub amount_out_usd: Option<String>,
    pub near_tx_hashes: Vec<String>,
}

impl SwapExecution {
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.status == SwapStatus::Success
    }
}

pub async fn execute(state: &AppState, params: &SwapParams<'_>) -> Result<SwapExecution, AppError> {
    let prepared = prepare(state, params).await?;
    submit_and_poll(state, prepared).await
}

pub async fn prepare(state: &AppState, params: &SwapParams<'_>) -> Result<PreparedSwap, AppError> {
    let deadline = deadline(state)?;
    let mut request = QuoteRequest {
        dry: true,
        swap_type: SwapType::ExactInput,
        slippage_tolerance: params.max_slippage_bps,
        origin_asset: params.origin_asset.into(),
        deposit_type: AccountType::ConfidentialIntents,
        destination_asset: params.destination_asset.into(),
        amount: params.amount.clone(),
        refund_to: params.refund_to.as_str().into(),
        refund_type: AccountType::ConfidentialIntents,
        recipient: params.recipient.as_str().into(),
        recipient_type: RecipientType::ConfidentialIntents,
        confidentiality: Confidentiality::Basic,
        deadline,
    };
    state.oneclick.quote(&request).await?;
    request.dry = false;
    request.deadline = deadline;

    let quote = state.oneclick.quote(&request).await?;
    let deposit_address = quote
        .quote
        .deposit_address
        .clone()
        .ok_or(AppError::UpstreamRejected)?;
    let intent = state
        .oneclick
        .generate_intent(&GenerateIntentRequest {
            intent_type: "swap_transfer",
            standard: "nep413",
            signer_id: params.signer.as_str(),
            deposit_address: &deposit_address,
        })
        .await?;
    let signed_intent = state.signers.sign_intent(params.signer, &intent.intent)?;
    Ok(PreparedSwap {
        quote,
        deposit_address,
        signed_intent,
    })
}

pub async fn submit_and_poll(
    state: &AppState,
    prepared: PreparedSwap,
) -> Result<SwapExecution, AppError> {
    submit(state, &prepared).await?;
    settlement(state, &prepared).await
}

pub async fn submit(state: &AppState, prepared: &PreparedSwap) -> Result<(), AppError> {
    state
        .oneclick
        .submit_intent(&prepared.signed_intent)
        .await?;
    Ok(())
}

pub async fn settlement(
    state: &AppState,
    prepared: &PreparedSwap,
) -> Result<SwapExecution, AppError> {
    let status = poll(state, &prepared.deposit_address, &prepared.quote).await?;
    let TypedSwapStatus {
        quote_response,
        status,
        swap_details,
        ..
    } = status;
    let amount_out = swap_details.amount_out.or_else(|| {
        (status != SwapStatus::Success).then(|| prepared.quote.quote.amount_out.clone())
    });
    let amount_out_usd = swap_details.amount_out_usd.or_else(|| {
        (status != SwapStatus::Success).then(|| prepared.quote.quote.amount_out_usd.clone())
    });
    Ok(SwapExecution {
        quote: quote_response,
        status,
        deposit_address: prepared.deposit_address.clone(),
        amount_in: selected_amount(
            swap_details.amount_in.as_deref(),
            &prepared.quote.quote.amount_in,
        ),
        amount_out,
        amount_in_usd: selected_amount(
            swap_details.amount_in_usd.as_deref(),
            &prepared.quote.quote.amount_in_usd,
        ),
        amount_out_usd,
        near_tx_hashes: swap_details.near_tx_hashes,
    })
}

async fn poll(
    state: &AppState,
    deposit_address: &str,
    quote: &QuoteResponse,
) -> Result<TypedSwapStatus, AppError> {
    let limit = Instant::now() + state.config.trade_settle_timeout;
    loop {
        match state.oneclick.status(deposit_address).await {
            Ok(status) => match status.status {
                SwapStatus::Success
                | SwapStatus::Refunded
                | SwapStatus::Failed
                | SwapStatus::IncompleteDeposit => return Ok(status),
                SwapStatus::PendingDeposit
                | SwapStatus::KnownDepositTx
                | SwapStatus::Processing => {}
            },
            Err(AppError::UpstreamRejected | AppError::UpstreamUnavailable) => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= limit {
            return Ok(timed_out_status(quote));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn timed_out_status(quote: &QuoteResponse) -> TypedSwapStatus {
    TypedSwapStatus {
        correlation_id: quote.correlation_id.clone(),
        quote_response: quote.clone(),
        status: SwapStatus::Processing,
        updated_at: Utc::now(),
        swap_details: SwapDetails {
            amount_in: Some(quote.quote.amount_in.clone()),
            amount_out: Some(quote.quote.amount_out.clone()),
            amount_in_usd: Some(quote.quote.amount_in_usd.clone()),
            amount_out_usd: Some(quote.quote.amount_out_usd.clone()),
            ..SwapDetails::default()
        },
    }
}

fn selected_amount(actual: Option<&str>, quoted: &str) -> String {
    actual
        .filter(|value| !value.is_empty())
        .unwrap_or(quoted)
        .into()
}

fn deadline(state: &AppState) -> Result<DateTime<Utc>, AppError> {
    let duration =
        ChronoDuration::from_std(state.config.quote_ttl).map_err(|_| AppError::Internal)?;
    Ok(Utc::now() + duration)
}
