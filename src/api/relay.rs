use std::{sync::Arc, time::Duration};

use axum::{
    extract::{
        Path, Query, State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket},
    },
    http::{HeaderMap, header},
    response::Response,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use redis::{
    AsyncCommands,
    streams::{StreamRangeReply, StreamReadOptions, StreamReadReply},
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    crypto::{constant_time_eq, seal_to_agent},
    domain::{KeyId, SignalFrame, StrategyId},
    error::AppError,
    services::strategy::{frame_for_signal, stream_key},
    state::AppState,
    store::{AccessKeyView, SignalRow},
};

const PROOF_AAD: &[u8] = b"privatecopy/ws-proof/v1";
const PROOF_TIMEOUT: Duration = Duration::from_secs(30);
const HEARTBEAT: Duration = Duration::from_secs(30);
const STREAM_BLOCK_MS: usize = 5_000;

#[derive(Debug, Deserialize)]
pub struct SignalQuery {
    pub key_id: String,
    pub since: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ProofMessage {
    #[serde(rename = "type")]
    message_type: String,
    challenge: String,
}

pub async fn connect(
    State(state): State<Arc<AppState>>,
    Path(strategy_id): Path<String>,
    Query(query): Query<SignalQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let token = bearer_token(&headers).ok_or(AppError::Unauthorized)?;
    let account = state.auth.authenticate(&token)?;
    let strategy_id = StrategyId::parse(strategy_id)?;
    let key_id = KeyId::parse(query.key_id)?;
    let key = state
        .store
        .active_key_for_holder(&key_id, &account.0)
        .await?;
    if key.strategy_id != strategy_id.as_str() {
        return Err(AppError::Forbidden);
    }
    let since = query.since.unwrap_or_default();
    Ok(ws
        .protocols(["bearer"])
        .on_upgrade(move |socket| handle(socket, state, strategy_id, key, since)))
}

async fn handle(
    socket: WebSocket,
    state: Arc<AppState>,
    strategy_id: StrategyId,
    key: AccessKeyView,
    since: u64,
) {
    let (mut sender, mut receiver) = socket.split();
    if let Err(reason) = authorize_agent(&mut sender, &mut receiver, &key).await {
        close(&mut sender, reason).await;
        return;
    }
    let (mut connection, stream, mut last_id) = match open_stream(&state, &strategy_id).await {
        Ok(stream) => stream,
        Err(reason) => {
            close(&mut sender, reason).await;
            return;
        }
    };

    let mut last_seq = since;
    if let Err(reason) = replay(&state, &key, &strategy_id, &mut sender, &mut last_seq).await {
        close(&mut sender, reason).await;
        return;
    }
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    loop {
        let keys = [stream.as_str()];
        let ids = [last_id.as_str()];
        let options = StreamReadOptions::default()
            .block(STREAM_BLOCK_MS)
            .count(32);
        tokio::select! {
            incoming = receiver.next() => {
                match incoming {
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if sender.send(Message::Pong(payload)).await.is_err() { break; }
                    }
                    Some(Ok(_)) => {}
                }
            }
            _ = heartbeat.tick() => {
                if send_json(&mut sender, &json!({"type":"heartbeat"})).await.is_err() {
                    break;
                }
            }
            reply = connection.xread_options::<_, _, Option<StreamReadReply>>(&keys, &ids, &options) => {
                let reply = match reply {
                    Ok(reply) => reply,
                    Err(error) => {
                        tracing::warn!(error = %error, "Redis signal read failed");
                        close(&mut sender, "signal stream unavailable").await;
                        break;
                    }
                };
                let Some(reply) = reply else { continue };
                for stream in reply.keys {
                    for entry in stream.ids {
                        last_id.clone_from(&entry.id);
                        let Some(seq) = stream_u64(&entry.map, "seq") else { continue };
                        if let Err(reason) = deliver(
                            &state,
                            &key,
                            &strategy_id,
                            seq,
                            &mut last_seq,
                            &mut sender,
                        ).await {
                            close(&mut sender, reason).await;
                            return;
                        }
                    }
                }
            }
        }
    }
}

async fn authorize_agent(
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    receiver: &mut futures_util::stream::SplitStream<WebSocket>,
    key: &AccessKeyView,
) -> Result<(), &'static str> {
    let mut expected = [0_u8; 32];
    rand::rng().fill_bytes(&mut expected);
    let sealed = seal_to_agent(&key.agent_pubkey, PROOF_AAD, &expected)
        .map_err(|_| "agent key is invalid")?;
    let challenge = json!({
        "type": "challenge",
        "sealed_challenge": sealed,
        "expires_in": PROOF_TIMEOUT.as_secs(),
    });
    send_json(sender, &challenge).await?;
    if verify_proof(receiver, &expected).await {
        Ok(())
    } else {
        Err("agent proof failed")
    }
}

async fn open_stream(
    state: &AppState,
    strategy_id: &StrategyId,
) -> Result<(redis::aio::MultiplexedConnection, String, String), &'static str> {
    let mut connection = state
        .redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "could not open Redis stream connection");
            "signal stream unavailable"
        })?;
    let stream = stream_key(strategy_id);
    let last_id = connection
        .xrevrange_count::<_, _, _, _, StreamRangeReply>(&stream, "+", "-", 1)
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "could not read Redis stream head");
            "signal stream unavailable"
        })?
        .ids
        .first()
        .map_or_else(|| "0-0".into(), |entry| entry.id.clone());
    Ok((connection, stream, last_id))
}

async fn replay(
    state: &AppState,
    key: &AccessKeyView,
    strategy_id: &StrategyId,
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    last_seq: &mut u64,
) -> Result<(), &'static str> {
    loop {
        let rows = state
            .store
            .signals_after(strategy_id, *last_seq, 200)
            .await
            .map_err(|_| "signal lookup failed")?;
        if rows.is_empty() {
            return Ok(());
        }
        for signal in rows {
            deliver_row(state, key, &signal, last_seq, sender).await?;
        }
    }
}

async fn deliver(
    state: &AppState,
    key: &AccessKeyView,
    strategy_id: &StrategyId,
    seq: u64,
    last_seq: &mut u64,
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) -> Result<(), &'static str> {
    if seq <= *last_seq {
        return Ok(());
    }
    let signal = state
        .store
        .signal(strategy_id, seq)
        .await
        .map_err(|_| "signal lookup failed")?
        .ok_or("signal missing")?;
    deliver_row(state, key, &signal, last_seq, sender).await
}

async fn deliver_row(
    state: &AppState,
    key: &AccessKeyView,
    signal: &SignalRow,
    last_seq: &mut u64,
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) -> Result<(), &'static str> {
    if signal.valid_until <= chrono::Utc::now() {
        *last_seq = signal.seq;
        return Ok(());
    }
    let holder = key.holder.parse().map_err(|_| "invalid holder")?;
    state
        .store
        .active_key_for_holder(
            &KeyId::parse(key.key_id.clone()).map_err(|_| "invalid key")?,
            &holder,
        )
        .await
        .map_err(|_| "access expired")?;
    if key.tier().map_err(|_| "invalid tier")? == crate::domain::AccessTier::Delayed {
        let due = signal.created_at
            + chrono::Duration::from_std(state.config.delayed_tier).map_err(|_| "invalid delay")?;
        if due >= signal.valid_until {
            *last_seq = signal.seq;
            return Ok(());
        }
        if let Ok(wait) = (due - chrono::Utc::now()).to_std() {
            tokio::time::sleep(wait).await;
        }
    }
    if signal.valid_until <= chrono::Utc::now() {
        *last_seq = signal.seq;
        return Ok(());
    }
    let frame = frame_for_signal(state, key, signal).map_err(|_| "signal wrapping failed")?;
    send_frame(sender, &frame).await?;
    *last_seq = signal.seq;
    Ok(())
}

async fn verify_proof(
    receiver: &mut futures_util::stream::SplitStream<WebSocket>,
    expected: &[u8; 32],
) -> bool {
    let timeout = tokio::time::timeout(PROOF_TIMEOUT, receiver.next()).await;
    let Ok(Some(Ok(Message::Text(text)))) = timeout else {
        return false;
    };
    let Ok(message) = serde_json::from_str::<ProofMessage>(&text) else {
        return false;
    };
    if message.message_type != "proof" {
        return false;
    }
    let Ok(proof) = BASE64.decode(message.challenge) else {
        return false;
    };
    constant_time_eq(&proof, expected)
}

async fn send_frame(
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    frame: &SignalFrame,
) -> Result<(), &'static str> {
    let value = serde_json::to_value(frame).map_err(|_| "signal encoding failed")?;
    send_json(sender, &value).await
}

async fn send_json(
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    value: &serde_json::Value,
) -> Result<(), &'static str> {
    let text = serde_json::to_string(value).map_err(|_| "frame encoding failed")?;
    sender
        .send(Message::Text(text.into()))
        .await
        .map_err(|_| "socket send failed")
}

async fn close(
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    reason: &'static str,
) {
    let _ = sender
        .send(Message::Close(Some(CloseFrame {
            code: axum::extract::ws::close_code::POLICY,
            reason: reason.into(),
        })))
        .await;
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    {
        return Some(value.to_owned());
    }
    let protocols = headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())?;
    let mut parts = protocols.split(',').map(str::trim);
    let first = parts.next()?;
    if first != "bearer" {
        return None;
    }
    parts
        .next()
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
}

fn stream_u64(map: &std::collections::HashMap<String, redis::Value>, key: &str) -> Option<u64> {
    use redis::Value;
    match map.get(key)? {
        Value::Int(value) => u64::try_from(*value).ok(),
        Value::BulkString(bytes) => std::str::from_utf8(bytes).ok()?.parse().ok(),
        Value::SimpleString(value) => value.parse().ok(),
        _ => None,
    }
}
