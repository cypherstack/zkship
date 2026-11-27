use crate::rate::{extract_client_ip, ConnGuard};
use crate::room::{parse_rules, RelayOutbound, RoomOpError, ServerEvent};
use crate::AppState;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::Instant;
use zkb_core::params::Rules;

const WS_MAX_BYTES: usize = 64 * 1024;
// Reconnect catch-up can contain every peer-authored frame plus its Hello and
// Attached event. Keep enough room to queue that prefix atomically.
const OUTBOX_CAP: usize = crate::room::MAX_TRANSCRIPT_FRAMES + 4;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    CreateRoom {
        rules: Option<String>,
    },
    JoinRoom {
        room_id: String,
    },
    QuickMatch {
        rules: Option<String>,
    },
    Attach {
        room_id: String,
        seat_token: String,
        #[serde(default)]
        after_seq: u64,
    },
    ClaimFinished,
    Ping,
}

struct AttachedSeat {
    room_id: String,
    seat: usize,
    conn_id: u64,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if !state.config.origin_allowed(origin) {
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }
    let ip = extract_client_ip(&headers, peer, state.config.trust_proxy);
    let Some(guard) = state
        .tracker
        .acquire_conn(ip, state.config.max_conns_per_ip)
    else {
        return (StatusCode::TOO_MANY_REQUESTS, "too many open connections").into_response();
    };
    ws.max_message_size(WS_MAX_BYTES)
        .max_frame_size(WS_MAX_BYTES)
        .on_upgrade(move |socket| handle_socket(socket, state, ip, guard))
}

async fn handle_socket(socket: WebSocket, state: AppState, ip: IpAddr, _guard: ConnGuard) {
    let (mut ws_sink, mut ws_stream) = socket.split();
    let (out_tx, mut out_rx) = mpsc::channel::<RelayOutbound>(OUTBOX_CAP);

    let ping_interval = state.config.ping_interval;
    let pong_timeout = state.config.pong_timeout;
    let last_pong = Arc::new(tokio::sync::Mutex::new(Instant::now()));
    let last_pong_writer = Arc::clone(&last_pong);

    let writer = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(ping_interval);
        ticker.tick().await;
        loop {
            tokio::select! {
                biased;
                item = out_rx.recv() => {
                    match item {
                        Some(RelayOutbound::Text(txt)) => {
                            if ws_sink.send(Message::Text(txt.into())).await.is_err() {
                                break;
                            }
                        }
                        Some(RelayOutbound::Binary(bin)) => {
                            if ws_sink.send(Message::Binary(bin.into())).await.is_err() {
                                break;
                            }
                        }
                        Some(RelayOutbound::Close(reason)) => {
                            let _ = ws_sink.send(Message::Close(Some(CloseFrame {
                                code: 4000,
                                reason: reason.into(),
                            }))).await;
                            break;
                        }
                        None => break,
                    }
                }
                _ = ticker.tick() => {
                    let elapsed = last_pong_writer.lock().await.elapsed();
                    if elapsed > pong_timeout {
                        let _ = ws_sink.send(Message::Close(Some(CloseFrame {
                            code: 4001,
                            reason: "heartbeat timeout".into(),
                        }))).await;
                        break;
                    }
                    if ws_sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut attached: Option<AttachedSeat> = None;

    while let Some(msg_res) = ws_stream.next().await {
        let msg = match msg_res {
            Ok(m) => m,
            Err(_) => break,
        };
        *last_pong.lock().await = Instant::now();

        match msg {
            Message::Pong(_) => {}
            Message::Ping(data) => {
                let _ = data; // axum/tungstenite auto-responds to Ping frames
            }
            Message::Close(_) => break,
            Message::Text(txt) => {
                let parsed: ClientMsg = match serde_json::from_str(&txt) {
                    Ok(m) => m,
                    Err(e) => {
                        send_err(&out_tx, "bad_json", format!("invalid control message: {e}"));
                        continue;
                    }
                };
                match parsed {
                    ClientMsg::Ping => {
                        let _ = out_tx.try_send(RelayOutbound::Text(ServerEvent::Pong.to_json()));
                    }
                    ClientMsg::CreateRoom { rules } => {
                        if attached.is_some() {
                            send_err(
                                &out_tx,
                                "already_attached",
                                "socket already attached to a room",
                            );
                            continue;
                        }
                        if !state
                            .tracker
                            .allow_room_create(ip, state.config.room_create_per_min)
                        {
                            send_err(&out_tx, "rate_limited", "room creation rate limit exceeded");
                            continue;
                        }
                        let Some(rules) = parse_opt_rules(rules.as_deref()) else {
                            send_err(&out_tx, "bad_request", "unknown rules");
                            continue;
                        };
                        match state.rooms.create_room(rules, false).await {
                            Ok(info) => {
                                let _ = out_tx.try_send(RelayOutbound::Text(
                                    ServerEvent::RoomCreated {
                                        room_id: info.room_id.clone(),
                                        seat_token: info.seat_token.clone(),
                                        seat: info.seat,
                                        rules: info.rules,
                                        params_id: info.params_id,
                                    }
                                    .to_json(),
                                ));
                                attach_after_join(
                                    &state,
                                    &out_tx,
                                    &mut attached,
                                    &info.room_id,
                                    &info.seat_token,
                                    0,
                                )
                                .await;
                            }
                            Err(e) => send_room_err(&out_tx, e),
                        }
                    }
                    ClientMsg::JoinRoom { room_id } => {
                        if attached.is_some() {
                            send_err(
                                &out_tx,
                                "already_attached",
                                "socket already attached to a room",
                            );
                            continue;
                        }
                        match state.rooms.join_room(&room_id).await {
                            Ok(info) => {
                                let _ = out_tx.try_send(RelayOutbound::Text(
                                    ServerEvent::RoomJoined {
                                        room_id: info.room_id.clone(),
                                        seat_token: info.seat_token.clone(),
                                        seat: info.seat,
                                        rules: info.rules,
                                        params_id: info.params_id,
                                        peer_present: info.peer_present,
                                    }
                                    .to_json(),
                                ));
                                attach_after_join(
                                    &state,
                                    &out_tx,
                                    &mut attached,
                                    &info.room_id,
                                    &info.seat_token,
                                    0,
                                )
                                .await;
                            }
                            Err(e) => send_room_err(&out_tx, e),
                        }
                    }
                    ClientMsg::QuickMatch { rules } => {
                        if attached.is_some() {
                            send_err(
                                &out_tx,
                                "already_attached",
                                "socket already attached to a room",
                            );
                            continue;
                        }
                        if !state
                            .tracker
                            .allow_room_create(ip, state.config.room_create_per_min)
                        {
                            send_err(&out_tx, "rate_limited", "rate limit exceeded");
                            continue;
                        }
                        let Some(rules) = parse_opt_rules(rules.as_deref()) else {
                            send_err(&out_tx, "bad_request", "unknown rules");
                            continue;
                        };
                        match state.rooms.quick_match(rules).await {
                            Ok((matched, info)) => {
                                let ev = if matched {
                                    ServerEvent::Matched {
                                        room_id: info.room_id.clone(),
                                        seat_token: info.seat_token.clone(),
                                        seat: info.seat,
                                        rules: info.rules,
                                        params_id: info.params_id,
                                    }
                                } else {
                                    ServerEvent::Queued {
                                        room_id: info.room_id.clone(),
                                        seat_token: info.seat_token.clone(),
                                        seat: info.seat,
                                        rules: info.rules,
                                        params_id: info.params_id,
                                    }
                                };
                                let _ = out_tx.try_send(RelayOutbound::Text(ev.to_json()));
                                attach_after_join(
                                    &state,
                                    &out_tx,
                                    &mut attached,
                                    &info.room_id,
                                    &info.seat_token,
                                    0,
                                )
                                .await;
                            }
                            Err(e) => send_room_err(&out_tx, e),
                        }
                    }
                    ClientMsg::Attach {
                        room_id,
                        seat_token,
                        after_seq,
                    } => {
                        if let Some(prev) = attached.take() {
                            state
                                .rooms
                                .detach(&prev.room_id, prev.seat, prev.conn_id)
                                .await;
                        }
                        attach_after_join(
                            &state,
                            &out_tx,
                            &mut attached,
                            &room_id,
                            &seat_token,
                            after_seq,
                        )
                        .await;
                    }
                    ClientMsg::ClaimFinished => {
                        let Some(att) = &attached else {
                            send_err(&out_tx, "not_attached", "attach to a room first");
                            continue;
                        };
                        if !state.tracker.allow_verify(ip, state.config.verify_per_min) {
                            send_err(&out_tx, "rate_limited", "verify rate limit exceeded");
                            continue;
                        }
                        if let Err(e) = state.rooms.claim_finished(&att.room_id).await {
                            send_room_err(&out_tx, e);
                        }
                    }
                }
            }
            Message::Binary(bin) => {
                let Some(att) = &attached else {
                    send_err(
                        &out_tx,
                        "not_attached",
                        "attach to a room before sending protocol bytes",
                    );
                    continue;
                };
                let Some((&kind, payload)) = bin.split_first() else {
                    send_err(&out_tx, "bad_binary", "empty binary message");
                    continue;
                };
                match kind {
                    0x01 => {
                        if let Err(e) = state
                            .rooms
                            .submit_hello(&att.room_id, att.seat, payload)
                            .await
                        {
                            send_room_err(&out_tx, e);
                        }
                    }
                    0x02 => {
                        match state
                            .rooms
                            .submit_frame(&att.room_id, att.seat, payload)
                            .await
                        {
                            Ok((seq, frame_hash)) => {
                                let _ = out_tx.try_send(RelayOutbound::Text(
                                    ServerEvent::FrameAck { seq, frame_hash }.to_json(),
                                ));
                            }
                            Err(e) => send_room_err(&out_tx, e),
                        }
                    }
                    other => {
                        send_err(
                            &out_tx,
                            "bad_binary",
                            format!("unknown binary tag 0x{other:02x}; expected 0x01 or 0x02"),
                        );
                    }
                }
            }
        }
    }

    if let Some(att) = attached {
        state
            .rooms
            .detach(&att.room_id, att.seat, att.conn_id)
            .await;
    }
    drop(out_tx);
    let _ = writer.await;
}

async fn attach_after_join(
    state: &AppState,
    out_tx: &mpsc::Sender<RelayOutbound>,
    attached: &mut Option<AttachedSeat>,
    room_id: &str,
    seat_token: &str,
    after_seq: u64,
) {
    match state
        .rooms
        .attach(room_id, seat_token, after_seq, out_tx.clone())
        .await
    {
        Ok((seat, conn_id, out)) => {
            if let Some(old) = out.replace_old_sender {
                let _ = old.try_send(RelayOutbound::Close("replaced_by_new_connection"));
            }
            *attached = Some(AttachedSeat {
                room_id: room_id.to_string(),
                seat,
                conn_id,
            });
        }
        Err(e) => send_room_err(out_tx, e),
    }
}

fn parse_opt_rules(s: Option<&str>) -> Option<Rules> {
    match s {
        None => Some(Rules::Standard),
        Some(v) => parse_rules(v),
    }
}

fn send_err(tx: &mpsc::Sender<RelayOutbound>, code: &str, message: impl Into<String>) {
    let _ = tx.try_send(RelayOutbound::Text(
        ServerEvent::Error {
            code: code.to_string(),
            message: message.into(),
        }
        .to_json(),
    ));
}

fn send_room_err(tx: &mpsc::Sender<RelayOutbound>, err: RoomOpError) {
    let (code, msg) = match err {
        RoomOpError::NotFound => ("not_found", "room not found".to_string()),
        RoomOpError::RoomFull => ("room_full", "room is full or finished".to_string()),
        RoomOpError::ServerFull => (
            "server_full",
            "relay room or transcript storage capacity reached".to_string(),
        ),
        RoomOpError::ServerBusy => (
            "server_busy",
            "transcript verifier is at capacity; retry later".to_string(),
        ),
        RoomOpError::Unauthorized => ("unauthorized", "invalid seat token".to_string()),
        RoomOpError::BadRequest(m) => ("bad_request", m),
        RoomOpError::ClassB(m) => ("class_b", m),
        RoomOpError::TranscriptFull => (
            "transcript_full",
            "transcript frame or byte limit reached".to_string(),
        ),
    };
    send_err(tx, code, msg);
}
