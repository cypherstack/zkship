use crate::rate::{extract_client_ip, IpTracker};
use crate::room::{decode_hex, hex, parse_rules, role_str, rules_name, RoomManager, RoomOpError};
use crate::AppState;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use zkb_core::params::{Parameters, Rules, BOARD_N, FLEET_LENGTHS, K, T};
use zkb_session::codec::MAX_FRAME_SIZE;
use zkb_session::hello::Hello;
use zkb_session::verify::{self, TranscriptVerdict};

#[derive(Serialize)]
struct ApiErrorBody {
    error: &'static str,
    message: String,
}

fn api_err(
    status: StatusCode,
    error: &'static str,
    message: impl Into<String>,
) -> axum::response::Response {
    (
        status,
        Json(ApiErrorBody {
            error,
            message: message.into(),
        }),
    )
        .into_response()
}

fn map_room_err(err: RoomOpError) -> axum::response::Response {
    match err {
        RoomOpError::NotFound => api_err(StatusCode::NOT_FOUND, "not_found", "room not found"),
        RoomOpError::RoomFull => api_err(
            StatusCode::CONFLICT,
            "room_full",
            "room is already full or finished",
        ),
        RoomOpError::ServerFull => api_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_full",
            "relay room or transcript storage capacity reached",
        ),
        RoomOpError::ServerBusy => api_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_busy",
            "transcript verifier is at capacity; retry later",
        ),
        RoomOpError::Unauthorized => api_err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid seat token",
        ),
        RoomOpError::BadRequest(m) => api_err(StatusCode::BAD_REQUEST, "bad_request", m),
        RoomOpError::ClassB(m) => api_err(StatusCode::BAD_REQUEST, "class_b", m),
        RoomOpError::TranscriptFull => api_err(
            StatusCode::BAD_REQUEST,
            "transcript_full",
            "transcript frame or byte limit reached",
        ),
    }
}

pub async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.rooms.health_stats().await;
    Json(serde_json::json!({
        "status": "ok",
        "rooms": stats.rooms,
        "quick_match_queued": stats.quick_match_queued,
        "transcript_bytes": stats.transcript_bytes,
        "max_transcript_bytes": stats.max_transcript_bytes,
    }))
}

pub async fn params() -> impl IntoResponse {
    Json(serde_json::json!({
        "board_n": BOARD_N,
        "ship_lengths": FLEET_LENGTHS,
        "total_ship_cells": T,
        "hello_len": Hello::LEN,
        "max_frame_size": MAX_FRAME_SIZE,
        "profiles": {
            "standard": hex(Parameters::standard().params_id()),
            "no-touch": hex(Parameters::no_touch().params_id()),
        }
    }))
}

#[derive(Default, Deserialize)]
pub struct CreateRoomReq {
    pub rules: Option<String>,
}

pub async fn create_room(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let ip = extract_client_ip(&headers, peer, state.config.trust_proxy);
    if !state
        .tracker
        .allow_room_create(ip, state.config.room_create_per_min)
    {
        return api_err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "room creation rate limit exceeded",
        );
    }
    let req: CreateRoomReq = if body.iter().all(|b| b.is_ascii_whitespace()) {
        CreateRoomReq::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(e) => {
                return api_err(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    format!("invalid JSON body: {e}"),
                );
            }
        }
    };
    let rules = match req.rules {
        None => Rules::Standard,
        Some(r) => match parse_rules(&r) {
            Some(rules) => rules,
            None => {
                return api_err(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    format!("unknown rules '{r}'; expected 'standard' or 'no-touch'"),
                );
            }
        },
    };
    match state.rooms.create_room(rules, false).await {
        Ok(info) => (StatusCode::CREATED, Json(info)).into_response(),
        Err(e) => map_room_err(e),
    }
}

pub async fn join_room(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
) -> impl IntoResponse {
    match state.rooms.join_room(&room_id).await {
        Ok(info) => (StatusCode::OK, Json(info)).into_response(),
        Err(e) => map_room_err(e),
    }
}

pub async fn get_room(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
) -> impl IntoResponse {
    match state.rooms.public_info(&room_id).await {
        Ok(info) => (StatusCode::OK, Json(info)).into_response(),
        Err(e) => map_room_err(e),
    }
}

pub async fn get_transcript(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
) -> impl IntoResponse {
    match state.rooms.public_transcript(&room_id).await {
        Ok(info) => (StatusCode::OK, Json(info)).into_response(),
        Err(e) => map_room_err(e),
    }
}

#[derive(Deserialize)]
pub struct VerifyTranscriptReq {
    pub hello_one: String,
    pub hello_two: String,
    pub frames: Vec<String>,
}

pub async fn verify_rate_limit(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&headers, peer, state.config.trust_proxy);
    if !state.tracker.allow_verify(ip, state.config.verify_per_min) {
        return api_err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "verify rate limit exceeded",
        );
    }
    next.run(request).await
}

#[derive(Serialize)]
struct SunkResp {
    ship: u8,
    length: u8,
    cells: Vec<u8>,
}

#[derive(Serialize)]
struct VerifyTranscriptResp {
    rules: String,
    params_id: String,
    sid: String,
    genesis_hash: String,
    role_a_key: String,
    role_b_key: String,
    first_mover: Option<String>,
    frames_verified: usize,
    shots_by_a: u8,
    shots_by_b: u8,
    hits_by_a: u8,
    hits_by_b: u8,
    sunk_on_a: Vec<SunkResp>,
    sunk_on_b: Vec<SunkResp>,
    verdict: String,
    winner: Option<String>,
    resigned: Option<String>,
    guilty: Option<String>,
    violation: Option<String>,
    violation_sequence: Option<u64>,
    violation_frame_hash: Option<String>,
    expected_next: Option<String>,
}

pub async fn verify_transcript(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let req: VerifyTranscriptReq = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            return api_err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                format!("invalid JSON body: {e}"),
            )
        }
    };
    if req.frames.len() > crate::room::MAX_TRANSCRIPT_FRAMES {
        return api_err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "too many frames in transcript",
        );
    }
    let Some(hello_one) = decode_hex(&req.hello_one) else {
        return api_err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "invalid hex in hello_one",
        );
    };
    let Some(hello_two) = decode_hex(&req.hello_two) else {
        return api_err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "invalid hex in hello_two",
        );
    };
    let mut frames = Vec::with_capacity(req.frames.len());
    for (idx, f_hex) in req.frames.iter().enumerate() {
        let Some(bytes) = decode_hex(f_hex) else {
            return api_err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                format!("invalid hex in frames[{idx}]"),
            );
        };
        frames.push(bytes);
    }

    let permit = match state.verifier_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return api_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_busy",
                "transcript verifier is at capacity; retry later",
            )
        }
    };
    let res = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify::verify_transcript(&hello_one, &hello_two, &frames)
    })
    .await;

    let report = match res {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return api_err(StatusCode::BAD_REQUEST, "invalid_transcript", e.to_string()),
        Err(_) => {
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "verifier task panicked",
            )
        }
    };

    let map_sunk = |flags: &[bool; K], cells: &[Option<Vec<zkb_core::params::CellIndex>>; K]| {
        (0..K)
            .filter(|&j| flags[j])
            .map(|j| SunkResp {
                ship: j as u8,
                length: FLEET_LENGTHS[j],
                cells: cells[j]
                    .as_ref()
                    .map(|cs| cs.iter().map(|c| c.index()).collect())
                    .unwrap_or_default(),
            })
            .collect()
    };

    let mut resp = VerifyTranscriptResp {
        rules: rules_name(report.rules).to_string(),
        params_id: hex(&report.params_id),
        sid: hex(&report.sid),
        genesis_hash: hex(&report.genesis_hash),
        role_a_key: report.role_a_key.fingerprint_hex(),
        role_b_key: report.role_b_key.fingerprint_hex(),
        first_mover: report.first_mover.map(|r| role_str(r).to_string()),
        frames_verified: report.frames_verified,
        shots_by_a: report.shots_by_a,
        shots_by_b: report.shots_by_b,
        hits_by_a: report.hits_by_a,
        hits_by_b: report.hits_by_b,
        sunk_on_a: map_sunk(&report.sunk_on_a, &report.sunk_cells_on_a),
        sunk_on_b: map_sunk(&report.sunk_on_b, &report.sunk_cells_on_b),
        verdict: String::new(),
        winner: None,
        resigned: None,
        guilty: None,
        violation: None,
        violation_sequence: None,
        violation_frame_hash: None,
        expected_next: None,
    };
    match report.verdict {
        TranscriptVerdict::Completed { winner } => {
            resp.verdict = "completed".to_string();
            resp.winner = Some(role_str(winner).to_string());
        }
        TranscriptVerdict::Resigned { winner, resigned } => {
            resp.verdict = "resigned".to_string();
            resp.winner = Some(role_str(winner).to_string());
            resp.resigned = Some(role_str(resigned).to_string());
        }
        TranscriptVerdict::AttributableViolation {
            guilty,
            sequence,
            frame_hash,
            violation,
        } => {
            resp.verdict = "attributable_violation".to_string();
            resp.guilty = Some(role_str(guilty).to_string());
            resp.violation = Some(violation.to_string());
            resp.violation_sequence = Some(sequence);
            resp.violation_frame_hash = Some(hex(&frame_hash));
        }
        TranscriptVerdict::Incomplete { expected_next } => {
            resp.verdict = "incomplete".to_string();
            resp.expected_next = Some(role_str(expected_next).to_string());
        }
    }
    (StatusCode::OK, Json(resp)).into_response()
}

// Re-export helpers to avoid unused warnings when building subsets.
#[allow(dead_code)]
fn _keep_types(_t: &IpTracker, _m: &RoomManager) {}
