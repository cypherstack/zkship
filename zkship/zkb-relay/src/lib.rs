pub mod config;
pub mod http;
pub mod rate;
pub mod room;
pub mod ws;

use axum::http::{header, HeaderValue, Method};
use axum::routing::{get, post};
use axum::Router;
use config::RelayConfig;
use rate::IpTracker;
use room::RoomManager;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RelayConfig>,
    pub rooms: Arc<RoomManager>,
    pub tracker: IpTracker,
    pub verifier_slots: Arc<Semaphore>,
}

impl AppState {
    pub fn new(config: RelayConfig) -> Self {
        let config = Arc::new(config);
        let verifier_slots = Arc::new(Semaphore::new(config.max_concurrent_verifications));
        let rooms = Arc::new(RoomManager::with_verifier_slots(
            config.clone(),
            verifier_slots.clone(),
        ));
        Self {
            config,
            rooms,
            tracker: IpTracker::default(),
            verifier_slots,
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    let cors = build_cors(&state.config);
    let verify_route = Router::new()
        .route("/api/v1/verify-transcript", post(http::verify_transcript))
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            http::verify_rate_limit,
        ));

    let api_routes = Router::new()
        .route("/healthz", get(http::healthz))
        .route("/api/v1/params", get(http::params))
        .route("/api/v1/rooms", post(http::create_room))
        .route("/api/v1/rooms/{room_id}", get(http::get_room))
        .route("/api/v1/rooms/{room_id}/join", post(http::join_room))
        .route(
            "/api/v1/rooms/{room_id}/transcript",
            get(http::get_transcript),
        )
        .layer(RequestBodyLimitLayer::new(64 * 1024));

    Router::new()
        .merge(api_routes)
        .merge(verify_route)
        .route("/ws", get(ws::ws_handler))
        .layer(cors)
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .with_state(state)
}

fn build_cors(cfg: &RelayConfig) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE]);
    if cfg.allow_all_origins() {
        base.allow_origin(AllowOrigin::any())
    } else {
        let origins: Vec<HeaderValue> = cfg
            .allowed_origins
            .iter()
            .filter_map(|s| HeaderValue::from_str(s).ok())
            .collect();
        base.allow_origin(origins)
    }
}
