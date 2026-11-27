use crate::config::RelayConfig;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, Mutex, Semaphore};
use zkb_core::game::Role;
use zkb_core::params::{Parameters, Rules};
use zkb_session::codec::MessageType;
use zkb_session::frame::{self, ChainExpectation, SignedFrame};
use zkb_session::hello::{self, CheckedHello, Hello};
use zkb_session::identity::{AuthenticatedPeer, PeerAuthPolicy, PeerKey};
use zkb_session::verify::{self, TranscriptVerdict};

pub use zkb_session::codec::{
    MAX_TRANSCRIPT_BYTES as MAX_ROOM_TRANSCRIPT_BYTES, MAX_TRANSCRIPT_FRAMES,
};
const ROOM_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

#[derive(Clone, Debug)]
pub enum RelayOutbound {
    Text(String),
    Binary(Vec<u8>),
    Close(&'static str),
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerEvent {
    RoomCreated {
        room_id: String,
        seat_token: String,
        seat: usize,
        rules: String,
        params_id: String,
    },
    RoomJoined {
        room_id: String,
        seat_token: String,
        seat: usize,
        rules: String,
        params_id: String,
        peer_present: bool,
    },
    Queued {
        room_id: String,
        seat_token: String,
        seat: usize,
        rules: String,
        params_id: String,
    },
    Matched {
        room_id: String,
        seat_token: String,
        seat: usize,
        rules: String,
        params_id: String,
    },
    Attached {
        room_id: String,
        seat: usize,
        rules: String,
        params_id: String,
        peer_present: bool,
        peer_connected: bool,
        own_hello_received: bool,
        peer_hello_received: bool,
        sid: Option<String>,
        genesis_hash: Option<String>,
        head_seq: u64,
        head_hash: Option<String>,
    },
    PeerJoined,
    PeerHelloAccepted {
        peer_public_key: String,
    },
    BootstrapReady {
        sid: String,
        genesis_hash: String,
        role_a_public_key: String,
        role_b_public_key: String,
        your_role: String,
    },
    FrameAck {
        seq: u64,
        frame_hash: String,
    },
    PeerDisconnected {
        grace_secs: u64,
    },
    PeerReconnected,
    RoomFinished {
        verdict: String,
        winner: Option<String>,
    },
    RoomClosed {
        reason: String,
        attributable: bool,
    },
    Error {
        code: String,
        message: String,
    },
    Pong,
}

impl ServerEvent {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("ServerEvent serialization cannot fail")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoomStatusKind {
    WaitingForPeer,
    Active,
    Finished,
}

#[derive(Clone, Debug)]
pub enum RoomOpError {
    NotFound,
    RoomFull,
    ServerFull,
    ServerBusy,
    Unauthorized,
    BadRequest(String),
    ClassB(String),
    TranscriptFull,
}

struct AnyValidKey;

impl PeerAuthPolicy for AnyValidKey {
    fn authenticate(&self, announced: &PeerKey) -> Option<AuthenticatedPeer> {
        Some(AuthenticatedPeer::from_policy_decision(*announced))
    }
}

struct Seat {
    token: [u8; 32],
    claimed: bool,
    hello: Option<Hello>,
    checked_hello: Option<CheckedHello>,
    auth_peer: Option<AuthenticatedPeer>,
    conn_id: u64,
    sender: Option<mpsc::Sender<RelayOutbound>>,
    disconnected_at: Option<Instant>,
}

impl Seat {
    fn new(token: [u8; 32], claimed: bool) -> Self {
        Self {
            token,
            claimed,
            hello: None,
            checked_hello: None,
            auth_peer: None,
            conn_id: 0,
            sender: None,
            disconnected_at: None,
        }
    }

    fn send_event(&self, event: &ServerEvent) {
        if let Some(tx) = &self.sender {
            let _ = tx.try_send(RelayOutbound::Text(event.to_json()));
        }
    }

    fn send_binary(&self, kind: u8, payload: &[u8]) {
        if let Some(tx) = &self.sender {
            let mut msg = Vec::with_capacity(1 + payload.len());
            msg.push(kind);
            msg.extend_from_slice(payload);
            let _ = tx.try_send(RelayOutbound::Binary(msg));
        }
    }
}

struct BootstrapInfo {
    sid: [u8; 32],
    genesis_hash: [u8; 32],
    role_a_key: PeerKey,
    role_b_key: PeerKey,
    seat_roles: [Role; 2],
    hello_a_bytes: Vec<u8>,
    hello_b_bytes: Vec<u8>,
}

struct Room {
    id: String,
    params: &'static Parameters,
    is_quick_match: bool,
    seats: [Seat; 2],
    bootstrap: Option<BootstrapInfo>,
    head_seq: u64,
    head_hash: [u8; 32],
    /// Stored as `(sender_seat_idx, raw_frame_bytes)` so reconnect catch-up
    /// only replays peer-authored frames past `after_seq`.
    frames: Vec<(usize, Vec<u8>)>,
    transcript_bytes: usize,
    created_at: Instant,
    last_activity: Instant,
    finished_at: Option<Instant>,
    finish_verdict: Option<(String, Option<String>)>,
}

impl Room {
    fn status(&self) -> RoomStatusKind {
        if self.finished_at.is_some() {
            RoomStatusKind::Finished
        } else if self.seats[1].claimed {
            RoomStatusKind::Active
        } else {
            RoomStatusKind::WaitingForPeer
        }
    }

    fn mark_finished(&mut self, verdict: String, winner: Option<String>) {
        if self.finished_at.is_none() {
            self.finished_at = Some(Instant::now());
            self.finish_verdict = Some((verdict, winner));
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RoomCreatedInfo {
    pub room_id: String,
    pub seat_token: String,
    pub seat: usize,
    pub rules: String,
    pub params_id: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RoomJoinedInfo {
    pub room_id: String,
    pub seat_token: String,
    pub seat: usize,
    pub rules: String,
    pub params_id: String,
    pub peer_present: bool,
    pub peer_hello_received: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RoomPublicInfo {
    pub room_id: String,
    pub status: String,
    pub rules: String,
    pub params_id: String,
    pub seats_claimed: usize,
    pub hellos_received: usize,
    pub sid: Option<String>,
    pub genesis_hash: Option<String>,
    pub frames_count: usize,
    pub transcript_bytes: usize,
    pub verdict: Option<String>,
    pub winner: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RoomTranscriptInfo {
    pub room_id: String,
    pub rules: String,
    pub params_id: String,
    pub hello_a: Option<String>,
    pub hello_b: Option<String>,
    pub sid: Option<String>,
    pub genesis_hash: Option<String>,
    pub frames: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct HealthStats {
    pub rooms: usize,
    pub quick_match_queued: usize,
    pub transcript_bytes: usize,
    pub max_transcript_bytes: usize,
}

pub struct AttachOutput {
    pub replace_old_sender: Option<mpsc::Sender<RelayOutbound>>,
}

#[derive(Default)]
struct ManagerInner {
    rooms: HashMap<String, Room>,
    quick_queue_standard: VecDeque<String>,
    quick_queue_notouch: VecDeque<String>,
    next_conn_id: u64,
    transcript_bytes: usize,
}

impl ManagerInner {
    fn queue_mut(&mut self, rules: Rules) -> &mut VecDeque<String> {
        match rules {
            Rules::Standard => &mut self.quick_queue_standard,
            Rules::NoTouch => &mut self.quick_queue_notouch,
        }
    }
}

pub struct RoomManager {
    config: Arc<RelayConfig>,
    inner: Mutex<ManagerInner>,
    verifier_slots: Arc<Semaphore>,
}

impl RoomManager {
    pub fn new(config: Arc<RelayConfig>) -> Self {
        let slots = Arc::new(Semaphore::new(config.max_concurrent_verifications));
        Self::with_verifier_slots(config, slots)
    }

    pub fn with_verifier_slots(config: Arc<RelayConfig>, verifier_slots: Arc<Semaphore>) -> Self {
        Self {
            config,
            inner: Mutex::new(ManagerInner::default()),
            verifier_slots,
        }
    }

    pub fn spawn_reaper(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                mgr.reap_expired().await;
            }
        })
    }

    pub async fn health_stats(&self) -> HealthStats {
        let inner = self.inner.lock().await;
        HealthStats {
            rooms: inner.rooms.len(),
            quick_match_queued: inner.quick_queue_standard.len() + inner.quick_queue_notouch.len(),
            transcript_bytes: inner.transcript_bytes,
            max_transcript_bytes: self.config.max_transcript_bytes,
        }
    }

    pub async fn create_room(
        &self,
        rules: Rules,
        is_quick_match: bool,
    ) -> Result<RoomCreatedInfo, RoomOpError> {
        let mut inner = self.inner.lock().await;
        if inner.rooms.len() >= self.config.max_rooms {
            return Err(RoomOpError::ServerFull);
        }
        let room_id = loop {
            let candidate = random_room_code();
            if !inner.rooms.contains_key(&candidate) {
                break candidate;
            }
        };
        let mut tok0 = [0u8; 32];
        let mut tok1 = [0u8; 32];
        OsRng.fill_bytes(&mut tok0);
        OsRng.fill_bytes(&mut tok1);
        let now = Instant::now();
        let params = Parameters::for_rules(rules);
        let room = Room {
            id: room_id.clone(),
            params,
            is_quick_match,
            seats: [Seat::new(tok0, true), Seat::new(tok1, false)],
            bootstrap: None,
            head_seq: 0,
            head_hash: [0u8; 32],
            frames: Vec::new(),
            transcript_bytes: 0,
            created_at: now,
            last_activity: now,
            finished_at: None,
            finish_verdict: None,
        };
        inner.rooms.insert(room_id.clone(), room);
        if is_quick_match {
            inner.queue_mut(rules).push_back(room_id.clone());
        }
        Ok(RoomCreatedInfo {
            room_id,
            seat_token: hex(&tok0),
            seat: 0,
            rules: rules_name(rules).to_string(),
            params_id: hex(params.params_id()),
        })
    }

    pub async fn join_room(&self, room_id: &str) -> Result<RoomJoinedInfo, RoomOpError> {
        let mut inner = self.inner.lock().await;
        let room = inner.rooms.get_mut(room_id).ok_or(RoomOpError::NotFound)?;
        if room.finished_at.is_some() || room.seats[1].claimed {
            return Err(RoomOpError::RoomFull);
        }
        room.seats[1].claimed = true;
        room.last_activity = Instant::now();
        let peer_hello_received = room.seats[0].hello.is_some();
        room.seats[0].send_event(&ServerEvent::PeerJoined);
        Ok(RoomJoinedInfo {
            room_id: room.id.clone(),
            seat_token: hex(&room.seats[1].token),
            seat: 1,
            rules: rules_name(room.params.rules()).to_string(),
            params_id: hex(room.params.params_id()),
            peer_present: true,
            peer_hello_received,
        })
    }

    pub async fn quick_match(&self, rules: Rules) -> Result<(bool, RoomJoinedInfo), RoomOpError> {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        while let Some(candidate) = inner.queue_mut(rules).pop_front() {
            let can_join = inner.rooms.get(&candidate).is_some_and(|r| {
                r.is_quick_match
                    && r.finished_at.is_none()
                    && !r.seats[1].claimed
                    && now.duration_since(r.created_at) < self.config.waiting_ttl
            });
            if can_join {
                let room = inner.rooms.get_mut(&candidate).expect("checked");
                room.seats[1].claimed = true;
                room.last_activity = now;
                let peer_hello_received = room.seats[0].hello.is_some();
                room.seats[0].send_event(&ServerEvent::PeerJoined);
                return Ok((
                    true,
                    RoomJoinedInfo {
                        room_id: room.id.clone(),
                        seat_token: hex(&room.seats[1].token),
                        seat: 1,
                        rules: rules_name(room.params.rules()).to_string(),
                        params_id: hex(room.params.params_id()),
                        peer_present: true,
                        peer_hello_received,
                    },
                ));
            }
        }
        drop(inner);
        let created = self.create_room(rules, true).await?;
        Ok((
            false,
            RoomJoinedInfo {
                room_id: created.room_id,
                seat_token: created.seat_token,
                seat: created.seat,
                rules: created.rules,
                params_id: created.params_id,
                peer_present: false,
                peer_hello_received: false,
            },
        ))
    }

    pub async fn attach(
        &self,
        room_id: &str,
        seat_token_hex: &str,
        after_seq: u64,
        tx: mpsc::Sender<RelayOutbound>,
    ) -> Result<(usize, u64, AttachOutput), RoomOpError> {
        let token = decode_hex_32(seat_token_hex).ok_or(RoomOpError::Unauthorized)?;
        let mut inner = self.inner.lock().await;
        inner.next_conn_id += 1;
        let conn_id = inner.next_conn_id;

        let room = inner.rooms.get_mut(room_id).ok_or(RoomOpError::NotFound)?;
        let seat_idx = identify_seat(room, &token).ok_or(RoomOpError::Unauthorized)?;
        let peer_idx = 1 - seat_idx;
        let was_disconnected = room.seats[seat_idx].disconnected_at.is_some();

        let peer_present = room.seats[peer_idx].claimed;
        let peer_connected = room.seats[peer_idx].sender.is_some();
        let own_hello_received = room.seats[seat_idx].hello.is_some();
        let peer_hello_received = room.seats[peer_idx].hello.is_some();
        let peer_hello = room.seats[peer_idx].hello.as_ref().map(Hello::encode);

        let start = (after_seq as usize).min(room.frames.len());
        let replay_frames: Vec<Vec<u8>> = room.frames[start..]
            .iter()
            .filter(|(sender, _)| *sender != seat_idx)
            .map(|(_, bytes)| bytes.clone())
            .collect();

        let (sid, genesis_hash, head_hash) = if let Some(b) = &room.bootstrap {
            (
                Some(hex(&b.sid)),
                Some(hex(&b.genesis_hash)),
                Some(hex(&room.head_hash)),
            )
        } else {
            (None, None, None)
        };

        let attached_event = ServerEvent::Attached {
            room_id: room.id.clone(),
            seat: seat_idx,
            rules: rules_name(room.params.rules()).to_string(),
            params_id: hex(room.params.params_id()),
            peer_present,
            peer_connected,
            own_hello_received,
            peer_hello_received,
            sid,
            genesis_hash,
            head_seq: room.head_seq,
            head_hash,
        };

        // Queue the complete reconnect prefix before publishing this sender to
        // the room. Otherwise a peer can append a live frame after the room
        // lock is released but before the caller queues replay_frames, causing
        // the new socket to observe the chain out of order.
        let needed = 1 + usize::from(peer_hello.is_some()) + replay_frames.len();
        if tx.capacity() < needed {
            return Err(RoomOpError::BadRequest(
                "connection outbox is too small for reconnect catch-up".to_string(),
            ));
        }
        tx.try_send(RelayOutbound::Text(attached_event.to_json()))
            .map_err(|_| RoomOpError::BadRequest("connection outbox is unavailable".to_string()))?;
        if let Some(raw) = peer_hello {
            let mut msg = Vec::with_capacity(1 + raw.len());
            msg.push(0x01);
            msg.extend_from_slice(&raw);
            tx.try_send(RelayOutbound::Binary(msg)).map_err(|_| {
                RoomOpError::BadRequest("connection outbox is unavailable".to_string())
            })?;
        }
        for raw in replay_frames {
            let mut msg = Vec::with_capacity(1 + raw.len());
            msg.push(0x02);
            msg.extend_from_slice(&raw);
            tx.try_send(RelayOutbound::Binary(msg)).map_err(|_| {
                RoomOpError::BadRequest("connection outbox is unavailable".to_string())
            })?;
        }

        let old_sender = room.seats[seat_idx].sender.replace(tx);
        room.seats[seat_idx].conn_id = conn_id;
        room.seats[seat_idx].disconnected_at = None;
        room.last_activity = Instant::now();

        if was_disconnected {
            room.seats[peer_idx].send_event(&ServerEvent::PeerReconnected);
        }

        Ok((
            seat_idx,
            conn_id,
            AttachOutput {
                replace_old_sender: old_sender,
            },
        ))
    }

    pub async fn detach(&self, room_id: &str, seat_idx: usize, conn_id: u64) {
        let mut inner = self.inner.lock().await;
        let Some(room) = inner.rooms.get_mut(room_id) else {
            return;
        };
        if room.seats[seat_idx].conn_id != conn_id {
            return;
        }
        room.seats[seat_idx].sender = None;
        if room.finished_at.is_none() {
            room.seats[seat_idx].disconnected_at = Some(Instant::now());
            room.seats[1 - seat_idx].send_event(&ServerEvent::PeerDisconnected {
                grace_secs: self.config.reconnect_grace.as_secs(),
            });
        }
    }

    pub async fn submit_hello(
        &self,
        room_id: &str,
        seat_idx: usize,
        raw: &[u8],
    ) -> Result<(), RoomOpError> {
        let mut inner = self.inner.lock().await;
        let room = inner.rooms.get_mut(room_id).ok_or(RoomOpError::NotFound)?;
        let params_id = *room.params.params_id();
        let hello = Hello::decode(raw)
            .map_err(|e| RoomOpError::BadRequest(format!("invalid Hello: {e}")))?;
        let checked = hello::check_hello(hello.clone(), &params_id, &AnyValidKey)
            .map_err(|e| RoomOpError::BadRequest(format!("hello rejected: {e}")))?;

        if let Some(existing) = &room.seats[seat_idx].hello {
            if existing.encode() == raw {
                return Ok(());
            }
            return Err(RoomOpError::BadRequest(
                "conflicting Hello for this seat".to_string(),
            ));
        }

        let peer_idx = 1 - seat_idx;
        if let Some(peer_checked) = &room.seats[peer_idx].checked_hello {
            if peer_checked.key() == checked.key() {
                return Err(RoomOpError::BadRequest(
                    "peer already registered the same identity key".to_string(),
                ));
            }
        }

        let pk_hex = checked.key().fingerprint_hex();
        let auth_peer = *checked.authenticated_peer();
        room.seats[seat_idx].hello = Some(hello);
        room.seats[seat_idx].checked_hello = Some(checked);
        room.seats[seat_idx].auth_peer = Some(auth_peer);
        room.last_activity = Instant::now();

        room.seats[peer_idx].send_event(&ServerEvent::PeerHelloAccepted {
            peer_public_key: pk_hex,
        });
        room.seats[peer_idx].send_binary(0x01, raw);

        if room.bootstrap.is_none()
            && room.seats[0].checked_hello.is_some()
            && room.seats[1].checked_hello.is_some()
        {
            let c0 = room.seats[0].checked_hello.clone().expect("checked");
            let c1 = room.seats[1].checked_hello.clone().expect("checked");
            let bootstrap = hello::complete_bootstrap(c0, c1)
                .map_err(|e| RoomOpError::BadRequest(format!("bootstrap failed: {e}")))?;
            let sid = *bootstrap.sid();
            let genesis_hash = *bootstrap.genesis_hash();
            let role0 = bootstrap.role_of(room.seats[0].hello.as_ref().unwrap().key());
            let role1 = role0.other();
            let info = BootstrapInfo {
                sid,
                genesis_hash,
                role_a_key: *bootstrap.hello_a().key(),
                role_b_key: *bootstrap.hello_b().key(),
                seat_roles: [role0, role1],
                hello_a_bytes: bootstrap.hello_a().encode(),
                hello_b_bytes: bootstrap.hello_b().encode(),
            };
            room.head_hash = genesis_hash;
            room.head_seq = 0;
            for seat in 0..2 {
                room.seats[seat].send_event(&ServerEvent::BootstrapReady {
                    sid: hex(&info.sid),
                    genesis_hash: hex(&info.genesis_hash),
                    role_a_public_key: info.role_a_key.fingerprint_hex(),
                    role_b_public_key: info.role_b_key.fingerprint_hex(),
                    your_role: role_str(info.seat_roles[seat]).to_string(),
                });
            }
            room.bootstrap = Some(info);
        }
        Ok(())
    }

    pub async fn submit_frame(
        &self,
        room_id: &str,
        seat_idx: usize,
        raw: &[u8],
    ) -> Result<(u64, String), RoomOpError> {
        let mut inner = self.inner.lock().await;
        let total_transcript_bytes = inner.transcript_bytes;
        let room = inner.rooms.get_mut(room_id).ok_or(RoomOpError::NotFound)?;
        let frame = SignedFrame::decode(raw)
            .map_err(|e| RoomOpError::ClassB(format!("malformed frame: {e}")))?;

        let seq = frame.header().sequence;
        if seq >= 1 && (seq as usize) <= room.frames.len() {
            let (_, existing) = &room.frames[(seq as usize) - 1];
            if existing.as_slice() == raw {
                return Ok((seq, hex(&frame::frame_hash(raw))));
            }
            return Err(RoomOpError::BadRequest(format!(
                "conflicting frame at already-committed sequence {seq}"
            )));
        }

        if room.finished_at.is_some() {
            return Err(RoomOpError::RoomFull);
        }

        let Some(bootstrap) = &room.bootstrap else {
            return Err(RoomOpError::BadRequest(
                "bootstrap is not complete yet".to_string(),
            ));
        };

        if room.frames.len() >= MAX_TRANSCRIPT_FRAMES {
            return Err(RoomOpError::TranscriptFull);
        }

        let expectation = ChainExpectation {
            sid: bootstrap.sid,
            sequence: room.head_seq + 1,
            prev_hash: room.head_hash,
        };
        let auth_peer = room.seats[seat_idx]
            .auth_peer
            .as_ref()
            .ok_or_else(|| RoomOpError::BadRequest("seat hello missing".to_string()))?;
        let authenticated = frame
            .authenticate(&expectation, auth_peer)
            .map_err(|e| RoomOpError::ClassB(e.to_string()))?;

        let fhash = authenticated.frame().frame_hash();
        let is_resign = authenticated.frame().header().message_type == MessageType::Resign;
        let (new_room_bytes, new_total_bytes) = next_transcript_sizes(
            room.transcript_bytes,
            total_transcript_bytes,
            raw.len(),
            self.config.max_transcript_bytes,
        )?;

        room.head_seq += 1;
        room.head_hash = fhash;
        room.frames.push((seat_idx, raw.to_vec()));
        room.transcript_bytes = new_room_bytes;
        room.last_activity = Instant::now();

        let peer_idx = 1 - seat_idx;
        room.seats[peer_idx].send_binary(0x02, raw);

        if is_resign {
            room.mark_finished("resign_relayed".to_string(), None);
        }

        let head_seq = room.head_seq;
        inner.transcript_bytes = new_total_bytes;
        Ok((head_seq, hex(&fhash)))
    }

    pub async fn claim_finished(
        &self,
        room_id: &str,
    ) -> Result<(String, Option<String>), RoomOpError> {
        let (hello_a, hello_b, frames) = {
            let inner = self.inner.lock().await;
            let room = inner.rooms.get(room_id).ok_or(RoomOpError::NotFound)?;
            if let Some((verdict, winner)) = &room.finish_verdict {
                if verdict == "completed" || verdict == "resigned" {
                    return Ok((verdict.clone(), winner.clone()));
                }
            }
            let Some(b) = &room.bootstrap else {
                return Err(RoomOpError::BadRequest(
                    "bootstrap is not complete".to_string(),
                ));
            };
            let frames: Vec<Vec<u8>> = room.frames.iter().map(|(_, f)| f.clone()).collect();
            (b.hello_a_bytes.clone(), b.hello_b_bytes.clone(), frames)
        };

        let permit = self
            .verifier_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| RoomOpError::ServerBusy)?;
        let report = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verify::verify_transcript(&hello_a, &hello_b, &frames)
        })
        .await
        .map_err(|_| RoomOpError::BadRequest("verifier task failed".to_string()))?
        .map_err(|e| RoomOpError::BadRequest(format!("transcript verification failed: {e}")))?;

        let (verdict, winner) = match report.verdict {
            TranscriptVerdict::Completed { winner } => {
                ("completed".to_string(), Some(role_str(winner).to_string()))
            }
            TranscriptVerdict::Resigned { winner, .. } => {
                ("resigned".to_string(), Some(role_str(winner).to_string()))
            }
            TranscriptVerdict::AttributableViolation { guilty, .. } => (
                "attributable_violation".to_string(),
                Some(role_str(guilty.other()).to_string()),
            ),
            TranscriptVerdict::Incomplete { .. } => {
                return Err(RoomOpError::BadRequest(
                    "transcript is still incomplete".to_string(),
                ));
            }
        };

        let mut inner = self.inner.lock().await;
        if let Some(room) = inner.rooms.get_mut(room_id) {
            room.mark_finished(verdict.clone(), winner.clone());
            let event = ServerEvent::RoomFinished {
                verdict: verdict.clone(),
                winner: winner.clone(),
            };
            room.seats[0].send_event(&event);
            room.seats[1].send_event(&event);
        }
        Ok((verdict, winner))
    }

    pub async fn public_info(&self, room_id: &str) -> Result<RoomPublicInfo, RoomOpError> {
        let inner = self.inner.lock().await;
        let room = inner.rooms.get(room_id).ok_or(RoomOpError::NotFound)?;
        let status = match room.status() {
            RoomStatusKind::WaitingForPeer => "waiting_for_peer",
            RoomStatusKind::Active => "active",
            RoomStatusKind::Finished => "finished",
        };
        Ok(RoomPublicInfo {
            room_id: room.id.clone(),
            status: status.to_string(),
            rules: rules_name(room.params.rules()).to_string(),
            params_id: hex(room.params.params_id()),
            seats_claimed: usize::from(room.seats[0].claimed) + usize::from(room.seats[1].claimed),
            hellos_received: usize::from(room.seats[0].hello.is_some())
                + usize::from(room.seats[1].hello.is_some()),
            sid: room.bootstrap.as_ref().map(|b| hex(&b.sid)),
            genesis_hash: room.bootstrap.as_ref().map(|b| hex(&b.genesis_hash)),
            frames_count: room.frames.len(),
            transcript_bytes: room.transcript_bytes,
            verdict: room.finish_verdict.as_ref().map(|(v, _)| v.clone()),
            winner: room.finish_verdict.as_ref().and_then(|(_, w)| w.clone()),
        })
    }

    pub async fn public_transcript(
        &self,
        room_id: &str,
    ) -> Result<RoomTranscriptInfo, RoomOpError> {
        let inner = self.inner.lock().await;
        let room = inner.rooms.get(room_id).ok_or(RoomOpError::NotFound)?;
        let (hello_a, hello_b, sid, genesis_hash) = if let Some(b) = &room.bootstrap {
            (
                Some(hex(&b.hello_a_bytes)),
                Some(hex(&b.hello_b_bytes)),
                Some(hex(&b.sid)),
                Some(hex(&b.genesis_hash)),
            )
        } else {
            (None, None, None, None)
        };
        Ok(RoomTranscriptInfo {
            room_id: room.id.clone(),
            rules: rules_name(room.params.rules()).to_string(),
            params_id: hex(room.params.params_id()),
            hello_a,
            hello_b,
            sid,
            genesis_hash,
            frames: room.frames.iter().map(|(_, f)| hex(f)).collect(),
        })
    }

    pub async fn reap_expired(&self) {
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        let mut remove_ids: Vec<(String, Option<&'static str>)> = Vec::new();
        for (id, room) in &inner.rooms {
            if let Some(finished_at) = room.finished_at {
                if now.duration_since(finished_at) >= self.config.finished_ttl {
                    remove_ids.push((id.clone(), None));
                }
                continue;
            }
            if !room.seats[1].claimed {
                if now.duration_since(room.created_at) >= self.config.waiting_ttl {
                    remove_ids.push((id.clone(), Some("waiting_timeout")));
                }
                continue;
            }
            let disc_expired = room.seats.iter().any(|s| {
                s.disconnected_at
                    .is_some_and(|t| now.duration_since(t) >= self.config.reconnect_grace)
            });
            if disc_expired {
                remove_ids.push((id.clone(), Some("reconnect_timeout")));
                continue;
            }
            if now.duration_since(room.last_activity) >= self.config.turn_timeout {
                remove_ids.push((id.clone(), Some("turn_timeout")));
            }
        }
        for (id, close_reason) in remove_ids {
            if let Some(room) = inner.rooms.remove(&id) {
                inner.transcript_bytes =
                    inner.transcript_bytes.saturating_sub(room.transcript_bytes);
                if let Some(reason) = close_reason {
                    let event = ServerEvent::RoomClosed {
                        reason: reason.to_string(),
                        attributable: false,
                    };
                    room.seats[0].send_event(&event);
                    room.seats[1].send_event(&event);
                    for s in &room.seats {
                        if let Some(tx) = &s.sender {
                            let _ = tx.try_send(RelayOutbound::Close(reason));
                        }
                    }
                }
            }
        }
        let state = &mut *inner;
        let rooms = &state.rooms;
        state
            .quick_queue_standard
            .retain(|id| rooms.contains_key(id));
        state
            .quick_queue_notouch
            .retain(|id| rooms.contains_key(id));
    }
}

fn next_transcript_sizes(
    room_bytes: usize,
    total_bytes: usize,
    frame_bytes: usize,
    max_total_bytes: usize,
) -> Result<(usize, usize), RoomOpError> {
    let new_room_bytes = room_bytes
        .checked_add(frame_bytes)
        .ok_or(RoomOpError::TranscriptFull)?;
    if new_room_bytes > MAX_ROOM_TRANSCRIPT_BYTES {
        return Err(RoomOpError::TranscriptFull);
    }
    let new_total_bytes = total_bytes
        .checked_add(frame_bytes)
        .ok_or(RoomOpError::ServerFull)?;
    if new_total_bytes > max_total_bytes {
        return Err(RoomOpError::ServerFull);
    }
    Ok((new_room_bytes, new_total_bytes))
}

fn identify_seat(room: &Room, token: &[u8; 32]) -> Option<usize> {
    if bool::from(room.seats[0].token.ct_eq(token)) {
        Some(0)
    } else if room.seats[1].claimed && bool::from(room.seats[1].token.ct_eq(token)) {
        Some(1)
    } else {
        None
    }
}

fn random_room_code() -> String {
    let mut raw = [0u8; 10];
    OsRng.fill_bytes(&mut raw);
    raw.iter()
        .map(|b| ROOM_ALPHABET[usize::from(*b & 0x1f)] as char)
        .collect()
}

pub fn rules_name(rules: Rules) -> &'static str {
    match rules {
        Rules::Standard => "standard",
        Rules::NoTouch => "no-touch",
    }
}

pub fn parse_rules(s: &str) -> Option<Rules> {
    match s {
        "standard" => Some(Rules::Standard),
        "no-touch" => Some(Rules::NoTouch),
        _ => None,
    }
}

pub fn role_str(role: Role) -> &'static str {
    match role {
        Role::A => "A",
        Role::B => "B",
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..s.len() / 2 {
        out.push(u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?);
    }
    Some(out)
}

pub fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    decode_hex(s)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkb_session::identity::IdentityKeypair;

    #[test]
    fn transcript_byte_budgets_reject_room_global_and_integer_overflow() {
        assert!(matches!(
            next_transcript_sizes(MAX_ROOM_TRANSCRIPT_BYTES - 1, 9, 1, 10),
            Ok((MAX_ROOM_TRANSCRIPT_BYTES, 10))
        ));
        assert!(matches!(
            next_transcript_sizes(MAX_ROOM_TRANSCRIPT_BYTES, 0, 1, usize::MAX),
            Err(RoomOpError::TranscriptFull)
        ));
        assert!(matches!(
            next_transcript_sizes(0, 10, 1, 10),
            Err(RoomOpError::ServerFull)
        ));
        assert!(matches!(
            next_transcript_sizes(0, usize::MAX, 1, usize::MAX),
            Err(RoomOpError::ServerFull)
        ));
    }

    #[tokio::test]
    async fn reaping_a_room_releases_its_transcript_budget() {
        let config = RelayConfig {
            finished_ttl: std::time::Duration::ZERO,
            ..RelayConfig::default()
        };
        let manager = RoomManager::new(Arc::new(config));
        let created = manager.create_room(Rules::Standard, false).await.unwrap();
        {
            let mut inner = manager.inner.lock().await;
            let room = inner.rooms.get_mut(&created.room_id).unwrap();
            room.transcript_bytes = 123;
            room.mark_finished("test".to_string(), None);
            inner.transcript_bytes = 123;
        }

        manager.reap_expired().await;
        let stats = manager.health_stats().await;
        assert_eq!(stats.rooms, 0);
        assert_eq!(stats.transcript_bytes, 0);
    }

    #[tokio::test]
    async fn attach_queues_reconnect_prefix_before_publishing_sender() {
        let manager = RoomManager::new(Arc::new(RelayConfig::default()));
        let created = manager.create_room(Rules::Standard, false).await.unwrap();
        manager.join_room(&created.room_id).await.unwrap();

        {
            let mut inner = manager.inner.lock().await;
            let room = inner.rooms.get_mut(&created.room_id).unwrap();
            room.frames.push((1, vec![0x11]));
            room.frames.push((0, vec![0x22]));
            room.frames.push((1, vec![0x33]));
            room.head_seq = 3;
        }

        let (tx, mut rx) = mpsc::channel(8);
        manager
            .attach(&created.room_id, &created.seat_token, 0, tx)
            .await
            .unwrap();

        assert!(matches!(rx.try_recv(), Ok(RelayOutbound::Text(_))));
        assert!(matches!(
            rx.try_recv(),
            Ok(RelayOutbound::Binary(bytes)) if bytes == [0x02, 0x11]
        ));
        assert!(matches!(
            rx.try_recv(),
            Ok(RelayOutbound::Binary(bytes)) if bytes == [0x02, 0x33]
        ));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn finished_room_rejects_new_frames_but_allows_final_frame_retry() {
        let manager = RoomManager::new(Arc::new(RelayConfig::default()));
        let created = manager.create_room(Rules::Standard, false).await.unwrap();
        let key = IdentityKeypair::from_seed(&[7; 32]);
        let final_frame = SignedFrame::craft(
            &key,
            &[1; 32],
            Role::A,
            1,
            MessageType::Resign,
            &[2; 32],
            Vec::new(),
        );
        let later_frame = SignedFrame::craft(
            &key,
            &[1; 32],
            Role::B,
            2,
            MessageType::Resign,
            &frame::frame_hash(final_frame.bytes()),
            Vec::new(),
        );

        {
            let mut inner = manager.inner.lock().await;
            let room = inner.rooms.get_mut(&created.room_id).unwrap();
            room.frames.push((0, final_frame.bytes().to_vec()));
            room.head_seq = 1;
            room.head_hash = frame::frame_hash(final_frame.bytes());
            room.mark_finished("resign_relayed".to_string(), None);
        }

        let retry = manager
            .submit_frame(&created.room_id, 0, final_frame.bytes())
            .await
            .unwrap();
        assert_eq!(retry.0, 1);
        assert!(matches!(
            manager
                .submit_frame(&created.room_id, 0, later_frame.bytes())
                .await,
            Err(RoomOpError::RoomFull)
        ));
    }
}
