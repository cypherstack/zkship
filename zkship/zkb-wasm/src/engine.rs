//! Pure-Rust stateful client engine for web and worker runtimes.
//!
//! Handles the full protocol lifecycle (`Hello`, `Session::from_bootstrap_owned`,
//! automatic draining of `Session::produce` including A's `CoinReveal` right after
//! `CoinNonce`, board views, snapshot export/restore, and typed Class A/B/C/D errors)
//! so JavaScript callers only shuttle bytes.

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};
use zkb_core::fleet::{Fleet, ShipPlacement, SHIP_BITS};
use zkb_core::game::{Role, ShotOutcome, State as GameState};
use zkb_core::params::{CellIndex, Parameters, Rules, BOARD_N, FLEET_LENGTHS, K, N, T};
use zkb_session::codec::MessageType;
use zkb_session::frame::{self, SignedFrame};
use zkb_session::hello::{self, CheckedHello, Hello};
use zkb_session::identity::{
    AuthenticatedPeer, ExpectedKey, IdentityKeypair, PeerAuthPolicy, PeerKey,
};
use zkb_session::state::{AcceptOutcome, PhaseKind, Session, SessionError};
use zkb_session::verify::{self, TranscriptVerdict};

const CLIENT_SNAPSHOT_MAGIC: &[u8; 8] = b"ZKBWC01\0";

mod bytes_serde {
    use serde::ser::{Serialize, SerializeSeq, Serializer};

    struct BytesRef<'a>(&'a [u8]);

    impl Serialize for BytesRef<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.0)
        }
    }

    pub fn serialize_opt<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => serializer.serialize_some(&BytesRef(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn serialize_vec<S: Serializer>(
        values: &[Vec<u8>],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(values.len()))?;
        for bytes in values {
            seq.serialize_element(&BytesRef(bytes))?;
        }
        seq.end()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShipDto {
    pub row: u8,
    pub col: u8,
    pub vertical: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientErrorDto {
    /// One of: `invalid_input`, `wrong_state`, `peer_auth`, `class_b`, `attributable`, `internal`.
    pub kind: String,
    pub message: String,
    #[serde(serialize_with = "bytes_serde::serialize_opt")]
    pub evidence_frame: Option<Vec<u8>>,
    pub evidence_frame_hash: Option<String>,
}

impl ClientErrorDto {
    fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.into(),
            evidence_frame: None,
            evidence_frame_hash: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolInfoDto {
    pub board_n: usize,
    pub cells: usize,
    pub ship_lengths: Vec<u8>,
    pub total_ship_cells: usize,
    pub standard_params_id: String,
    pub no_touch_params_id: String,
    pub hello_len: usize,
    pub max_frame_size: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SunkShipDto {
    pub ship: u8,
    pub length: u8,
    pub cells: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapResultDto {
    pub local_role: String,
    pub sid: String,
    pub genesis_hash: String,
    pub safety_code: String,
    pub peer_public_key: String,
    pub peer_fingerprint: String,
    #[serde(serialize_with = "bytes_serde::serialize_vec")]
    pub outgoing_frames: Vec<Vec<u8>>,
    pub state: ClientStateDto,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepResultDto {
    pub event: String,
    #[serde(serialize_with = "bytes_serde::serialize_vec")]
    pub outgoing_frames: Vec<Vec<u8>>,
    pub first_mover: Option<String>,
    pub cell: Option<u8>,
    pub outcome: Option<String>,
    pub sunk_ship: Option<u8>,
    pub winner: Option<String>,
    pub state: ClientStateDto,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientStateDto {
    pub phase: String,
    pub rules: String,
    pub params_id: String,
    pub own_public_key: String,
    pub own_fingerprint: String,
    pub peer_public_key: Option<String>,
    pub peer_fingerprint: Option<String>,
    pub safety_code: Option<String>,
    pub sid: Option<String>,
    pub genesis_hash: Option<String>,
    pub local_role: Option<String>,
    pub first_mover: Option<String>,
    pub expected_sender: Option<String>,
    pub your_turn: bool,
    pub can_fire_shot: bool,
    pub can_resign: bool,
    pub head_sequence: u64,
    pub head_hash: Option<String>,
    pub winner: Option<String>,
    pub finish_reason: Option<String>,
    pub verified_hits: u8,
    pub hits_conceded: u8,
    /// Per-cell view of own board: `"water"`, `"ship"`, `"miss"`, `"hit"`, `"sunk"`.
    pub my_board: Vec<String>,
    /// Per-cell view of opponent board: `"unknown"`, `"miss"`, `"hit"`, `"sunk"`.
    pub opponent_board: Vec<String>,
    pub my_sunk_ships: Vec<SunkShipDto>,
    pub opponent_sunk_ships: Vec<SunkShipDto>,
    #[serde(serialize_with = "bytes_serde::serialize_opt")]
    pub evidence_frame: Option<Vec<u8>>,
    pub evidence_frame_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptDto {
    pub rules: String,
    pub params_id: String,
    #[serde(serialize_with = "bytes_serde::serialize_opt")]
    pub hello_a: Option<Vec<u8>>,
    #[serde(serialize_with = "bytes_serde::serialize_opt")]
    pub hello_b: Option<Vec<u8>>,
    pub sid: Option<String>,
    pub genesis_hash: Option<String>,
    #[serde(serialize_with = "bytes_serde::serialize_vec")]
    pub frames: Vec<Vec<u8>>,
    #[serde(serialize_with = "bytes_serde::serialize_opt")]
    pub evidence_frame: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReportDto {
    pub rules: String,
    pub params_id: String,
    pub sid: String,
    pub genesis_hash: String,
    pub role_a_key: String,
    pub role_b_key: String,
    pub first_mover: Option<String>,
    pub frames_verified: usize,
    pub shots_by_a: u8,
    pub shots_by_b: u8,
    pub hits_by_a: u8,
    pub hits_by_b: u8,
    pub sunk_on_a: Vec<SunkShipDto>,
    pub sunk_on_b: Vec<SunkShipDto>,
    pub verdict: String,
    pub winner: Option<String>,
    pub resigned: Option<String>,
    pub guilty: Option<String>,
    pub violation: Option<String>,
    pub violation_sequence: Option<u64>,
    pub violation_frame_hash: Option<String>,
    pub expected_next: Option<String>,
}

pub fn parse_rules(rules: &str) -> Result<Rules, ClientErrorDto> {
    match rules {
        "standard" => Ok(Rules::Standard),
        "no-touch" => Ok(Rules::NoTouch),
        _ => Err(ClientErrorDto::new(
            "invalid_input",
            format!("unknown rules '{rules}'; expected 'standard' or 'no-touch'"),
        )),
    }
}

pub fn rules_str(rules: Rules) -> &'static str {
    match rules {
        Rules::Standard => "standard",
        Rules::NoTouch => "no-touch",
    }
}

fn role_str(role: Role) -> &'static str {
    match role {
        Role::A => "A",
        Role::B => "B",
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex_32(s: &str, label: &str) -> Result<[u8; 32], ClientErrorDto> {
    let trimmed = s.trim();
    if trimmed.len() != 64 {
        return Err(ClientErrorDto::new(
            "invalid_input",
            format!("{label} must be 64 hex characters, got {}", trimmed.len()),
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&trimmed[2 * i..2 * i + 2], 16)
            .map_err(|_| ClientErrorDto::new("invalid_input", format!("invalid hex in {label}")))?;
    }
    Ok(out)
}

pub fn parse_fleet(ships: &[ShipDto], rules: Rules) -> Result<Fleet, ClientErrorDto> {
    if ships.len() != K {
        return Err(ClientErrorDto::new(
            "invalid_input",
            format!("expected {K} ships, got {}", ships.len()),
        ));
    }
    let placements: [ShipPlacement; K] = std::array::from_fn(|j| ShipPlacement {
        row: ships[j].row,
        col: ships[j].col,
        vertical: ships[j].vertical,
    });
    Fleet::new(placements, rules).map_err(|e| ClientErrorDto::new("invalid_input", e.to_string()))
}

pub fn fleet_to_dtos(fleet: &Fleet) -> Vec<ShipDto> {
    fleet
        .ships()
        .iter()
        .map(|s| ShipDto {
            row: s.row,
            col: s.col,
            vertical: s.vertical,
        })
        .collect()
}

pub fn protocol_info() -> ProtocolInfoDto {
    ProtocolInfoDto {
        board_n: BOARD_N,
        cells: N,
        ship_lengths: FLEET_LENGTHS.to_vec(),
        total_ship_cells: T,
        standard_params_id: hex(Parameters::standard().params_id()),
        no_touch_params_id: hex(Parameters::no_touch().params_id()),
        hello_len: Hello::LEN,
        max_frame_size: zkb_session::codec::MAX_FRAME_SIZE,
    }
}

pub fn warmup(rules: &str) -> Result<String, ClientErrorDto> {
    let rules = parse_rules(rules)?;
    Ok(hex(Parameters::for_rules(rules).params_id()))
}

pub fn verify_transcript_dto(
    hello_one: &[u8],
    hello_two: &[u8],
    frames: &[Vec<u8>],
) -> Result<VerifyReportDto, ClientErrorDto> {
    let report = verify::verify_transcript(hello_one, hello_two, frames)
        .map_err(|e| ClientErrorDto::new("invalid_input", e.to_string()))?;

    let map_sunk = |flags: &[bool; K], cells: &[Option<Vec<CellIndex>>; K]| -> Vec<SunkShipDto> {
        (0..K)
            .filter(|&j| flags[j])
            .map(|j| SunkShipDto {
                ship: j as u8,
                length: FLEET_LENGTHS[j],
                cells: cells[j]
                    .as_ref()
                    .map(|cs| cs.iter().map(|c| c.index()).collect())
                    .unwrap_or_default(),
            })
            .collect()
    };

    let mut dto = VerifyReportDto {
        rules: rules_str(report.rules).to_string(),
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
            dto.verdict = "completed".to_string();
            dto.winner = Some(role_str(winner).to_string());
        }
        TranscriptVerdict::Resigned { winner, resigned } => {
            dto.verdict = "resigned".to_string();
            dto.winner = Some(role_str(winner).to_string());
            dto.resigned = Some(role_str(resigned).to_string());
        }
        TranscriptVerdict::AttributableViolation {
            guilty,
            sequence,
            frame_hash,
            violation,
        } => {
            dto.verdict = "attributable_violation".to_string();
            dto.guilty = Some(role_str(guilty).to_string());
            dto.violation = Some(violation.to_string());
            dto.violation_sequence = Some(sequence);
            dto.violation_frame_hash = Some(hex(&frame_hash));
        }
        TranscriptVerdict::Incomplete { expected_next } => {
            dto.verdict = "incomplete".to_string();
            dto.expected_next = Some(role_str(expected_next).to_string());
        }
    }
    Ok(dto)
}

struct AnyValidKey;

impl PeerAuthPolicy for AnyValidKey {
    fn authenticate(&self, announced: &PeerKey) -> Option<AuthenticatedPeer> {
        Some(AuthenticatedPeer::from_policy_decision(*announced))
    }
}

struct PendingBootstrap {
    keypair: IdentityKeypair,
    fleet: Fleet,
    rho: Zeroizing<Vec<Scalar>>,
    own_occupied: [bool; N],
    own_hello: Hello,
    checked_own: CheckedHello,
    expected_peer: Option<PeerKey>,
}

struct ActiveSession {
    session: Session<'static>,
    own_hello: Hello,
    peer_hello: Hello,
    expected_peer: Option<PeerKey>,
    safety_code: String,
    own_occupied: [bool; N],
    opponent_outcomes: [Option<bool>; N],
    finish_reason: Option<String>,
    evidence_frame: Option<Vec<u8>>,
    evidence_frame_hash: Option<String>,
}

enum Stage {
    AwaitingPeerHello(Box<PendingBootstrap>),
    Active(Box<ActiveSession>),
    AbortedPreBootstrap {
        own_hello: Option<Box<Hello>>,
        reason: String,
    },
}

pub struct ClientEngine {
    params: &'static Parameters,
    own_key: PeerKey,
    stage: Stage,
}

impl Drop for ClientEngine {
    fn drop(&mut self) {
        match &mut self.stage {
            Stage::AwaitingPeerHello(pending) => pending.own_occupied.zeroize(),
            Stage::Active(active) => active.own_occupied.zeroize(),
            Stage::AbortedPreBootstrap { .. } => {}
        }
    }
}

impl ClientEngine {
    pub fn new(
        rules: &str,
        ships: &[ShipDto],
        identity_seed: Option<&[u8]>,
        expected_peer_key_hex: Option<&str>,
    ) -> Result<Self, ClientErrorDto> {
        Self::new_with_rng(
            rules,
            ships,
            identity_seed,
            expected_peer_key_hex,
            &mut OsRng,
        )
    }

    pub fn new_with_rng<R: RngCore + CryptoRng>(
        rules: &str,
        ships: &[ShipDto],
        identity_seed: Option<&[u8]>,
        expected_peer_key_hex: Option<&str>,
        rng: &mut R,
    ) -> Result<Self, ClientErrorDto> {
        let rules = parse_rules(rules)?;
        let params = Parameters::for_rules(rules);
        let fleet = parse_fleet(ships, rules)?;
        let expected_peer = match expected_peer_key_hex {
            Some(hex_str) if !hex_str.trim().is_empty() => {
                let bytes = decode_hex_32(hex_str, "expected_peer_key")?;
                let pk = PeerKey::from_bytes(bytes)
                    .map_err(|e| ClientErrorDto::new("invalid_input", e.to_string()))?;
                Some(pk)
            }
            _ => None,
        };
        let keypair = match identity_seed {
            Some(bytes) => {
                let seed: [u8; 32] = bytes.try_into().map_err(|_| {
                    ClientErrorDto::new(
                        "invalid_input",
                        format!("identity_seed must be 32 bytes, got {}", bytes.len()),
                    )
                })?;
                IdentityKeypair::from_seed(&seed)
            }
            None => IdentityKeypair::generate(rng),
        };
        let own_key = keypair.peer_key();
        if expected_peer == Some(own_key) {
            return Err(ClientErrorDto::new(
                "invalid_input",
                "expected peer key cannot match own identity key",
            ));
        }

        let own_hello = Hello::create(&keypair, *params.params_id(), rng);
        let checked_own = hello::check_hello(
            own_hello.clone(),
            params.params_id(),
            &ExpectedKey::new(own_key),
        )
        .map_err(|e| ClientErrorDto::new("internal", e.to_string()))?;

        let rho = Zeroizing::new((0..SHIP_BITS).map(|_| Scalar::random(rng)).collect());
        let own_occupied = fleet.occupied();
        Ok(Self {
            params,
            own_key,
            stage: Stage::AwaitingPeerHello(Box::new(PendingBootstrap {
                keypair,
                fleet,
                rho,
                own_occupied,
                own_hello,
                checked_own,
                expected_peer,
            })),
        })
    }

    pub fn hello_bytes(&self) -> Vec<u8> {
        match &self.stage {
            Stage::AwaitingPeerHello(p) => p.own_hello.encode(),
            Stage::Active(a) => a.own_hello.encode(),
            Stage::AbortedPreBootstrap { own_hello, .. } => {
                own_hello.as_ref().map(|h| h.encode()).unwrap_or_default()
            }
        }
    }

    pub fn own_public_key_hex(&self) -> String {
        self.own_key.fingerprint_hex()
    }

    pub fn own_fingerprint(&self) -> String {
        self.own_key.fingerprint_hex()
    }

    pub fn accept_peer_hello(
        &mut self,
        bytes: &[u8],
    ) -> Result<BootstrapResultDto, ClientErrorDto> {
        self.accept_peer_hello_with_rng(bytes, &mut OsRng)
    }

    pub fn accept_peer_hello_with_rng<R: RngCore + CryptoRng>(
        &mut self,
        bytes: &[u8],
        rng: &mut R,
    ) -> Result<BootstrapResultDto, ClientErrorDto> {
        let peer_hello = Hello::decode(bytes)
            .map_err(|e| ClientErrorDto::new("peer_auth", format!("invalid peer Hello: {e}")))?;

        let (expected_peer, checked_own) = match &self.stage {
            Stage::AwaitingPeerHello(p) => (p.expected_peer, p.checked_own.clone()),
            _ => {
                return Err(ClientErrorDto::new(
                    "wrong_state",
                    "peer Hello already processed or session aborted",
                ));
            }
        };

        let checked_peer = match expected_peer {
            Some(expected) => hello::check_hello(
                peer_hello.clone(),
                self.params.params_id(),
                &ExpectedKey::new(expected),
            ),
            None => hello::check_hello(peer_hello.clone(), self.params.params_id(), &AnyValidKey),
        }
        .map_err(|e| ClientErrorDto::new("peer_auth", e.to_string()))?;

        let peer = *checked_peer.authenticated_peer();
        let bootstrap = hello::complete_bootstrap(checked_own, checked_peer)
            .map_err(|e| ClientErrorDto::new("peer_auth", e.to_string()))?;
        let safety_code = bootstrap.safety_code();

        let Stage::AwaitingPeerHello(pending) = std::mem::replace(
            &mut self.stage,
            Stage::AbortedPreBootstrap {
                own_hello: None,
                reason: "bootstrap in progress".to_string(),
            },
        ) else {
            unreachable!()
        };

        let mut session = match Session::from_bootstrap_owned(
            self.params,
            pending.keypair,
            &bootstrap,
            peer,
            pending.fleet,
            pending.rho.to_vec(),
        ) {
            Ok(s) => s,
            Err(e) => {
                self.stage = Stage::AbortedPreBootstrap {
                    own_hello: Some(Box::new(pending.own_hello)),
                    reason: format!("session init failed: {e}"),
                };
                return Err(ClientErrorDto::new("internal", e.to_string()));
            }
        };

        let mut outgoing_frames = Vec::new();
        if let Err(err) = drain_produce(&mut session, rng, &mut outgoing_frames) {
            self.stage = Stage::AbortedPreBootstrap {
                own_hello: Some(Box::new(pending.own_hello)),
                reason: err.message.clone(),
            };
            return Err(err);
        }

        let local_role = session.local_role();
        let peer_pk = peer.key().fingerprint_hex();
        let sid_hex = hex(session.sid());
        let genesis_hex = hex(session.genesis_hash());

        self.stage = Stage::Active(Box::new(ActiveSession {
            session,
            own_hello: pending.own_hello,
            peer_hello,
            expected_peer: pending.expected_peer,
            safety_code: safety_code.clone(),
            own_occupied: pending.own_occupied,
            opponent_outcomes: [None; N],
            finish_reason: None,
            evidence_frame: None,
            evidence_frame_hash: None,
        }));

        Ok(BootstrapResultDto {
            local_role: role_str(local_role).to_string(),
            sid: sid_hex,
            genesis_hash: genesis_hex,
            safety_code,
            peer_public_key: peer_pk.clone(),
            peer_fingerprint: peer_pk,
            outgoing_frames,
            state: self.state(),
        })
    }

    pub fn accept_frame(&mut self, bytes: &[u8]) -> Result<StepResultDto, ClientErrorDto> {
        self.accept_frame_with_rng(bytes, &mut OsRng)
    }

    pub fn accept_frame_with_rng<R: RngCore + CryptoRng>(
        &mut self,
        bytes: &[u8],
        rng: &mut R,
    ) -> Result<StepResultDto, ClientErrorDto> {
        let Stage::Active(active) = &mut self.stage else {
            return Err(ClientErrorDto::new(
                "wrong_state",
                "session has not completed bootstrap or was aborted",
            ));
        };

        let pending_local_cell = active.session.game().and_then(|g| match g.state() {
            GameState::AwaitingAnswer { shooter, cell }
                if shooter == active.session.local_role() =>
            {
                Some(cell)
            }
            _ => None,
        });

        let accept_res = active.session.accept(bytes);
        let outcome = match accept_res {
            Ok(o) => o,
            Err(SessionError::ClassB(reason)) => {
                return Err(ClientErrorDto::new("class_b", reason.to_string()));
            }
            Err(SessionError::Attributable(v)) => {
                let raw = v.frame.bytes().to_vec();
                let hash = hex(&frame::frame_hash(&raw));
                let msg = v.violation.to_string();
                active.evidence_frame = Some(raw.clone());
                active.evidence_frame_hash = Some(hash.clone());
                active.finish_reason = Some(format!("attributable_violation: {msg}"));
                let mut err = ClientErrorDto::new("attributable", msg);
                err.evidence_frame = Some(raw);
                err.evidence_frame_hash = Some(hash);
                return Err(err);
            }
            Err(SessionError::WrongLocalState(msg)) => {
                return Err(ClientErrorDto::new("wrong_state", msg));
            }
            Err(SessionError::InternalInvariant(msg)) => {
                active.finish_reason = Some(format!("internal_error: {msg}"));
                return Err(ClientErrorDto::new("internal", msg));
            }
            Err(SessionError::LocalGame(e)) => {
                return Err(ClientErrorDto::new("invalid_input", e.to_string()));
            }
        };

        let mut outgoing_frames = Vec::new();
        if let Err(err) = drain_produce(&mut active.session, rng, &mut outgoing_frames) {
            active.finish_reason = Some(err.message.clone());
            return Err(err);
        }

        let event;
        let mut first_mover = None;
        let mut cell_out = None;
        let mut outcome_str = None;
        let mut sunk_ship = None;
        let mut winner_out = None;

        match outcome {
            AcceptOutcome::CommitVerified => {
                event = "commit_verified".to_string();
            }
            AcceptOutcome::CoinProgress => {
                event = "coin_progress".to_string();
            }
            AcceptOutcome::GameReady { first_mover: fm } => {
                event = "game_ready".to_string();
                first_mover = Some(role_str(fm).to_string());
            }
            AcceptOutcome::ShotReceived {
                cell,
                hit,
                answer,
                winner,
            } => {
                event = "shot_received".to_string();
                cell_out = Some(cell.index());
                outcome_str = Some(if hit { "hit" } else { "miss" }.to_string());
                outgoing_frames.push(answer.bytes().to_vec());
                if let Some(w) = winner {
                    winner_out = Some(role_str(w).to_string());
                    active.finish_reason = Some("completed".to_string());
                }
            }
            AcceptOutcome::Answer(shot_outcome) => {
                event = "answer".to_string();
                if let Some(cell) = pending_local_cell {
                    cell_out = Some(cell.index());
                    active.opponent_outcomes[cell.index() as usize] =
                        Some(shot_outcome != ShotOutcome::Miss);
                }
                match shot_outcome {
                    ShotOutcome::Miss => outcome_str = Some("miss".to_string()),
                    ShotOutcome::Hit => outcome_str = Some("hit".to_string()),
                    ShotOutcome::Sunk { ship } => {
                        outcome_str = Some("sunk".to_string());
                        sunk_ship = Some(ship);
                    }
                    ShotOutcome::Win => outcome_str = Some("win".to_string()),
                }
            }
            AcceptOutcome::GameFinished { winner } => {
                event = "game_finished".to_string();
                if let Some(cell) = pending_local_cell {
                    cell_out = Some(cell.index());
                    active.opponent_outcomes[cell.index() as usize] = Some(true);
                }
                outcome_str = Some("win".to_string());
                winner_out = Some(role_str(winner).to_string());
                active.finish_reason = Some("completed".to_string());
            }
            AcceptOutcome::PeerResigned => {
                event = "peer_resigned".to_string();
                let w = active.session.winner().expect("winner set on resign");
                winner_out = Some(role_str(w).to_string());
                active.finish_reason = Some("peer_resigned".to_string());
            }
        }

        Ok(StepResultDto {
            event,
            outgoing_frames,
            first_mover,
            cell: cell_out,
            outcome: outcome_str,
            sunk_ship,
            winner: winner_out,
            state: self.state(),
        })
    }

    pub fn fire_shot(&mut self, row: u8, col: u8) -> Result<StepResultDto, ClientErrorDto> {
        let cell = CellIndex::from_row_col(row, col).ok_or_else(|| {
            ClientErrorDto::new(
                "invalid_input",
                format!("cell ({row}, {col}) is outside the {BOARD_N}x{BOARD_N} board"),
            )
        })?;
        self.fire_shot_cell(cell)
    }

    pub fn fire_shot_index(&mut self, index: u8) -> Result<StepResultDto, ClientErrorDto> {
        let cell = CellIndex::from_index(index).ok_or_else(|| {
            ClientErrorDto::new(
                "invalid_input",
                format!("cell index {index} is outside 0..{N}"),
            )
        })?;
        self.fire_shot_cell(cell)
    }

    fn fire_shot_cell(&mut self, cell: CellIndex) -> Result<StepResultDto, ClientErrorDto> {
        let Stage::Active(active) = &mut self.stage else {
            return Err(ClientErrorDto::new("wrong_state", "no active session"));
        };
        let frame = active
            .session
            .fire_shot(cell)
            .map_err(map_local_session_err)?;
        Ok(StepResultDto {
            event: "shot_fired".to_string(),
            outgoing_frames: vec![frame.bytes().to_vec()],
            first_mover: None,
            cell: Some(cell.index()),
            outcome: None,
            sunk_ship: None,
            winner: None,
            state: self.state(),
        })
    }

    pub fn resign(&mut self) -> Result<StepResultDto, ClientErrorDto> {
        let Stage::Active(active) = &mut self.stage else {
            return Err(ClientErrorDto::new("wrong_state", "no active session"));
        };
        let frame = active.session.resign().map_err(map_local_session_err)?;
        active.finish_reason = Some("self_resigned".to_string());
        let winner = active.session.winner().map(|w| role_str(w).to_string());
        Ok(StepResultDto {
            event: "resigned".to_string(),
            outgoing_frames: vec![frame.bytes().to_vec()],
            first_mover: None,
            cell: None,
            outcome: None,
            sunk_ship: None,
            winner,
            state: self.state(),
        })
    }

    pub fn abort(&mut self, reason: Option<&str>) -> ClientStateDto {
        let msg = reason.unwrap_or("aborted").to_string();
        match &mut self.stage {
            Stage::AwaitingPeerHello(_) => {
                let prev = std::mem::replace(
                    &mut self.stage,
                    Stage::AbortedPreBootstrap {
                        own_hello: None,
                        reason: msg.clone(),
                    },
                );
                if let Stage::AwaitingPeerHello(p) = prev {
                    self.stage = Stage::AbortedPreBootstrap {
                        own_hello: Some(Box::new(p.own_hello)),
                        reason: msg,
                    };
                }
            }
            Stage::Active(active) => {
                active.session.abort();
                if active.finish_reason.is_none() {
                    active.finish_reason = Some(msg);
                }
            }
            Stage::AbortedPreBootstrap { .. } => {}
        }
        self.state()
    }

    pub fn state(&self) -> ClientStateDto {
        let rules = rules_str(self.params.rules()).to_string();
        let params_id = hex(self.params.params_id());
        let own_pk = self.own_key.fingerprint_hex();

        match &self.stage {
            Stage::AwaitingPeerHello(p) => ClientStateDto {
                phase: "awaiting_peer_hello".to_string(),
                rules,
                params_id,
                own_public_key: own_pk.clone(),
                own_fingerprint: own_pk,
                peer_public_key: p.expected_peer.map(|k| k.fingerprint_hex()),
                peer_fingerprint: p.expected_peer.map(|k| k.fingerprint_hex()),
                safety_code: None,
                sid: None,
                genesis_hash: None,
                local_role: None,
                first_mover: None,
                expected_sender: None,
                your_turn: false,
                can_fire_shot: false,
                can_resign: false,
                head_sequence: 0,
                head_hash: None,
                winner: None,
                finish_reason: None,
                verified_hits: 0,
                hits_conceded: 0,
                my_board: (0..N)
                    .map(|i| if p.own_occupied[i] { "ship" } else { "water" }.to_string())
                    .collect(),
                opponent_board: vec!["unknown".to_string(); N],
                my_sunk_ships: Vec::new(),
                opponent_sunk_ships: Vec::new(),
                evidence_frame: None,
                evidence_frame_hash: None,
            },
            Stage::AbortedPreBootstrap { reason, .. } => ClientStateDto {
                phase: "aborted".to_string(),
                rules,
                params_id,
                own_public_key: own_pk.clone(),
                own_fingerprint: own_pk,
                peer_public_key: None,
                peer_fingerprint: None,
                safety_code: None,
                sid: None,
                genesis_hash: None,
                local_role: None,
                first_mover: None,
                expected_sender: None,
                your_turn: false,
                can_fire_shot: false,
                can_resign: false,
                head_sequence: 0,
                head_hash: None,
                winner: None,
                finish_reason: Some(reason.clone()),
                verified_hits: 0,
                hits_conceded: 0,
                my_board: vec!["water".to_string(); N],
                opponent_board: vec!["unknown".to_string(); N],
                my_sunk_ships: Vec::new(),
                opponent_sunk_ships: Vec::new(),
                evidence_frame: None,
                evidence_frame_hash: None,
            },
            Stage::Active(active) => {
                let s = &active.session;
                let phase = match s.phase_kind() {
                    PhaseKind::Commit => "commit",
                    PhaseKind::Coin => "coin",
                    PhaseKind::Playing => "playing",
                    PhaseKind::Finished => "finished",
                    PhaseKind::Aborted => "aborted",
                }
                .to_string();
                let local_role = s.local_role();
                let expected = s.expected_sender();
                let can_fire = s.can_fire_shot();
                let can_resign = expected == Some(local_role);
                let peer_pk = s.peer().key().fingerprint_hex();

                let (
                    verified_hits,
                    hits_conceded,
                    my_board,
                    opponent_board,
                    my_sunk_ships,
                    opp_sunk_ships,
                ) = if let Some(game) = s.game() {
                    let own_shots = game.shots_on_board(local_role);
                    let mut my_sunk_mask = [false; N];
                    let mut my_sunk = Vec::new();
                    let mut opp_sunk_mask = [false; N];
                    let mut opp_sunk = Vec::new();
                    for (j, &length) in FLEET_LENGTHS.iter().enumerate() {
                        if game.own_sunk()[j] {
                            let cells: Vec<u8> = game
                                .own_sunk_cells(j)
                                .map(|cs| cs.iter().map(|c| c.index()).collect())
                                .unwrap_or_default();
                            for &c in &cells {
                                my_sunk_mask[c as usize] = true;
                            }
                            my_sunk.push(SunkShipDto {
                                ship: j as u8,
                                length,
                                cells,
                            });
                        }
                        if game.peer_sunk()[j] {
                            let cells: Vec<u8> = game
                                .peer_sunk_cells(j)
                                .map(|cs| cs.iter().map(|c| c.index()).collect())
                                .unwrap_or_default();
                            for &c in &cells {
                                opp_sunk_mask[c as usize] = true;
                            }
                            opp_sunk.push(SunkShipDto {
                                ship: j as u8,
                                length,
                                cells,
                            });
                        }
                    }
                    let my_cells = (0..N)
                        .map(|i| {
                            let cell = CellIndex::from_index(i as u8).expect("i < N");
                            let occ = active.own_occupied[i];
                            let shot = own_shots.is_shot(cell);
                            match (occ, shot, my_sunk_mask[i]) {
                                (true, _, true) => "sunk",
                                (true, true, false) => "hit",
                                (true, false, false) => "ship",
                                (false, true, _) => "miss",
                                (false, false, _) => "water",
                            }
                            .to_string()
                        })
                        .collect();
                    let opp_cells = (0..N)
                        .map(|i| {
                            if opp_sunk_mask[i] {
                                "sunk"
                            } else {
                                match active.opponent_outcomes[i] {
                                    Some(true) => "hit",
                                    Some(false) => "miss",
                                    None => "unknown",
                                }
                            }
                            .to_string()
                        })
                        .collect();
                    (
                        game.verified_hits(),
                        game.hits_conceded(),
                        my_cells,
                        opp_cells,
                        my_sunk,
                        opp_sunk,
                    )
                } else {
                    let my_cells = (0..N)
                        .map(|i| {
                            if active.own_occupied[i] {
                                "ship"
                            } else {
                                "water"
                            }
                            .to_string()
                        })
                        .collect();
                    (
                        0,
                        0,
                        my_cells,
                        vec!["unknown".to_string(); N],
                        Vec::new(),
                        Vec::new(),
                    )
                };

                ClientStateDto {
                    phase,
                    rules,
                    params_id,
                    own_public_key: own_pk.clone(),
                    own_fingerprint: own_pk,
                    peer_public_key: Some(peer_pk.clone()),
                    peer_fingerprint: Some(peer_pk),
                    safety_code: Some(active.safety_code.clone()),
                    sid: Some(hex(s.sid())),
                    genesis_hash: Some(hex(s.genesis_hash())),
                    local_role: Some(role_str(local_role).to_string()),
                    first_mover: s.first_mover().map(|r| role_str(r).to_string()),
                    expected_sender: expected.map(|r| role_str(r).to_string()),
                    your_turn: can_fire || s.needs_produce(),
                    can_fire_shot: can_fire,
                    can_resign,
                    head_sequence: s.head_sequence(),
                    head_hash: Some(hex(s.head_hash())),
                    winner: s.winner().map(|w| role_str(w).to_string()),
                    finish_reason: active.finish_reason.clone(),
                    verified_hits,
                    hits_conceded,
                    my_board,
                    opponent_board,
                    my_sunk_ships,
                    opponent_sunk_ships: opp_sunk_ships,
                    evidence_frame: active.evidence_frame.clone(),
                    evidence_frame_hash: active.evidence_frame_hash.clone(),
                }
            }
        }
    }

    pub fn export_public_transcript(&self) -> TranscriptDto {
        let rules = rules_str(self.params.rules()).to_string();
        let params_id = hex(self.params.params_id());
        match &self.stage {
            Stage::AwaitingPeerHello(p) => TranscriptDto {
                rules,
                params_id,
                hello_a: Some(p.own_hello.encode()),
                hello_b: None,
                sid: None,
                genesis_hash: None,
                frames: Vec::new(),
                evidence_frame: None,
            },
            Stage::AbortedPreBootstrap { own_hello, .. } => TranscriptDto {
                rules,
                params_id,
                hello_a: own_hello.as_ref().map(|h| h.encode()),
                hello_b: None,
                sid: None,
                genesis_hash: None,
                frames: Vec::new(),
                evidence_frame: None,
            },
            Stage::Active(active) => {
                let (hello_a, hello_b) = match active.session.local_role() {
                    Role::A => (active.own_hello.encode(), active.peer_hello.encode()),
                    Role::B => (active.peer_hello.encode(), active.own_hello.encode()),
                };
                TranscriptDto {
                    rules,
                    params_id,
                    hello_a: Some(hello_a),
                    hello_b: Some(hello_b),
                    sid: Some(hex(active.session.sid())),
                    genesis_hash: Some(hex(active.session.genesis_hash())),
                    frames: active.session.transcript().to_vec(),
                    evidence_frame: active.evidence_frame.clone(),
                }
            }
        }
    }

    pub fn export_secret_snapshot(&self) -> Result<Zeroizing<Vec<u8>>, ClientErrorDto> {
        let Stage::Active(active) = &self.stage else {
            return Err(ClientErrorDto::new(
                "wrong_state",
                "snapshots are supported only after bootstrap while active",
            ));
        };
        let session_snap = active
            .session
            .export_snapshot()
            .map_err(map_local_session_err)?;
        let seed = active.session.keypair().to_seed();
        let mut out = Zeroizing::new(Vec::with_capacity(
            8 + 1 + 32 + Hello::LEN * 2 + 33 + 4 + session_snap.len(),
        ));
        out.extend_from_slice(CLIENT_SNAPSHOT_MAGIC);
        out.push(match self.params.rules() {
            Rules::Standard => 0,
            Rules::NoTouch => 1,
        });
        out.extend_from_slice(&*seed);
        out.extend_from_slice(&active.own_hello.encode());
        out.extend_from_slice(&active.peer_hello.encode());
        match active.expected_peer {
            Some(pk) => {
                out.push(1);
                out.extend_from_slice(pk.as_bytes());
            }
            None => out.push(0),
        }
        let snap_len = u32::try_from(session_snap.len())
            .map_err(|_| ClientErrorDto::new("internal", "snapshot exceeds u32"))?;
        out.extend_from_slice(&snap_len.to_le_bytes());
        out.extend_from_slice(&session_snap);
        Ok(out)
    }

    pub fn restore_secret_snapshot(snapshot: &[u8]) -> Result<Self, ClientErrorDto> {
        let invalid = |msg: &str| ClientErrorDto::new("invalid_input", msg);
        let mut pos = 0usize;
        let take = |pos: &mut usize, n: usize| -> Result<&[u8], ClientErrorDto> {
            let end = pos
                .checked_add(n)
                .ok_or_else(|| invalid("snapshot overflow"))?;
            if end > snapshot.len() {
                return Err(invalid("truncated client snapshot"));
            }
            let s = &snapshot[*pos..end];
            *pos = end;
            Ok(s)
        };
        if take(&mut pos, 8)? != CLIENT_SNAPSHOT_MAGIC {
            return Err(invalid("invalid client snapshot header"));
        }
        let rules = match take(&mut pos, 1)?[0] {
            0 => Rules::Standard,
            1 => Rules::NoTouch,
            _ => return Err(invalid("unknown rules in snapshot")),
        };
        let params = Parameters::for_rules(rules);
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(take(&mut pos, 32)?);
        let keypair = IdentityKeypair::from_seed(&seed);
        let own_key = keypair.peer_key();

        let own_hello = Hello::decode(take(&mut pos, Hello::LEN)?)
            .map_err(|e| invalid(&format!("invalid own hello in snapshot: {e}")))?;
        let peer_hello = Hello::decode(take(&mut pos, Hello::LEN)?)
            .map_err(|e| invalid(&format!("invalid peer hello in snapshot: {e}")))?;
        let expected_peer = match take(&mut pos, 1)?[0] {
            0 => None,
            1 => {
                let bytes: [u8; 32] = take(&mut pos, 32)?.try_into().expect("32");
                Some(
                    PeerKey::from_bytes(bytes)
                        .map_err(|e| invalid(&format!("invalid expected peer key: {e}")))?,
                )
            }
            _ => return Err(invalid("invalid expected peer flag in snapshot")),
        };
        let snap_len = u32::from_le_bytes(take(&mut pos, 4)?.try_into().expect("4")) as usize;
        let session_snap = take(&mut pos, snap_len)?;
        if pos != snapshot.len() {
            return Err(invalid("trailing bytes in client snapshot"));
        }

        let checked_own = hello::check_hello(
            own_hello.clone(),
            params.params_id(),
            &ExpectedKey::new(own_key),
        )
        .map_err(|e| ClientErrorDto::new("peer_auth", e.to_string()))?;
        let checked_peer = match expected_peer {
            Some(pk) => hello::check_hello(
                peer_hello.clone(),
                params.params_id(),
                &ExpectedKey::new(pk),
            ),
            None => hello::check_hello(peer_hello.clone(), params.params_id(), &AnyValidKey),
        }
        .map_err(|e| ClientErrorDto::new("peer_auth", e.to_string()))?;
        let peer = *checked_peer.authenticated_peer();
        let bootstrap = hello::complete_bootstrap(checked_own, checked_peer)
            .map_err(|e| ClientErrorDto::new("peer_auth", e.to_string()))?;
        let safety_code = bootstrap.safety_code();
        let expected_role = bootstrap.role_of(&own_key);
        let expected_sid = *bootstrap.sid();
        let expected_genesis = *bootstrap.genesis_hash();

        let session = Session::restore_snapshot_owned(params, keypair, peer, session_snap)
            .map_err(map_local_session_err)?;
        if session.local_role() != expected_role
            || session.sid() != &expected_sid
            || session.genesis_hash() != &expected_genesis
        {
            return Err(invalid(
                "session snapshot does not match the authenticated Hello bootstrap",
            ));
        }
        let fleet_bytes = session.own_fleet_bytes().ok_or_else(|| {
            ClientErrorDto::new("internal", "restored snapshot missing fleet secrets")
        })?;
        let own_occupied = Fleet::from_bytes(&fleet_bytes, rules)
            .map_err(|e| ClientErrorDto::new("internal", e.to_string()))?
            .occupied();

        let opponent_outcomes =
            reconstruct_opponent_outcomes(session.local_role(), session.transcript());

        Ok(Self {
            params,
            own_key,
            stage: Stage::Active(Box::new(ActiveSession {
                session,
                own_hello,
                peer_hello,
                expected_peer,
                safety_code,
                own_occupied,
                opponent_outcomes,
                finish_reason: None,
                evidence_frame: None,
                evidence_frame_hash: None,
            })),
        })
    }
}

fn reconstruct_opponent_outcomes(local_role: Role, transcript: &[Vec<u8>]) -> [Option<bool>; N] {
    let mut out = [None; N];
    let local_byte = frame::role_to_byte(local_role);
    let peer_byte = frame::role_to_byte(local_role.other());
    let mut pending: Option<usize> = None;
    for raw in transcript {
        let Ok(f) = SignedFrame::decode(raw) else {
            continue;
        };
        let hdr = f.header();
        if hdr.sender_role == local_byte && hdr.message_type == MessageType::Shot {
            pending = Some(usize::from(f.payload()[0]));
        } else if hdr.sender_role == peer_byte && hdr.message_type == MessageType::Answer {
            if let Some(cell) = pending.take() {
                if cell < N {
                    out[cell] = Some(f.payload()[0] != 0);
                }
            }
        }
    }
    out
}

fn drain_produce<R: RngCore + CryptoRng>(
    session: &mut Session<'static>,
    rng: &mut R,
    out: &mut Vec<Vec<u8>>,
) -> Result<(), ClientErrorDto> {
    while let Some(frame) = session.produce(rng).map_err(map_local_session_err)? {
        out.push(frame.bytes().to_vec());
    }
    Ok(())
}

fn map_local_session_err(err: SessionError) -> ClientErrorDto {
    match err {
        SessionError::WrongLocalState(m) => ClientErrorDto::new("wrong_state", m),
        SessionError::LocalGame(e) => ClientErrorDto::new("invalid_input", e.to_string()),
        SessionError::InternalInvariant(m) => ClientErrorDto::new("internal", m),
        SessionError::ClassB(r) => ClientErrorDto::new("class_b", r.to_string()),
        SessionError::Attributable(v) => {
            let mut dto = ClientErrorDto::new("attributable", v.violation.to_string());
            let raw = v.frame.bytes().to_vec();
            dto.evidence_frame_hash = Some(hex(&frame::frame_hash(&raw)));
            dto.evidence_frame = Some(raw);
            dto
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn sample_ships_a() -> Vec<ShipDto> {
        vec![
            ShipDto {
                row: 0,
                col: 0,
                vertical: false,
            },
            ShipDto {
                row: 2,
                col: 0,
                vertical: false,
            },
            ShipDto {
                row: 4,
                col: 0,
                vertical: false,
            },
            ShipDto {
                row: 6,
                col: 0,
                vertical: false,
            },
            ShipDto {
                row: 8,
                col: 0,
                vertical: false,
            },
        ]
    }

    fn sample_ships_b() -> Vec<ShipDto> {
        vec![
            ShipDto {
                row: 0,
                col: 9,
                vertical: true,
            },
            ShipDto {
                row: 0,
                col: 7,
                vertical: true,
            },
            ShipDto {
                row: 0,
                col: 5,
                vertical: true,
            },
            ShipDto {
                row: 0,
                col: 3,
                vertical: true,
            },
            ShipDto {
                row: 0,
                col: 1,
                vertical: true,
            },
        ]
    }

    #[test]
    fn full_game_with_pinning_snapshot_and_verification() {
        let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
        let seed_a = [0x11u8; 32];
        let seed_b = [0x22u8; 32];
        let pk_a = IdentityKeypair::from_seed(&seed_a)
            .peer_key()
            .fingerprint_hex();
        let pk_b = IdentityKeypair::from_seed(&seed_b)
            .peer_key()
            .fingerprint_hex();

        for rules in ["standard", "no-touch"] {
            let mut ca = ClientEngine::new_with_rng(
                rules,
                &sample_ships_a(),
                Some(&seed_a),
                Some(&pk_b),
                &mut rng,
            )
            .unwrap();
            let mut cb = ClientEngine::new_with_rng(
                rules,
                &sample_ships_b(),
                Some(&seed_b),
                Some(&pk_a),
                &mut rng,
            )
            .unwrap();

            let ha = ca.hello_bytes();
            let hb = cb.hello_bytes();
            let ba = ca.accept_peer_hello_with_rng(&hb, &mut rng).unwrap();
            let bb = cb.accept_peer_hello_with_rng(&ha, &mut rng).unwrap();
            assert_eq!(ba.safety_code, bb.safety_code);
            assert_eq!(ba.sid, bb.sid);

            let mut q_to_b: Vec<Vec<u8>> = ba.outgoing_frames;
            let mut q_to_a: Vec<Vec<u8>> = bb.outgoing_frames;
            while !q_to_b.is_empty() || !q_to_a.is_empty() {
                for f in std::mem::take(&mut q_to_b) {
                    let step = cb.accept_frame_with_rng(&f, &mut rng).unwrap();
                    q_to_a.extend(step.outgoing_frames);
                }
                for f in std::mem::take(&mut q_to_a) {
                    let step = ca.accept_frame_with_rng(&f, &mut rng).unwrap();
                    q_to_b.extend(step.outgoing_frames);
                }
            }

            let sa = ca.state();
            let sb = cb.state();
            assert_eq!(sa.phase, "playing");
            assert_eq!(sb.phase, "playing");
            assert_eq!(sa.first_mover, sb.first_mover);
            assert_ne!(sa.can_fire_shot, sb.can_fire_shot);

            let mut turn = 0u32;
            let mut snapshotted = false;
            loop {
                let (att, def) = if ca.state().can_fire_shot {
                    (&mut ca, &mut cb)
                } else {
                    (&mut cb, &mut ca)
                };
                if turn == 12 && !snapshotted {
                    let s_att = att.export_secret_snapshot().unwrap();
                    let s_def = def.export_secret_snapshot().unwrap();
                    *att = ClientEngine::restore_secret_snapshot(&s_att).unwrap();
                    *def = ClientEngine::restore_secret_snapshot(&s_def).unwrap();
                    snapshotted = true;
                }
                let st = att.state();
                let cell = st
                    .opponent_board
                    .iter()
                    .position(|s| s == "unknown")
                    .unwrap() as u8;
                let shot_step = att.fire_shot_index(cell).unwrap();
                let recv_step = def
                    .accept_frame_with_rng(&shot_step.outgoing_frames[0], &mut rng)
                    .unwrap();
                let ans_step = att
                    .accept_frame_with_rng(&recv_step.outgoing_frames[0], &mut rng)
                    .unwrap();
                turn += 1;
                if ans_step.winner.is_some() {
                    break;
                }
            }

            let final_a = ca.state();
            let final_b = cb.state();
            assert_eq!(final_a.phase, "finished");
            assert_eq!(final_b.phase, "finished");
            assert_eq!(final_a.winner, final_b.winner);
            assert!(
                final_a.opponent_sunk_ships.len() == K || final_b.opponent_sunk_ships.len() == K
            );

            let t_a = ca.export_public_transcript();
            let report = verify_transcript_dto(
                t_a.hello_a.as_deref().unwrap(),
                t_a.hello_b.as_deref().unwrap(),
                &t_a.frames,
            )
            .unwrap();
            assert_eq!(report.verdict, "completed");
            assert_eq!(report.winner, final_a.winner);
        }
    }

    #[test]
    fn peer_pinning_and_attributable_evidence_work() {
        let mut rng = ChaCha20Rng::from_seed([0x77; 32]);
        let wrong_pk = IdentityKeypair::from_seed(&[0x99; 32])
            .peer_key()
            .fingerprint_hex();
        let mut ca = ClientEngine::new_with_rng(
            "standard",
            &sample_ships_a(),
            Some(&[0x11; 32]),
            Some(&wrong_pk),
            &mut rng,
        )
        .unwrap();
        let cb = ClientEngine::new_with_rng(
            "standard",
            &sample_ships_b(),
            Some(&[0x22; 32]),
            None,
            &mut rng,
        )
        .unwrap();
        let err = ca.accept_peer_hello(&cb.hello_bytes()).unwrap_err();
        assert_eq!(err.kind, "peer_auth");

        // Now connect properly and test Class-A evidence capture.
        let mut ca = ClientEngine::new_with_rng(
            "standard",
            &sample_ships_a(),
            Some(&[0x11; 32]),
            None,
            &mut rng,
        )
        .unwrap();
        let ba = ca.accept_peer_hello(&cb.hello_bytes()).unwrap();
        let mut cb = cb;
        let _bb = cb.accept_peer_hello(&ca.hello_bytes()).unwrap();
        if !ba.outgoing_frames.is_empty() {
            ca.accept_frame(ba.outgoing_frames[0].as_slice())
                .unwrap_err(); // Class-B self frame
        }
        // Have Role A craft an invalid Shot at sequence 1 to test Class-A evidence capture.
        let (target, cheater_seed) = if ca.state().local_role.as_deref() == Some("A") {
            (&mut cb, [0x11; 32])
        } else {
            (&mut ca, [0x22; 32])
        };
        let kp_other = IdentityKeypair::from_seed(&cheater_seed);
        let st = target.state();
        let sid_bytes = decode_hex_32(st.sid.as_deref().unwrap(), "sid").unwrap();
        let gen_bytes = decode_hex_32(st.genesis_hash.as_deref().unwrap(), "gen").unwrap();
        let bad_shot = SignedFrame::craft(
            &kp_other,
            &sid_bytes,
            Role::A,
            1,
            MessageType::Shot,
            &gen_bytes,
            vec![0],
        );
        let err = target.accept_frame(bad_shot.bytes()).unwrap_err();
        assert_eq!(err.kind, "attributable");
        assert!(err.evidence_frame.is_some());
        assert_eq!(target.state().phase, "aborted");
        assert!(target.export_public_transcript().evidence_frame.is_some());
    }

    #[test]
    fn pre_bootstrap_abort_works_cleanly() {
        let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
        let mut c = ClientEngine::new_with_rng("no-touch", &sample_ships_a(), None, None, &mut rng)
            .unwrap();
        let hello = c.hello_bytes();
        let state = c.abort(Some("cancelled before peer joined"));
        assert_eq!(state.phase, "aborted");
        assert_eq!(
            state.finish_reason.as_deref(),
            Some("cancelled before peer joined")
        );
        assert_eq!(c.export_public_transcript().hello_a, Some(hello));
    }

    #[test]
    fn restored_snapshot_is_bound_to_hello_bootstrap() {
        let mut rng = ChaCha20Rng::from_seed([0x31; 32]);
        let mut ca = ClientEngine::new_with_rng(
            "standard",
            &sample_ships_a(),
            Some(&[0x11; 32]),
            None,
            &mut rng,
        )
        .unwrap();
        let mut cb = ClientEngine::new_with_rng(
            "standard",
            &sample_ships_b(),
            Some(&[0x22; 32]),
            None,
            &mut rng,
        )
        .unwrap();
        let ha = ca.hello_bytes();
        let hb = cb.hello_bytes();
        ca.accept_peer_hello_with_rng(&hb, &mut rng).unwrap();
        cb.accept_peer_hello_with_rng(&ha, &mut rng).unwrap();

        // Role B has no local frame yet, so changing the embedded session id
        // would otherwise restore cleanly despite disagreeing with the Hellos.
        let client = if ca.state().local_role.as_deref() == Some("B") {
            &ca
        } else {
            &cb
        };
        let mut snapshot = client.export_secret_snapshot().unwrap();
        let expected_peer_flag = 8 + 1 + 32 + 2 * Hello::LEN;
        assert_eq!(snapshot[expected_peer_flag], 0);
        let session_start = expected_peer_flag + 1 + 4;
        let session_sid = session_start + 8 + 1 + 1 + 32;
        snapshot[session_sid] ^= 1;

        let err = match ClientEngine::restore_secret_snapshot(&snapshot) {
            Ok(_) => panic!("tampered snapshot unexpectedly restored"),
            Err(err) => err,
        };
        assert_eq!(err.kind, "invalid_input");
        assert!(err.message.contains("Hello bootstrap"));
    }
}
