//! Session driver. Message order: A Commit, B Commit (only after A's proof verifies),
//! CoinCommit, CoinNonce, CoinReveal, then Shot/Answer alternating. At every nonterminal
//! chain position exactly one sender is expected; ordinary messages and `Resign` are accepted
//! only from it, so each chain position has one legitimate successor. To give up off-turn,
//! close the transport (class C).
//!
//! Error classes: A [`SessionError::Attributable`] = chain-extending, validly signed frame with
//! invalid content (session aborts, secrets erased, offending frame retained);
//! B [`SessionError::ClassB`] = non-extending/replayed/unauthenticated/corrupt, never evidence,
//! state unchanged; C timeout/silence is deliberately not representable, since a two-party
//! transcript cannot attribute silence (paper Construction 7.1, S7, and Section 10);
//! D [`SessionError::InternalInvariant`] = implementation incident.

use crate::codec::{CodecError, MessageType, MAX_FRAME_SIZE, MAX_TRANSCRIPT_FRAMES};
use crate::coin;
use crate::frame::{self, AuthenticatedFrame, ChainError, ChainExpectation, SignedFrame};
use crate::hello::SessionBootstrap;
use crate::identity::{AuthenticatedPeer, IdentityKeypair};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand_core::{CryptoRng, OsRng, RngCore};
use std::fmt;
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroizing;
use zkb_core::answers::{self, AnswerContext, AnswerDecodeError, AnswerRejection, ShotAnswer};
use zkb_core::fleet::{Fleet, SHIP_BITS};
use zkb_core::game::{Game, GameContext, GameError, Role, ShotOutcome, State as GameState};
use zkb_core::params::{CellIndex, Parameters, Rules, K};
use zkb_core::setup::{self, SetupError, SetupMessage, VerifiedSetup};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClassBReason {
    Malformed(CodecError),
    WrongSession,
    WrongSequence { expected: u64, actual: u64 },
    WrongPrevHash,
    BadSignature,
}

impl fmt::Display for ClassBReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClassBReason::Malformed(e) => write!(f, "malformed frame: {e}"),
            ClassBReason::WrongSession => write!(f, "frame belongs to a different session"),
            ClassBReason::WrongSequence { expected, actual } => {
                write!(f, "frame sequence {actual}, expected {expected}")
            }
            ClassBReason::WrongPrevHash => {
                write!(f, "frame prev_hash does not match the chain head")
            }
            ClassBReason::BadSignature => write!(f, "frame signature does not verify"),
        }
    }
}

#[derive(Debug)]
pub enum Violation {
    SenderRoleMismatch { claimed: u8 },
    UnexpectedMessage { message_type: MessageType },
    OutOfTurnResign,
    InvalidCommit(SetupError),
    InvalidAnswerEncoding(AnswerDecodeError),
    InvalidAnswer(AnswerRejection),
    InvalidShot(GameError),
    BadCoinReveal,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Violation::SenderRoleMismatch { claimed } => {
                write!(f, "frame claims impossible sender-role byte {claimed}")
            }
            Violation::UnexpectedMessage { message_type } => {
                write!(
                    f,
                    "unexpected {message_type:?} in the current session state"
                )
            }
            Violation::OutOfTurnResign => write!(f, "out-of-turn resign"),
            Violation::InvalidCommit(e) => write!(f, "invalid commit: {e}"),
            Violation::InvalidAnswerEncoding(e) => write!(f, "invalid answer encoding: {e}"),
            Violation::InvalidAnswer(e) => write!(f, "invalid answer: {e}"),
            Violation::InvalidShot(e) => write!(f, "invalid shot: {e}"),
            Violation::BadCoinReveal => write!(f, "coin reveal does not match the commitment"),
        }
    }
}

#[derive(Debug)]
pub struct AttributableViolation {
    pub frame: SignedFrame,
    pub violation: Violation,
}

#[derive(Debug)]
pub enum SessionError {
    ClassB(ClassBReason),
    Attributable(Box<AttributableViolation>),
    InternalInvariant(&'static str),
    /// Local API misuse.
    WrongLocalState(&'static str),
    LocalGame(GameError),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::ClassB(e) => write!(f, "class-B input: {e}"),
            SessionError::Attributable(e) => {
                write!(f, "attributable peer violation: {}", e.violation)
            }
            SessionError::InternalInvariant(m) => write!(f, "internal invariant failure: {m}"),
            SessionError::WrongLocalState(m) => write!(f, "wrong local state: {m}"),
            SessionError::LocalGame(e) => write!(f, "invalid local game data: {e}"),
        }
    }
}

impl std::error::Error for SessionError {}

#[derive(Debug)]
pub enum AcceptOutcome {
    CommitVerified,
    CoinProgress,
    GameReady {
        first_mover: Role,
    },
    /// Carries the `Answer` frame to send.
    ShotReceived {
        cell: CellIndex,
        hit: bool,
        answer: SignedFrame,
        /// `Some` when this answer concedes the T-th hit; `answer` is then the final frame.
        winner: Option<Role>,
    },
    Answer(ShotOutcome),
    GameFinished {
        winner: Role,
    },
    PeerResigned,
}

#[derive(Clone, Copy, Debug)]
struct ChainHead {
    sequence: u64,
    hash: [u8; 32],
}

#[derive(Default)]
// Clone only for the fuzz harness's verified-fixture snapshots.
#[cfg_attr(fuzzing, derive(Clone))]
struct OwnBoard {
    ship_cells: Option<Vec<RistrettoPoint>>,
    fleet: Option<Fleet>,
    rho: Option<Zeroizing<Vec<Scalar>>>,
    /// Keys the not-sunk proof nonces; drawn when the setup is sent.
    answer_seed: Option<Zeroizing<[u8; 32]>>,
}

impl OwnBoard {
    fn take(&mut self) -> OwnBoard {
        std::mem::take(self)
    }
}

#[cfg_attr(fuzzing, derive(Clone))]
struct CommitPhase {
    a_done: bool,
    b_done: bool,
    own: OwnBoard,
    peer_verified: Option<VerifiedSetup>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoinStep {
    Commit,
    Nonce,
    Reveal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseKind {
    Commit,
    Coin,
    Playing,
    Finished,
    Aborted,
}

#[cfg_attr(fuzzing, derive(Clone))]
struct CoinPhase<'a> {
    step: CoinStep,
    coin_commit: Option<[u8; 32]>,
    r_a: Option<Zeroizing<[u8; 32]>>,
    r_b: Option<[u8; 32]>,
    own: OwnBoard,
    peer_verified: Option<VerifiedSetup>,
    game: Option<Game<'a>>,
}

#[cfg_attr(fuzzing, derive(Clone))]
enum Phase<'a> {
    Commit(Box<CommitPhase>),
    Coin(Box<CoinPhase<'a>>),
    Playing(Box<Game<'a>>),
    /// Board secrets dropped.
    Aborted,
    /// Retains the game for its public tallies; `Game` already dropped its secrets.
    Finished {
        winner: Role,
        game: Option<Box<Game<'a>>>,
    },
}

enum Transition {
    ToCoin,
    ToPlaying,
    Finished { winner: Role },
}

#[cfg_attr(fuzzing, derive(Clone))]
enum KeypairRef<'a> {
    Borrowed(&'a IdentityKeypair),
    Owned(Box<IdentityKeypair>),
}

impl<'a> KeypairRef<'a> {
    fn as_ref(&self) -> &IdentityKeypair {
        match self {
            KeypairRef::Borrowed(kp) => kp,
            KeypairRef::Owned(kp) => kp,
        }
    }
}

/// One local player's view.
#[cfg_attr(fuzzing, derive(Clone))]
pub struct Session<'a> {
    params: &'a Parameters,
    keypair: KeypairRef<'a>,
    local_role: Role,
    peer: AuthenticatedPeer,
    sid: [u8; 32],
    genesis_hash: [u8; 32],
    head: ChainHead,
    first_mover: Option<Role>,
    phase: Phase<'a>,
    transcript: Vec<Vec<u8>>,
}

fn craft_next(
    keypair: &IdentityKeypair,
    sid: &[u8; 32],
    local_role: Role,
    head: &mut ChainHead,
    transcript: &mut Vec<Vec<u8>>,
    message_type: MessageType,
    payload: Vec<u8>,
) -> SignedFrame {
    let frame = SignedFrame::craft(
        keypair,
        sid,
        local_role,
        head.sequence + 1,
        message_type,
        &head.hash,
        payload,
    );
    head.sequence += 1;
    head.hash = frame.frame_hash();
    transcript.push(frame.bytes().to_vec());
    frame
}

fn advance_chain(head: &mut ChainHead, transcript: &mut Vec<Vec<u8>>, frame: &AuthenticatedFrame) {
    debug_assert_eq!(frame.frame().header().sequence, head.sequence + 1);
    head.sequence += 1;
    head.hash = frame.frame().frame_hash();
    transcript.push(frame.frame().bytes().to_vec());
}

fn attributable(frame: AuthenticatedFrame, violation: Violation) -> SessionError {
    SessionError::Attributable(Box::new(AttributableViolation {
        frame: frame.into_frame(),
        violation,
    }))
}

fn game_context(
    keypair: &IdentityKeypair,
    peer: &AuthenticatedPeer,
    sid: &[u8; 32],
) -> GameContext {
    GameContext {
        own_id: *keypair.peer_key().as_bytes(),
        peer_id: *peer.key().as_bytes(),
        sid: *sid,
    }
}

fn build_game<'a>(
    params: &'a Parameters,
    local_role: Role,
    first_mover: Role,
    ctx: GameContext,
    own: &mut OwnBoard,
    peer_verified: &mut Option<VerifiedSetup>,
) -> Result<Game<'a>, SessionError> {
    let fleet = own.fleet.take().expect("witness present until game build");
    let mut rho = own.rho.take().expect("witness present until game build");
    let seed = own
        .answer_seed
        .take()
        .expect("seed drawn with the local commit");
    let ship_cells = own.ship_cells.take().expect("local commit produced");
    let peer = peer_verified.take().expect("peer commit verified");
    Game::new(
        params,
        local_role,
        first_mover,
        ctx,
        ship_cells,
        &fleet,
        std::mem::take(&mut *rho),
        &seed,
        peer,
    )
    .map_err(|_| SessionError::InternalInvariant("validated board could not initialize game"))
}

impl<'a> Session<'a> {
    /// `fleet`, `rho`: secret fleet and fresh ship-cell blinders, moved in and zeroized on
    /// drop.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        params: &'a Parameters,
        keypair: &'a IdentityKeypair,
        local_role: Role,
        peer: AuthenticatedPeer,
        sid: [u8; 32],
        genesis_hash: [u8; 32],
        fleet: Fleet,
        rho: Vec<Scalar>,
    ) -> Result<Session<'a>, SessionError> {
        Self::new_with_keypair(
            params,
            KeypairRef::Borrowed(keypair),
            local_role,
            peer,
            sid,
            genesis_hash,
            fleet,
            rho,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_keypair(
        params: &'a Parameters,
        keypair: KeypairRef<'a>,
        local_role: Role,
        peer: AuthenticatedPeer,
        sid: [u8; 32],
        genesis_hash: [u8; 32],
        fleet: Fleet,
        rho: Vec<Scalar>,
    ) -> Result<Session<'a>, SessionError> {
        if keypair.as_ref().peer_key() == *peer.key() {
            return Err(SessionError::WrongLocalState(
                "local identity key must differ from peer key",
            ));
        }
        let rho = Zeroizing::new(rho);
        if rho.len() != SHIP_BITS {
            return Err(SessionError::LocalGame(GameError::WrongWitnessLength {
                expected: SHIP_BITS,
                actual: rho.len(),
            }));
        }
        Fleet::new(*fleet.ships(), params.rules())
            .map_err(GameError::IllegalPlacement)
            .map_err(SessionError::LocalGame)?;
        Ok(Session {
            params,
            keypair,
            local_role,
            peer,
            sid,
            genesis_hash,
            head: ChainHead {
                sequence: 0,
                hash: genesis_hash,
            },
            first_mover: None,
            phase: Phase::Commit(Box::new(CommitPhase {
                a_done: false,
                b_done: false,
                own: OwnBoard {
                    ship_cells: None,
                    fleet: Some(fleet),
                    rho: Some(rho),
                    answer_seed: None,
                },
                peer_verified: None,
            })),
            transcript: Vec::new(),
        })
    }

    /// Variant of [`Session::new`] that takes ownership of `keypair`, yielding `'static`
    /// when `params` is `'static` (useful for FFI/WASM hosts).
    #[allow(clippy::too_many_arguments)]
    pub fn new_owned(
        params: &'a Parameters,
        keypair: IdentityKeypair,
        local_role: Role,
        peer: AuthenticatedPeer,
        sid: [u8; 32],
        genesis_hash: [u8; 32],
        fleet: Fleet,
        rho: Vec<Scalar>,
    ) -> Result<Session<'a>, SessionError> {
        Self::new_with_keypair(
            params,
            KeypairRef::Owned(Box::new(keypair)),
            local_role,
            peer,
            sid,
            genesis_hash,
            fleet,
            rho,
        )
    }

    pub fn from_bootstrap(
        params: &'a Parameters,
        keypair: &'a IdentityKeypair,
        bootstrap: &SessionBootstrap,
        peer: AuthenticatedPeer,
        fleet: Fleet,
        rho: Vec<Scalar>,
    ) -> Result<Session<'a>, SessionError> {
        let (local_role, sid, genesis_hash) =
            validate_bootstrap(params, keypair, bootstrap, &peer)?;
        Session::new(
            params,
            keypair,
            local_role,
            peer,
            sid,
            genesis_hash,
            fleet,
            rho,
        )
    }

    pub fn from_bootstrap_owned(
        params: &'a Parameters,
        keypair: IdentityKeypair,
        bootstrap: &SessionBootstrap,
        peer: AuthenticatedPeer,
        fleet: Fleet,
        rho: Vec<Scalar>,
    ) -> Result<Session<'a>, SessionError> {
        let (local_role, sid, genesis_hash) =
            validate_bootstrap(params, &keypair, bootstrap, &peer)?;
        Session::new_owned(
            params,
            keypair,
            local_role,
            peer,
            sid,
            genesis_hash,
            fleet,
            rho,
        )
    }

    pub fn params(&self) -> &'a Parameters {
        self.params
    }

    pub fn keypair(&self) -> &IdentityKeypair {
        self.keypair.as_ref()
    }

    pub fn peer(&self) -> &AuthenticatedPeer {
        &self.peer
    }

    pub fn sid(&self) -> &[u8; 32] {
        &self.sid
    }

    pub fn genesis_hash(&self) -> &[u8; 32] {
        &self.genesis_hash
    }

    pub fn local_role(&self) -> Role {
        self.local_role
    }

    pub fn first_mover(&self) -> Option<Role> {
        self.first_mover
    }

    /// Packed `[u8; 3 * K]` fleet encoding while board secrets are still held.
    pub fn own_fleet_bytes(&self) -> Option<Zeroizing<[u8; 3 * K]>> {
        match &self.phase {
            Phase::Commit(cp) => cp.own.fleet.as_ref().map(Fleet::to_bytes),
            Phase::Coin(cp) => cp
                .game
                .as_ref()
                .and_then(|g| g.snapshot_secrets().map(|s| Zeroizing::new(s.fleet_bytes)))
                .or_else(|| cp.own.fleet.as_ref().map(Fleet::to_bytes)),
            Phase::Playing(game) => game
                .snapshot_secrets()
                .map(|s| Zeroizing::new(s.fleet_bytes)),
            Phase::Finished { .. } | Phase::Aborted => None,
        }
    }

    pub fn phase_kind(&self) -> PhaseKind {
        match &self.phase {
            Phase::Commit(_) => PhaseKind::Commit,
            Phase::Coin(_) => PhaseKind::Coin,
            Phase::Playing(_) => PhaseKind::Playing,
            Phase::Finished { .. } => PhaseKind::Finished,
            Phase::Aborted => PhaseKind::Aborted,
        }
    }

    pub fn needs_produce(&self) -> bool {
        if self.expected_sender() != Some(self.local_role) {
            return false;
        }
        matches!(self.phase, Phase::Commit(_) | Phase::Coin(_))
    }

    pub fn can_fire_shot(&self) -> bool {
        matches!(
            &self.phase,
            Phase::Playing(g)
                if matches!(g.state(), GameState::AwaitingShot { shooter } if shooter == self.local_role)
        )
    }

    pub fn head_sequence(&self) -> u64 {
        self.head.sequence
    }

    pub fn head_hash(&self) -> &[u8; 32] {
        &self.head.hash
    }

    /// Accepted and produced frames in chain order, byte-for-byte.
    pub fn transcript(&self) -> &[Vec<u8>] {
        &self.transcript
    }

    pub fn winner(&self) -> Option<Role> {
        match &self.phase {
            Phase::Finished { winner, .. } => Some(*winner),
            _ => None,
        }
    }

    /// Remains available after finish (public tallies only).
    pub fn game(&self) -> Option<&Game<'a>> {
        match &self.phase {
            Phase::Playing(game) => Some(game),
            Phase::Coin(cp) => cp.game.as_ref(),
            Phase::Finished { game, .. } => game.as_deref(),
            Phase::Commit(_) | Phase::Aborted => None,
        }
    }

    /// An abort assigns no winner.
    pub fn is_aborted(&self) -> bool {
        matches!(self.phase, Phase::Aborted)
    }

    /// Erases board secrets, keeps the public transcript; for disconnects/timeouts. Not evidence.
    pub fn abort(&mut self) {
        if !matches!(self.phase, Phase::Finished { .. }) {
            self.phase = Phase::Aborted;
        }
    }

    fn abort_on_failure<T>(&mut self, result: &Result<T, SessionError>) {
        if matches!(
            result,
            Err(SessionError::Attributable(_) | SessionError::InternalInvariant(_))
        ) {
            self.abort();
        }
    }

    pub fn expected_sender(&self) -> Option<Role> {
        match &self.phase {
            Phase::Commit(cp) => Some(if cp.a_done { Role::B } else { Role::A }),
            Phase::Coin(cp) => Some(match cp.step {
                CoinStep::Commit => Role::A,
                CoinStep::Nonce => Role::B,
                CoinStep::Reveal => Role::A,
            }),
            Phase::Playing(game) => match game.state() {
                GameState::AwaitingShot { shooter } => Some(shooter),
                GameState::AwaitingAnswer { shooter, .. } => Some(shooter.other()),
                GameState::Finished { .. } => None,
            },
            Phase::Finished { .. } | Phase::Aborted => None,
        }
    }

    fn enter_coin_phase(&mut self) {
        let Phase::Commit(cp) = &mut self.phase else {
            return;
        };
        let own = cp.own.take();
        let peer_verified = cp.peer_verified.take().expect("both commits verified");
        self.phase = Phase::Coin(Box::new(CoinPhase {
            step: CoinStep::Commit,
            coin_commit: None,
            r_a: None,
            r_b: None,
            own,
            peer_verified: Some(peer_verified),
            game: None,
        }));
    }

    fn enter_playing_phase(&mut self) {
        let Phase::Coin(cp) = &mut self.phase else {
            return;
        };
        let game = cp.game.take().expect("game built before play");
        self.phase = Phase::Playing(Box::new(game));
    }

    fn finish(&mut self, winner: Role) {
        let previous = std::mem::replace(&mut self.phase, Phase::Finished { winner, game: None });
        let mut game = match previous {
            Phase::Playing(game) => Some(game),
            Phase::Coin(cp) => cp.game.map(Box::new),
            Phase::Commit(_) | Phase::Finished { .. } | Phase::Aborted => None,
        };
        if let Some(game) = &mut game {
            if !matches!(game.state(), GameState::Finished { .. }) {
                game.finish_by_forfeit(winner)
                    .expect("live game can finish by forfeit");
            }
        }
        self.phase = Phase::Finished { winner, game };
    }

    /// Next protocol-fixed message owed (Commit or a coin message), `None` while waiting.
    /// Shots go through [`Session::fire_shot`].
    pub fn produce<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Option<SignedFrame>, SessionError> {
        self.produce_with_rng(rng, OsRng)
    }

    /// Injected proof-finalization RNG, for deterministic vectors only; never in production.
    pub fn produce_with_rng<R: RngCore + CryptoRng, F: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        proof_finalize_rng: F,
    ) -> Result<Option<SignedFrame>, SessionError> {
        let result = self.produce_inner(rng, proof_finalize_rng);
        self.abort_on_failure(&result);
        result
    }

    fn produce_inner<R: RngCore + CryptoRng, F: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        proof_finalize_rng: F,
    ) -> Result<Option<SignedFrame>, SessionError> {
        let commit_turn = matches!(&self.phase, Phase::Commit(cp) if {
            let expected = if cp.a_done { Role::B } else { Role::A };
            expected == self.local_role
        });
        if commit_turn {
            let msg = {
                let Phase::Commit(cp) = &self.phase else {
                    unreachable!()
                };
                let fleet = cp.own.fleet.as_ref().expect("witness present");
                let rho = cp.own.rho.as_ref().expect("witness present");
                setup::prove_with_rng(
                    self.params,
                    self.keypair.as_ref().peer_key().as_bytes(),
                    &self.sid,
                    fleet,
                    rho.as_slice(),
                    proof_finalize_rng,
                )
                .map_err(|_| {
                    SessionError::InternalInvariant("local prover refused its validated witness")
                })?
            };
            let payload = msg.encode();
            let mut answer_seed = Zeroizing::new([0u8; 32]);
            rng.fill_bytes(&mut *answer_seed);
            let frame = craft_next(
                self.keypair.as_ref(),
                &self.sid,
                self.local_role,
                &mut self.head,
                &mut self.transcript,
                MessageType::Commit,
                payload,
            );
            let mut to_coin = false;
            if let Phase::Commit(cp) = &mut self.phase {
                cp.own.ship_cells = Some(msg.ship_cells);
                cp.own.answer_seed = Some(answer_seed);
                match self.local_role {
                    Role::A => cp.a_done = true,
                    Role::B => cp.b_done = true,
                }
                to_coin = cp.a_done && cp.b_done;
            }
            if to_coin {
                self.enter_coin_phase();
            }
            return Ok(Some(frame));
        }

        let coin_action = match &mut self.phase {
            Phase::Coin(cp) => match cp.step {
                CoinStep::Commit if self.local_role == Role::A => {
                    let r_a = Zeroizing::new(coin::sample_nonce(rng));
                    let commitment = coin::coin_commit(&self.sid, &r_a);
                    cp.r_a = Some(r_a);
                    cp.coin_commit = Some(commitment);
                    cp.step = CoinStep::Nonce;
                    Some((MessageType::CoinCommit, commitment.to_vec()))
                }
                CoinStep::Nonce if self.local_role == Role::B => {
                    let r_b = coin::sample_nonce(rng);
                    cp.r_b = Some(r_b);
                    cp.step = CoinStep::Reveal;
                    Some((MessageType::CoinNonce, r_b.to_vec()))
                }
                CoinStep::Reveal if self.local_role == Role::A => {
                    let r_a = cp.r_a.take().expect("A sampled r_A");
                    Some((MessageType::CoinReveal, r_a.to_vec()))
                }
                _ => None,
            },
            _ => None,
        };
        if let Some((message_type, payload)) = coin_action {
            let frame = craft_next(
                self.keypair.as_ref(),
                &self.sid,
                self.local_role,
                &mut self.head,
                &mut self.transcript,
                message_type,
                payload,
            );
            if message_type == MessageType::CoinReveal {
                self.enter_playing_phase();
            }
            return Ok(Some(frame));
        }
        Ok(None)
    }

    pub fn fire_shot(&mut self, cell: CellIndex) -> Result<SignedFrame, SessionError> {
        let Phase::Playing(game) = &mut self.phase else {
            return Err(SessionError::WrongLocalState("no game in progress"));
        };
        let byte = game.fire_shot(cell).map_err(SessionError::LocalGame)?;
        Ok(craft_next(
            self.keypair.as_ref(),
            &self.sid,
            self.local_role,
            &mut self.head,
            &mut self.transcript,
            MessageType::Shot,
            vec![byte],
        ))
    }

    /// Only while the local player is the expected next sender; otherwise close the transport.
    pub fn resign(&mut self) -> Result<SignedFrame, SessionError> {
        if self.expected_sender() != Some(self.local_role) {
            return Err(SessionError::WrongLocalState(
                "not the expected next sender; close the transport instead of an out-of-turn Resign",
            ));
        }
        let frame = craft_next(
            self.keypair.as_ref(),
            &self.sid,
            self.local_role,
            &mut self.head,
            &mut self.transcript,
            MessageType::Resign,
            Vec::new(),
        );
        self.finish(self.local_role.other());
        Ok(frame)
    }

    /// Structural parse, then chain gate (class B), then role/semantic checks (attributable).
    /// Attributable and internal failures abort the session permanently.
    pub fn accept(&mut self, bytes: &[u8]) -> Result<AcceptOutcome, SessionError> {
        if self.is_aborted() {
            return Err(SessionError::WrongLocalState("session has aborted"));
        }
        let result = self.accept_inner(bytes);
        self.abort_on_failure(&result);
        result
    }

    fn accept_inner(&mut self, bytes: &[u8]) -> Result<AcceptOutcome, SessionError> {
        let frame = SignedFrame::decode(bytes)
            .map_err(|e| SessionError::ClassB(ClassBReason::Malformed(e)))?;
        let expectation = ChainExpectation {
            sid: self.sid,
            sequence: self.head.sequence + 1,
            prev_hash: self.head.hash,
        };
        let frame = frame.authenticate(&expectation, &self.peer).map_err(|e| {
            SessionError::ClassB(match e {
                ChainError::WrongSession => ClassBReason::WrongSession,
                ChainError::WrongSequence { expected, actual } => {
                    ClassBReason::WrongSequence { expected, actual }
                }
                ChainError::WrongPrevHash => ClassBReason::WrongPrevHash,
                ChainError::BadSignature => ClassBReason::BadSignature,
            })
        })?;
        let claimed = frame.frame().header().sender_role;
        if claimed != frame::role_to_byte(self.local_role.other()) {
            return Err(attributable(
                frame,
                Violation::SenderRoleMismatch { claimed },
            ));
        }
        self.accept_authenticated(frame)
    }

    fn accept_authenticated(
        &mut self,
        frame: AuthenticatedFrame,
    ) -> Result<AcceptOutcome, SessionError> {
        let sender = self.local_role.other();
        let message_type = frame.frame().header().message_type;

        if message_type == MessageType::Resign {
            if self.expected_sender() == Some(sender) {
                advance_chain(&mut self.head, &mut self.transcript, &frame);
                self.finish(self.local_role);
                return Ok(AcceptOutcome::PeerResigned);
            }
            return Err(attributable(frame, Violation::OutOfTurnResign));
        }

        let mut transition: Option<Transition> = None;
        let outcome = match &mut self.phase {
            Phase::Commit(cp) => {
                let expected = if cp.a_done { Role::B } else { Role::A };
                if message_type != MessageType::Commit || expected != sender {
                    return Err(attributable(
                        frame,
                        Violation::UnexpectedMessage { message_type },
                    ));
                }
                let payload = frame.frame().payload();
                let verified = (|| -> Result<VerifiedSetup, SetupError> {
                    let msg = SetupMessage::decode(payload, self.params.rules())?;
                    setup::verify(self.params, self.peer.key().as_bytes(), &self.sid, &msg)
                })();
                let verified = match verified {
                    Ok(v) => v,
                    Err(e) => return Err(attributable(frame, Violation::InvalidCommit(e))),
                };
                match sender {
                    Role::A => cp.a_done = true,
                    Role::B => cp.b_done = true,
                }
                cp.peer_verified = Some(verified);
                advance_chain(&mut self.head, &mut self.transcript, &frame);
                if cp.a_done && cp.b_done {
                    transition = Some(Transition::ToCoin);
                }
                Ok(AcceptOutcome::CommitVerified)
            }
            Phase::Coin(cp) => match (cp.step, message_type, sender) {
                (CoinStep::Commit, MessageType::CoinCommit, Role::A) => {
                    let commitment: [u8; 32] = frame
                        .frame()
                        .payload()
                        .try_into()
                        .expect("payload length checked structurally");
                    cp.coin_commit = Some(commitment);
                    cp.step = CoinStep::Nonce;
                    advance_chain(&mut self.head, &mut self.transcript, &frame);
                    Ok(AcceptOutcome::CoinProgress)
                }
                (CoinStep::Nonce, MessageType::CoinNonce, Role::B) => {
                    let r_b: [u8; 32] = frame
                        .frame()
                        .payload()
                        .try_into()
                        .expect("payload length checked structurally");
                    cp.r_b = Some(r_b);
                    cp.step = CoinStep::Reveal;
                    let mut outcome = AcceptOutcome::CoinProgress;
                    if self.local_role == Role::A {
                        let r_a = cp.r_a.as_ref().expect("A sampled r_A");
                        let first_mover = coin::first_mover(&self.sid, r_a, &r_b);
                        self.first_mover = Some(first_mover);
                        let game = build_game(
                            self.params,
                            self.local_role,
                            first_mover,
                            game_context(self.keypair.as_ref(), &self.peer, &self.sid),
                            &mut cp.own,
                            &mut cp.peer_verified,
                        )?;
                        cp.game = Some(game);
                        outcome = AcceptOutcome::GameReady { first_mover };
                    }
                    advance_chain(&mut self.head, &mut self.transcript, &frame);
                    Ok(outcome)
                }
                (CoinStep::Reveal, MessageType::CoinReveal, Role::A) => {
                    let r_a: [u8; 32] = frame
                        .frame()
                        .payload()
                        .try_into()
                        .expect("payload length checked structurally");
                    let commitment = cp.coin_commit.as_ref().expect("commitment received");
                    if !coin::verify_reveal(&self.sid, commitment, &r_a) {
                        return Err(attributable(frame, Violation::BadCoinReveal));
                    }
                    let first_mover = coin::first_mover(
                        &self.sid,
                        &r_a,
                        cp.r_b.as_ref().expect("nonce received"),
                    );
                    self.first_mover = Some(first_mover);
                    let game = build_game(
                        self.params,
                        self.local_role,
                        first_mover,
                        game_context(self.keypair.as_ref(), &self.peer, &self.sid),
                        &mut cp.own,
                        &mut cp.peer_verified,
                    )?;
                    cp.game = Some(game);
                    advance_chain(&mut self.head, &mut self.transcript, &frame);
                    transition = Some(Transition::ToPlaying);
                    Ok(AcceptOutcome::GameReady { first_mover })
                }
                _ => Err(attributable(
                    frame,
                    Violation::UnexpectedMessage { message_type },
                )),
            },
            Phase::Playing(game) => match message_type {
                MessageType::Shot => {
                    let expected = matches!(game.state(), GameState::AwaitingShot { shooter } if shooter == sender);
                    if !expected {
                        return Err(attributable(
                            frame,
                            Violation::UnexpectedMessage { message_type },
                        ));
                    }
                    let cell_byte = frame.frame().payload()[0];
                    if let Err(e) = game.receive_shot(cell_byte) {
                        return Err(attributable(frame, Violation::InvalidShot(e)));
                    }
                    let cell = CellIndex::from_index(cell_byte).expect("accepted shot is in range");
                    let answer = game.answer_shot().map_err(|_| {
                        SessionError::InternalInvariant("answer owed but not producible")
                    })?;
                    // Conceding the T-th hit finishes the defender here; the Answer is the final frame.
                    let winner = match game.state() {
                        GameState::Finished { winner } => Some(winner),
                        _ => None,
                    };
                    advance_chain(&mut self.head, &mut self.transcript, &frame);
                    let answer_frame = craft_next(
                        self.keypair.as_ref(),
                        &self.sid,
                        self.local_role,
                        &mut self.head,
                        &mut self.transcript,
                        MessageType::Answer,
                        answer.encode(),
                    );
                    if let Some(winner) = winner {
                        transition = Some(Transition::Finished { winner });
                    }
                    Ok(AcceptOutcome::ShotReceived {
                        cell,
                        hit: answer.is_hit(),
                        answer: answer_frame,
                        winner,
                    })
                }
                MessageType::Answer => {
                    let expected = matches!(game.state(), GameState::AwaitingAnswer { shooter, .. } if shooter == self.local_role);
                    if !expected {
                        return Err(attributable(
                            frame,
                            Violation::UnexpectedMessage { message_type },
                        ));
                    }
                    let decoded = match game.decode_answer(frame.frame().payload()) {
                        Ok(a) => a,
                        Err(e) => {
                            return Err(attributable(frame, Violation::InvalidAnswerEncoding(e)))
                        }
                    };
                    match game.accept_answer(&decoded) {
                        Err(GameError::AnswerRejected(r)) => {
                            Err(attributable(frame, Violation::InvalidAnswer(r)))
                        }
                        Err(GameError::InternalInvariantFailure(m)) => {
                            Err(SessionError::InternalInvariant(m))
                        }
                        Err(_) => Err(SessionError::InternalInvariant("unexpected game error")),
                        Ok(ShotOutcome::Win) => {
                            advance_chain(&mut self.head, &mut self.transcript, &frame);
                            transition = Some(Transition::Finished {
                                winner: self.local_role,
                            });
                            Ok(AcceptOutcome::GameFinished {
                                winner: self.local_role,
                            })
                        }
                        Ok(outcome) => {
                            advance_chain(&mut self.head, &mut self.transcript, &frame);
                            Ok(AcceptOutcome::Answer(outcome))
                        }
                    }
                }
                _ => Err(attributable(
                    frame,
                    Violation::UnexpectedMessage { message_type },
                )),
            },
            Phase::Aborted => Err(SessionError::WrongLocalState("session has aborted")),
            Phase::Finished { .. } => Err(attributable(
                frame,
                Violation::UnexpectedMessage { message_type },
            )),
        };

        match transition {
            Some(Transition::ToCoin) => self.enter_coin_phase(),
            Some(Transition::ToPlaying) => self.enter_playing_phase(),
            Some(Transition::Finished { winner }) => self.finish(winner),
            None => {}
        }
        outcome
    }

    /// Exports an active (non-finished, non-aborted) session and its secret
    /// state for crash/reload recovery. Caller must keep the bytes secret.
    pub fn export_snapshot(&self) -> Result<Zeroizing<Vec<u8>>, SessionError> {
        struct SnapshotParts {
            fleet_bytes: Zeroizing<[u8; 3 * K]>,
            rho: Zeroizing<Vec<Scalar>>,
            answer_seed: Option<Zeroizing<[u8; 32]>>,
            r_a: Option<Zeroizing<[u8; 32]>>,
        }
        let parts = match &self.phase {
            Phase::Commit(cp) => {
                let fleet = cp
                    .own
                    .fleet
                    .as_ref()
                    .ok_or(SessionError::InternalInvariant("missing fleet witness"))?;
                let rho = cp
                    .own
                    .rho
                    .as_ref()
                    .ok_or(SessionError::InternalInvariant("missing blinder witness"))?;
                SnapshotParts {
                    fleet_bytes: fleet.to_bytes(),
                    rho: rho.clone(),
                    answer_seed: cp.own.answer_seed.clone(),
                    r_a: None,
                }
            }
            Phase::Coin(cp) => {
                if let Some(game) = &cp.game {
                    let secrets =
                        game.snapshot_secrets()
                            .ok_or(SessionError::InternalInvariant(
                                "missing game secrets in coin phase",
                            ))?;
                    SnapshotParts {
                        fleet_bytes: Zeroizing::new(secrets.fleet_bytes),
                        rho: Zeroizing::new(secrets.rho.clone()),
                        answer_seed: Some(Zeroizing::new(secrets.answer_seed)),
                        r_a: cp.r_a.clone(),
                    }
                } else {
                    let fleet = cp
                        .own
                        .fleet
                        .as_ref()
                        .ok_or(SessionError::InternalInvariant("missing fleet witness"))?;
                    let rho = cp
                        .own
                        .rho
                        .as_ref()
                        .ok_or(SessionError::InternalInvariant("missing blinder witness"))?;
                    SnapshotParts {
                        fleet_bytes: fleet.to_bytes(),
                        rho: rho.clone(),
                        answer_seed: cp.own.answer_seed.clone(),
                        r_a: cp.r_a.clone(),
                    }
                }
            }
            Phase::Playing(game) => {
                let secrets = game
                    .snapshot_secrets()
                    .ok_or(SessionError::InternalInvariant(
                        "missing game secrets in playing phase",
                    ))?;
                SnapshotParts {
                    fleet_bytes: Zeroizing::new(secrets.fleet_bytes),
                    rho: Zeroizing::new(secrets.rho.clone()),
                    answer_seed: Some(Zeroizing::new(secrets.answer_seed)),
                    r_a: None,
                }
            }
            Phase::Finished { .. } | Phase::Aborted => {
                return Err(SessionError::WrongLocalState(
                    "finished or aborted session cannot be snapshotted",
                ));
            }
        };
        let SnapshotParts {
            fleet_bytes,
            rho,
            answer_seed,
            r_a,
        } = parts;
        if rho.len() != SHIP_BITS {
            return Err(SessionError::InternalInvariant(
                "corrupt snapshot rho length",
            ));
        }
        let mut out = Zeroizing::new(Vec::with_capacity(
            128 + 32 * SHIP_BITS + self.transcript.iter().map(|f| 4 + f.len()).sum::<usize>(),
        ));
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.push(match self.params.rules() {
            Rules::Standard => 0,
            Rules::NoTouch => 1,
        });
        out.push(frame::role_to_byte(self.local_role));
        out.extend_from_slice(self.peer.key().as_bytes());
        out.extend_from_slice(&self.sid);
        out.extend_from_slice(&self.genesis_hash);
        out.extend_from_slice(&*fleet_bytes);
        for s in rho.iter() {
            out.extend_from_slice(s.as_bytes());
        }
        match answer_seed {
            Some(seed) => {
                out.push(1);
                out.extend_from_slice(&*seed);
            }
            None => out.push(0),
        }
        match r_a {
            Some(nonce) => {
                out.push(1);
                out.extend_from_slice(&*nonce);
            }
            None => out.push(0),
        }
        let frame_count = u32::try_from(self.transcript.len())
            .map_err(|_| SessionError::InternalInvariant("transcript exceeds u32"))?;
        out.extend_from_slice(&frame_count.to_le_bytes());
        for raw in &self.transcript {
            let len = u32::try_from(raw.len())
                .map_err(|_| SessionError::InternalInvariant("frame exceeds u32"))?;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(raw);
        }
        Ok(out)
    }

    /// Restores an active [`Session`] from bytes produced by [`Session::export_snapshot`],
    /// taking ownership of `keypair`.
    pub fn restore_snapshot_owned(
        params: &'a Parameters,
        keypair: IdentityKeypair,
        peer: AuthenticatedPeer,
        snapshot: &[u8],
    ) -> Result<Session<'a>, SessionError> {
        Self::restore_snapshot_with_keypair(
            params,
            KeypairRef::Owned(Box::new(keypair)),
            peer,
            snapshot,
        )
    }

    /// Restores an active [`Session`] from bytes produced by [`Session::export_snapshot`],
    /// re-verifying signatures, setup proofs, coin flip, and play history.
    pub fn restore_snapshot(
        params: &'a Parameters,
        keypair: &'a IdentityKeypair,
        peer: AuthenticatedPeer,
        snapshot: &[u8],
    ) -> Result<Session<'a>, SessionError> {
        Self::restore_snapshot_with_keypair(params, KeypairRef::Borrowed(keypair), peer, snapshot)
    }

    fn restore_snapshot_with_keypair(
        params: &'a Parameters,
        keypair: KeypairRef<'a>,
        peer: AuthenticatedPeer,
        snapshot: &[u8],
    ) -> Result<Session<'a>, SessionError> {
        let mut cur = SnapshotReader::new(snapshot);
        if cur.take_array::<8>()? != *SNAPSHOT_MAGIC {
            return Err(SessionError::WrongLocalState("invalid snapshot header"));
        }
        let rules = match cur.take_u8()? {
            0 => Rules::Standard,
            1 => Rules::NoTouch,
            _ => return Err(SessionError::WrongLocalState("unknown snapshot rules")),
        };
        if rules != params.rules() {
            return Err(SessionError::WrongLocalState("snapshot rules mismatch"));
        }
        let local_role = frame::role_from_byte(cur.take_u8()?)
            .ok_or(SessionError::WrongLocalState("invalid snapshot role"))?;
        let peer_bytes = cur.take_array::<32>()?;
        if &peer_bytes != peer.key().as_bytes() {
            return Err(SessionError::WrongLocalState("snapshot peer key mismatch"));
        }
        let sid = cur.take_array::<32>()?;
        let genesis_hash = cur.take_array::<32>()?;
        let fleet_bytes = Zeroizing::new(cur.take_array::<{ 3 * K }>()?);
        let fleet = Fleet::from_bytes(&fleet_bytes, params.rules())
            .map_err(|e| SessionError::LocalGame(GameError::IllegalPlacement(e)))?;
        let mut rho = Zeroizing::new(Vec::with_capacity(SHIP_BITS));
        for _ in 0..SHIP_BITS {
            let scalar_bytes = cur.take_array::<32>()?;
            let s = Option::from(Scalar::from_canonical_bytes(scalar_bytes)).ok_or(
                SessionError::WrongLocalState("non-canonical scalar in snapshot"),
            )?;
            rho.push(s);
        }
        let answer_seed = match cur.take_u8()? {
            0 => None,
            1 => Some(Zeroizing::new(cur.take_array::<32>()?)),
            _ => {
                return Err(SessionError::WrongLocalState(
                    "invalid snapshot answer_seed flag",
                ))
            }
        };
        let mut r_a = match cur.take_u8()? {
            0 => None,
            1 => Some(Zeroizing::new(cur.take_array::<32>()?)),
            _ => return Err(SessionError::WrongLocalState("invalid snapshot r_a flag")),
        };
        let frame_count = cur.take_u32()? as usize;
        if frame_count > MAX_TRANSCRIPT_FRAMES {
            return Err(SessionError::WrongLocalState(
                "snapshot frame count out of bounds",
            ));
        }
        let mut frames = Vec::with_capacity(frame_count);
        for _ in 0..frame_count {
            let len = cur.take_u32()? as usize;
            if len > MAX_FRAME_SIZE {
                return Err(SessionError::WrongLocalState(
                    "snapshot frame exceeds max size",
                ));
            }
            frames.push(cur.take_slice(len)?);
        }
        if !cur.is_empty() {
            return Err(SessionError::WrongLocalState("trailing bytes in snapshot"));
        }

        // Precompute our own ship commitments to bind local Commit frames to the secret witness.
        let bits = fleet.ship_bits();
        let identity = RistrettoPoint::identity();
        let expected_ship_cells: Vec<RistrettoPoint> = (0..SHIP_BITS)
            .map(|k| {
                params.h_table() * &rho[k]
                    + RistrettoPoint::conditional_select(
                        &identity,
                        params.g(),
                        Choice::from(bits[k] & 1),
                    )
            })
            .collect();
        let own_cell_commitments = setup::cell_commitments(&expected_ship_cells);

        let own_key_pair = keypair.as_ref().peer_key();
        let own_auth = AuthenticatedPeer::from_policy_decision(own_key_pair);
        let mut session = Session::new_with_keypair(
            params,
            keypair,
            local_role,
            peer,
            sid,
            genesis_hash,
            fleet,
            rho.to_vec(),
        )?;
        let local_role_byte = frame::role_to_byte(local_role);

        // In Phase::Playing, r_a was consumed on CoinReveal; recover it from that public frame so
        // replaying CoinNonce/CoinReveal can verify the coin flip identically.
        let decoded_frames: Vec<SignedFrame> = frames
            .iter()
            .map(|raw| {
                SignedFrame::decode(raw)
                    .map_err(|_| SessionError::WrongLocalState("malformed frame in snapshot"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if r_a.is_none() && local_role == Role::A {
            for f in &decoded_frames {
                if f.header().message_type == MessageType::CoinReveal
                    && f.header().sender_role == local_role_byte
                {
                    let bytes: [u8; 32] = f
                        .payload()
                        .try_into()
                        .map_err(|_| SessionError::WrongLocalState("bad CoinReveal payload"))?;
                    r_a = Some(Zeroizing::new(bytes));
                    break;
                }
            }
        }

        for frame in decoded_frames {
            let expectation = ChainExpectation {
                sid: session.sid,
                sequence: session.head.sequence + 1,
                prev_hash: session.head.hash,
            };
            if frame.header().sender_role == local_role_byte {
                let auth = frame.authenticate(&expectation, &own_auth).map_err(|_| {
                    SessionError::WrongLocalState("snapshot local frame failed auth")
                })?;
                let msg_type = auth.frame().header().message_type;
                let payload = auth.frame().payload();
                match (&mut session.phase, msg_type) {
                    (Phase::Commit(cp), MessageType::Commit) => {
                        let expected_sender = if cp.a_done { Role::B } else { Role::A };
                        if expected_sender != local_role {
                            return Err(SessionError::WrongLocalState("out-of-turn local Commit"));
                        }
                        let msg = SetupMessage::decode(payload, params.rules()).map_err(|_| {
                            SessionError::WrongLocalState("invalid local Commit encoding")
                        })?;
                        let verified =
                            setup::verify(params, own_key_pair.as_bytes(), &session.sid, &msg)
                                .map_err(|_| {
                                    SessionError::WrongLocalState(
                                        "local Commit proof failed verification",
                                    )
                                })?;
                        if verified.ship_cells() != expected_ship_cells.as_slice() {
                            return Err(SessionError::WrongLocalState(
                                "snapshot witness does not match committed ship cells",
                            ));
                        }
                        let seed = answer_seed.clone().ok_or(SessionError::WrongLocalState(
                            "snapshot missing answer_seed after local Commit",
                        ))?;
                        cp.own.ship_cells = Some(msg.ship_cells);
                        cp.own.answer_seed = Some(seed);
                        match local_role {
                            Role::A => cp.a_done = true,
                            Role::B => cp.b_done = true,
                        }
                        let to_coin = cp.a_done && cp.b_done;
                        advance_chain(&mut session.head, &mut session.transcript, &auth);
                        if to_coin {
                            session.enter_coin_phase();
                        }
                    }
                    (Phase::Coin(cp), MessageType::CoinCommit)
                        if cp.step == CoinStep::Commit && local_role == Role::A =>
                    {
                        let commitment: [u8; 32] = payload.try_into().map_err(|_| {
                            SessionError::WrongLocalState("bad local CoinCommit payload")
                        })?;
                        let ra = r_a.clone().ok_or(SessionError::WrongLocalState(
                            "snapshot missing r_A for CoinCommit",
                        ))?;
                        if !coin::verify_reveal(&session.sid, &commitment, &ra) {
                            return Err(SessionError::WrongLocalState(
                                "snapshot r_A does not match CoinCommit",
                            ));
                        }
                        cp.coin_commit = Some(commitment);
                        cp.r_a = Some(ra);
                        cp.step = CoinStep::Nonce;
                        advance_chain(&mut session.head, &mut session.transcript, &auth);
                    }
                    (Phase::Coin(cp), MessageType::CoinNonce)
                        if cp.step == CoinStep::Nonce && local_role == Role::B =>
                    {
                        let rb: [u8; 32] = payload.try_into().map_err(|_| {
                            SessionError::WrongLocalState("bad local CoinNonce payload")
                        })?;
                        cp.r_b = Some(rb);
                        cp.step = CoinStep::Reveal;
                        advance_chain(&mut session.head, &mut session.transcript, &auth);
                    }
                    (Phase::Coin(cp), MessageType::CoinReveal)
                        if cp.step == CoinStep::Reveal && local_role == Role::A =>
                    {
                        let ra_bytes: [u8; 32] = payload.try_into().map_err(|_| {
                            SessionError::WrongLocalState("bad local CoinReveal payload")
                        })?;
                        let expected_ra = cp.r_a.take().ok_or(SessionError::WrongLocalState(
                            "missing r_A during CoinReveal replay",
                        ))?;
                        if ra_bytes != *expected_ra {
                            return Err(SessionError::WrongLocalState("CoinReveal mismatch"));
                        }
                        advance_chain(&mut session.head, &mut session.transcript, &auth);
                        session.enter_playing_phase();
                    }
                    (Phase::Playing(game), MessageType::Shot) => {
                        let cell = CellIndex::from_index(payload[0]).ok_or(
                            SessionError::WrongLocalState("invalid local Shot cell in snapshot"),
                        )?;
                        game.fire_shot(cell).map_err(|_| {
                            SessionError::WrongLocalState("local Shot invalid for restored game")
                        })?;
                        advance_chain(&mut session.head, &mut session.transcript, &auth);
                    }
                    (Phase::Playing(game), MessageType::Answer) => {
                        let GameState::AwaitingAnswer { shooter, cell } = game.state() else {
                            return Err(SessionError::WrongLocalState(
                                "unexpected local Answer in snapshot",
                            ));
                        };
                        if shooter == local_role {
                            return Err(SessionError::WrongLocalState(
                                "local Answer while local Shot pending",
                            ));
                        }
                        let answer = ShotAnswer::decode(
                            payload,
                            game.shots_on_board(local_role).unsunk_count(),
                        )
                        .map_err(|_| {
                            SessionError::WrongLocalState("invalid local Answer encoding")
                        })?;
                        let ctx = AnswerContext {
                            defender_id: own_key_pair.as_bytes(),
                            sid: &session.sid,
                        };
                        answers::verify_answer(
                            params,
                            &ctx,
                            &expected_ship_cells,
                            &own_cell_commitments,
                            game.shots_on_board(local_role),
                            cell,
                            &answer,
                        )
                        .map_err(|_| {
                            SessionError::WrongLocalState("local Answer failed verification")
                        })?;
                        game.replay_own_answer(&answer).map_err(|_| {
                            SessionError::WrongLocalState("local Answer replay failed")
                        })?;
                        advance_chain(&mut session.head, &mut session.transcript, &auth);
                    }
                    _ => {
                        return Err(SessionError::WrongLocalState(
                            "unexpected local frame in snapshot",
                        ));
                    }
                }
            } else {
                let auth = frame
                    .authenticate(&expectation, &session.peer)
                    .map_err(|_| {
                        SessionError::WrongLocalState("snapshot peer frame failed auth")
                    })?;
                if auth.frame().header().sender_role != frame::role_to_byte(local_role.other()) {
                    return Err(SessionError::WrongLocalState(
                        "snapshot peer frame has wrong sender role",
                    ));
                }
                let is_playing_shot = matches!(session.phase, Phase::Playing(_))
                    && auth.frame().header().message_type == MessageType::Shot;
                if is_playing_shot {
                    let cell_byte = auth.frame().payload()[0];
                    let Phase::Playing(game) = &mut session.phase else {
                        unreachable!()
                    };
                    game.receive_shot(cell_byte).map_err(|_| {
                        SessionError::WrongLocalState("invalid peer Shot in snapshot")
                    })?;
                    advance_chain(&mut session.head, &mut session.transcript, &auth);
                } else {
                    session.accept_authenticated(auth).map_err(|_| {
                        SessionError::WrongLocalState("snapshot peer frame failed protocol check")
                    })?;
                }
            }
        }

        match &session.phase {
            Phase::Finished { .. } | Phase::Aborted => {
                return Err(SessionError::WrongLocalState(
                    "restored snapshot is already finished or aborted",
                ));
            }
            Phase::Playing(game) => {
                if matches!(
                    game.state(),
                    GameState::AwaitingAnswer { shooter, .. } if shooter != local_role
                ) {
                    return Err(SessionError::WrongLocalState(
                        "snapshot ends with unanswered peer shot",
                    ));
                }
            }
            Phase::Commit(_) | Phase::Coin(_) => {}
        }
        Ok(session)
    }
}

fn validate_bootstrap(
    params: &Parameters,
    keypair: &IdentityKeypair,
    bootstrap: &SessionBootstrap,
    peer: &AuthenticatedPeer,
) -> Result<(Role, [u8; 32], [u8; 32]), SessionError> {
    if bootstrap.params_id() != params.params_id() {
        return Err(SessionError::WrongLocalState(
            "bootstrap params_id does not match session parameters",
        ));
    }
    let own_key = keypair.peer_key();
    let local_role = bootstrap
        .try_role_of(&own_key)
        .ok_or(SessionError::WrongLocalState(
            "local identity key is not part of bootstrap",
        ))?;
    if bootstrap.peer_key_for(&own_key) != Some(peer.key()) {
        return Err(SessionError::WrongLocalState(
            "authenticated peer key does not match bootstrap",
        ));
    }
    Ok((local_role, *bootstrap.sid(), *bootstrap.genesis_hash()))
}

const SNAPSHOT_MAGIC: &[u8; 8] = b"ZKBSS01\0";

struct SnapshotReader<'a> {
    buf: &'a [u8],
}

impl<'a> SnapshotReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn take_slice(&mut self, len: usize) -> Result<&'a [u8], SessionError> {
        if self.buf.len() < len {
            return Err(SessionError::WrongLocalState("truncated snapshot"));
        }
        let (head, rest) = self.buf.split_at(len);
        self.buf = rest;
        Ok(head)
    }

    fn take_u8(&mut self) -> Result<u8, SessionError> {
        Ok(self.take_slice(1)?[0])
    }

    fn take_u32(&mut self) -> Result<u32, SessionError> {
        let bytes = self.take_array::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], SessionError> {
        let slice = self.take_slice(N)?;
        Ok(slice.try_into().expect("length checked"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hello;
    use crate::identity::{ExpectedKey, IdentityKeypair, PeerAuthPolicy};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const SID: [u8; 32] = [0x51; 32];
    const GENESIS: [u8; 32] = [0x6E; 32];

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn keypair(seed: u8) -> IdentityKeypair {
        IdentityKeypair::from_seed(&[seed; 32])
    }

    fn auth(key: &IdentityKeypair) -> AuthenticatedPeer {
        ExpectedKey::new(key.peer_key())
            .authenticate(&key.peer_key())
            .unwrap()
    }

    fn ship(row: u8, col: u8, vertical: bool) -> zkb_core::fleet::ShipPlacement {
        zkb_core::fleet::ShipPlacement { row, col, vertical }
    }

    /// Cells 0-4, 20-23, 40-42, 50-52, 70-71.
    fn placement_a() -> Fleet {
        let ships = [
            ship(0, 0, false),
            ship(2, 0, false),
            ship(4, 0, false),
            ship(5, 0, false),
            ship(7, 0, false),
        ];
        Fleet::new(ships, zkb_core::params::Rules::Standard).unwrap()
    }

    /// Cells 5-9, 10-13, 14-16, 30-32, 50-51.
    fn placement_b() -> Fleet {
        let ships = [
            ship(0, 5, false),
            ship(1, 0, false),
            ship(1, 4, false),
            ship(3, 0, false),
            ship(5, 0, false),
        ];
        Fleet::new(ships, zkb_core::params::Rules::Standard).unwrap()
    }

    fn blinders(seed: u8) -> Vec<Scalar> {
        let mut rng = rng(seed);
        (0..SHIP_BITS).map(|_| Scalar::random(&mut rng)).collect()
    }

    fn session<'b>(local: &'b IdentityKeypair, role: Role, peer: &IdentityKeypair) -> Session<'b> {
        let params = Parameters::standard();
        Session::new(
            params,
            local,
            role,
            auth(peer),
            SID,
            GENESIS,
            placement_a(),
            blinders(0x01),
        )
        .unwrap()
    }

    #[test]
    fn new_rejects_bad_local_witness() {
        let params = Parameters::standard();
        let ka = keypair(1);
        let kb = keypair(2);
        // Rows 4 and 5 touch: legal in the standard game only.
        assert!(matches!(
            Session::new(
                Parameters::no_touch(),
                &ka,
                Role::A,
                auth(&kb),
                SID,
                GENESIS,
                placement_a(),
                blinders(1)
            ),
            Err(SessionError::LocalGame(GameError::IllegalPlacement(_)))
        ));
        assert!(matches!(
            Session::new(
                params,
                &ka,
                Role::A,
                auth(&kb),
                SID,
                GENESIS,
                placement_a(),
                blinders(1)[..SHIP_BITS - 1].to_vec()
            ),
            Err(SessionError::LocalGame(
                GameError::WrongWitnessLength { .. }
            ))
        ));
    }

    #[test]
    fn attributable_failure_aborts_and_cannot_be_corrected() {
        let ka = keypair(1);
        let kb = keypair(2);
        let mut sb = session(&kb, Role::B, &ka);
        let bad = SignedFrame::craft(&ka, &SID, Role::A, 1, MessageType::Shot, &GENESIS, vec![0]);
        assert!(matches!(
            sb.accept(bad.bytes()),
            Err(SessionError::Attributable(_))
        ));
        assert!(sb.is_aborted());
        assert!(matches!(sb.phase, Phase::Aborted)); // OwnBoard was dropped.
        assert_eq!(sb.expected_sender(), None);
        assert_eq!(sb.head_sequence(), 0);
        assert!(sb.transcript().is_empty());
        let corrected =
            SignedFrame::craft(&ka, &SID, Role::A, 1, MessageType::Resign, &GENESIS, vec![]);
        assert!(matches!(
            sb.accept(corrected.bytes()),
            Err(SessionError::WrongLocalState(_))
        ));
        assert!(sb.produce(&mut rng(1)).unwrap().is_none());
        assert!(matches!(sb.resign(), Err(SessionError::WrongLocalState(_))));
    }

    #[test]
    fn internal_prover_failure_drops_session_secrets() {
        let ka = keypair(1);
        let kb = keypair(2);
        let mut sa = session(&ka, Role::A, &kb);
        let Phase::Commit(cp) = &mut sa.phase else {
            unreachable!()
        };
        cp.own.rho.as_mut().unwrap().pop();
        assert!(matches!(
            sa.produce(&mut rng(1)),
            Err(SessionError::InternalInvariant(_))
        ));
        assert!(matches!(sa.phase, Phase::Aborted));
        assert_eq!(sa.expected_sender(), None);
        assert_eq!(sa.winner(), None);
        assert!(sa.produce(&mut rng(2)).unwrap().is_none());
    }

    #[test]
    fn local_abort_drops_secrets_without_attributing_timeout() {
        let ka = keypair(1);
        let kb = keypair(2);
        let mut sa = session(&ka, Role::A, &kb);
        sa.abort();
        assert!(matches!(sa.phase, Phase::Aborted));
        assert_eq!(sa.winner(), None);
        assert_eq!(sa.expected_sender(), None);
        assert_eq!(sa.head_sequence(), 0);
    }

    #[test]
    fn internal_game_handoff_failure_is_terminal_for_either_role() {
        let ka = keypair(1);
        let kb = keypair(2);
        for failing_role in [Role::A, Role::B] {
            let mut sa = session(&ka, Role::A, &kb);
            let mut sb = session(&kb, Role::B, &ka);
            let mut entropy = rng(12);
            let f = sa.produce(&mut entropy).unwrap().unwrap();
            sb.accept(f.bytes()).unwrap();
            let f = sb.produce(&mut entropy).unwrap().unwrap();
            sa.accept(f.bytes()).unwrap();
            let f = sa.produce(&mut entropy).unwrap().unwrap();
            sb.accept(f.bytes()).unwrap();
            let nonce = sb.produce(&mut entropy).unwrap().unwrap();
            let (failed, incoming) = match failing_role {
                Role::A => (&mut sa, nonce),
                Role::B => {
                    sa.accept(nonce.bytes()).unwrap();
                    let reveal = sa.produce(&mut entropy).unwrap().unwrap();
                    (&mut sb, reveal)
                }
            };
            let Phase::Coin(cp) = &mut failed.phase else {
                unreachable!()
            };
            // Corrupt the validated witness: the game handoff must fail terminally.
            cp.own.rho.as_mut().unwrap().pop();
            let previous_head = *failed.head_hash();
            let previous_sequence = failed.head_sequence();
            assert!(matches!(
                failed.accept(incoming.bytes()),
                Err(SessionError::InternalInvariant(
                    "validated board could not initialize game"
                ))
            ));
            assert!(matches!(failed.phase, Phase::Aborted));
            assert!(failed.game().is_none());
            assert_eq!(failed.expected_sender(), None);
            assert_eq!(failed.head_sequence(), previous_sequence);
            assert_eq!(*failed.head_hash(), previous_head);
            assert!(failed.produce(&mut entropy).unwrap().is_none());
            assert!(matches!(
                failed.accept(incoming.bytes()),
                Err(SessionError::WrongLocalState(_))
            ));
            assert!(matches!(
                failed.resign(),
                Err(SessionError::WrongLocalState(_))
            ));
        }
    }

    #[test]
    fn resignation_after_coin_nonce_finishes_retained_game() {
        let ka = keypair(1);
        let kb = keypair(2);
        let mut sa = session(&ka, Role::A, &kb);
        let mut sb = session(&kb, Role::B, &ka);
        let mut entropy = rng(12);
        let f = sa.produce(&mut entropy).unwrap().unwrap();
        sb.accept(f.bytes()).unwrap();
        let f = sb.produce(&mut entropy).unwrap().unwrap();
        sa.accept(f.bytes()).unwrap();
        let f = sa.produce(&mut entropy).unwrap().unwrap();
        sb.accept(f.bytes()).unwrap();
        let f = sb.produce(&mut entropy).unwrap().unwrap();
        sa.accept(f.bytes()).unwrap();
        assert!(matches!(sa.phase, Phase::Coin(_)));
        assert!(sa.game().is_some());
        let resignation = sa.resign().unwrap();
        sb.accept(resignation.bytes()).unwrap();
        assert_eq!(
            sa.game().unwrap().state(),
            GameState::Finished { winner: Role::B }
        );
        assert_eq!(sa.head_hash(), sb.head_hash());
        assert_eq!(sa.winner(), Some(Role::B));
        assert_eq!(sb.winner(), Some(Role::B));
    }

    #[test]
    fn out_of_turn_resign_is_attributable() {
        let ka = keypair(1);
        let kb = keypair(2);
        // A owes the first commit, so a Resign from B is out of turn.
        let mut sa = session(&ka, Role::A, &kb);
        let frame =
            SignedFrame::craft(&kb, &SID, Role::B, 1, MessageType::Resign, &GENESIS, vec![]);
        match sa.accept(frame.bytes()) {
            Err(SessionError::Attributable(v)) => {
                assert!(matches!(v.violation, Violation::OutOfTurnResign));
                assert_eq!(v.frame.bytes(), frame.bytes());
            }
            other => panic!("expected attributable violation, got {other:?}"),
        }
        let kb2 = keypair(3);
        let ka2 = keypair(4);
        let mut sb = session(&kb2, Role::B, &ka2);
        assert!(matches!(sb.resign(), Err(SessionError::WrongLocalState(_))));
    }

    #[test]
    fn in_turn_resign_accepted_and_replay_is_class_b() {
        let ka = keypair(1);
        let kb = keypair(2);
        let mut sb = session(&kb, Role::B, &ka);
        let frame =
            SignedFrame::craft(&ka, &SID, Role::A, 1, MessageType::Resign, &GENESIS, vec![]);
        assert!(matches!(
            sb.accept(frame.bytes()),
            Ok(AcceptOutcome::PeerResigned)
        ));
        assert_eq!(sb.winner(), Some(Role::B));
        assert_eq!(sb.head_sequence(), 1);

        match sb.accept(frame.bytes()) {
            Err(SessionError::ClassB(ClassBReason::WrongSequence {
                expected: 2,
                actual: 1,
            })) => {}
            other => panic!("expected class-B wrong sequence, got {other:?}"),
        }
    }

    #[test]
    fn class_b_rejections() {
        let ka = keypair(1);
        let kb = keypair(2);
        let mut sb = session(&kb, Role::B, &ka);

        let frame = SignedFrame::craft(
            &ka,
            &[0xEE; 32],
            Role::A,
            1,
            MessageType::Resign,
            &GENESIS,
            vec![],
        );
        assert!(matches!(
            sb.accept(frame.bytes()),
            Err(SessionError::ClassB(ClassBReason::WrongSession))
        ));
        let frame =
            SignedFrame::craft(&ka, &SID, Role::A, 5, MessageType::Resign, &GENESIS, vec![]);
        assert!(matches!(
            sb.accept(frame.bytes()),
            Err(SessionError::ClassB(ClassBReason::WrongSequence { .. }))
        ));
        let frame = SignedFrame::craft(
            &ka,
            &SID,
            Role::A,
            1,
            MessageType::Resign,
            &[0xEE; 32],
            vec![],
        );
        assert!(matches!(
            sb.accept(frame.bytes()),
            Err(SessionError::ClassB(ClassBReason::WrongPrevHash))
        ));
        let stranger = keypair(9);
        let frame = SignedFrame::craft(
            &stranger,
            &SID,
            Role::A,
            1,
            MessageType::Resign,
            &GENESIS,
            vec![],
        );
        assert!(matches!(
            sb.accept(frame.bytes()),
            Err(SessionError::ClassB(ClassBReason::BadSignature))
        ));
        assert!(matches!(
            sb.accept(&[0u8; 10]),
            Err(SessionError::ClassB(ClassBReason::Malformed(_)))
        ));
        assert!(!sb.is_aborted());
        assert_eq!(sb.expected_sender(), Some(Role::A));
        let next = SignedFrame::craft(&ka, &SID, Role::A, 1, MessageType::Resign, &GENESIS, vec![]);
        assert!(matches!(
            sb.accept(next.bytes()),
            Ok(AcceptOutcome::PeerResigned)
        ));
    }

    #[test]
    fn attributable_content_violations() {
        let ka = keypair(1);
        let kb = keypair(2);

        let mut sb = session(&kb, Role::B, &ka);
        let payload = vec![0xFF; crate::codec::COMMIT_PAYLOAD_LEN];
        let frame = SignedFrame::craft(
            &ka,
            &SID,
            Role::A,
            1,
            MessageType::Commit,
            &GENESIS,
            payload,
        );
        match sb.accept(frame.bytes()) {
            Err(SessionError::Attributable(v)) => {
                assert!(matches!(v.violation, Violation::InvalidCommit(_)));
            }
            other => panic!("expected attributable invalid commit, got {other:?}"),
        }

        let mut sb = session(&kb, Role::B, &ka);
        let frame = SignedFrame::craft(&ka, &SID, Role::A, 1, MessageType::Shot, &GENESIS, vec![0]);
        match sb.accept(frame.bytes()) {
            Err(SessionError::Attributable(v)) => {
                assert!(matches!(
                    v.violation,
                    Violation::UnexpectedMessage {
                        message_type: MessageType::Shot
                    }
                ));
            }
            other => panic!("expected attributable unexpected message, got {other:?}"),
        }

        let mut sb = session(&kb, Role::B, &ka);
        let frame =
            SignedFrame::craft(&ka, &SID, Role::B, 1, MessageType::Resign, &GENESIS, vec![]);
        match sb.accept(frame.bytes()) {
            Err(SessionError::Attributable(v)) => {
                assert!(matches!(v.violation, Violation::SenderRoleMismatch { .. }));
            }
            other => panic!("expected attributable sender-role mismatch, got {other:?}"),
        }
    }

    /// The single slow test: real proofs.
    #[test]
    fn full_session_between_two_players() {
        let params = Parameters::standard();
        let params_id = *params.params_id();
        let ka = keypair(0x11);
        let kb = keypair(0x22);
        let mut rng = rng(0x99);

        let hello_a = hello::Hello::create(&ka, params_id, &mut rng);
        let hello_b = hello::Hello::create(&kb, params_id, &mut rng);
        let checked_a =
            hello::check_hello(hello_a, &params_id, &ExpectedKey::new(ka.peer_key())).unwrap();
        let checked_b =
            hello::check_hello(hello_b, &params_id, &ExpectedKey::new(kb.peer_key())).unwrap();
        let bootstrap = hello::complete_bootstrap(checked_a, checked_b).unwrap();
        let sid = *bootstrap.sid();
        let genesis = *bootstrap.genesis_hash();
        let role_of = |k: &IdentityKeypair| bootstrap.role_of(&k.peer_key());

        let session_a = Session::new(
            params,
            &ka,
            role_of(&ka),
            auth(&kb),
            sid,
            genesis,
            placement_a(),
            blinders(0xA0),
        )
        .unwrap();
        let session_b = Session::new(
            params,
            &kb,
            role_of(&kb),
            auth(&ka),
            sid,
            genesis,
            placement_b(),
            blinders(0xB0),
        )
        .unwrap();
        let (mut s_a, mut s_b) = if role_of(&ka) == Role::A {
            (session_a, session_b)
        } else {
            (session_b, session_a)
        };

        let frame = s_a.produce(&mut rng).unwrap().unwrap();
        assert!(matches!(
            s_b.accept(frame.bytes()),
            Ok(AcceptOutcome::CommitVerified)
        ));
        let frame = s_b.produce(&mut rng).unwrap().unwrap();
        assert!(matches!(
            s_a.accept(frame.bytes()),
            Ok(AcceptOutcome::CommitVerified)
        ));

        let frame = s_a.produce(&mut rng).unwrap().unwrap(); // CoinCommit
        assert!(matches!(
            s_b.accept(frame.bytes()),
            Ok(AcceptOutcome::CoinProgress)
        ));
        let frame = s_b.produce(&mut rng).unwrap().unwrap(); // CoinNonce
        let first_mover = match s_a.accept(frame.bytes()).unwrap() {
            AcceptOutcome::GameReady { first_mover } => first_mover,
            other => panic!("expected GameReady, got {other:?}"),
        };
        let frame = s_a.produce(&mut rng).unwrap().unwrap(); // CoinReveal
        match s_b.accept(frame.bytes()).unwrap() {
            AcceptOutcome::GameReady { first_mover: fm_b } => assert_eq!(fm_b, first_mover),
            other => panic!("expected GameReady, got {other:?}"),
        }

        let mut current = first_mover;
        for _ in 0..6 {
            let (attacker, defender) = if current == Role::A {
                (&mut s_a, &mut s_b)
            } else {
                (&mut s_b, &mut s_a)
            };
            let cell = (0..100u8)
                .map(|i| CellIndex::from_index(i).unwrap())
                .find(|c| {
                    !attacker
                        .game()
                        .unwrap()
                        .shots_on_board(current.other())
                        .is_shot(*c)
                })
                .unwrap();
            let shot = attacker.fire_shot(cell).unwrap();
            let answer = match defender.accept(shot.bytes()).unwrap() {
                AcceptOutcome::ShotReceived {
                    answer,
                    cell: shot_cell,
                    winner: None,
                    ..
                } => {
                    assert_eq!(shot_cell, cell);
                    answer
                }
                other => panic!("expected ShotReceived, got {other:?}"),
            };
            match attacker.accept(answer.bytes()).unwrap() {
                AcceptOutcome::Answer(_) => {}
                other => panic!("expected Answer, got {other:?}"),
            }
            current = current.other();
        }

        assert_eq!(s_a.head_sequence(), s_b.head_sequence());
        assert_eq!(s_a.head_hash(), s_b.head_hash());
        assert_eq!(s_a.transcript().len(), s_b.transcript().len());

        let (resigner, other) = if current == Role::A {
            (&mut s_a, &mut s_b)
        } else {
            (&mut s_b, &mut s_a)
        };
        let frame = resigner.resign().unwrap();
        assert!(matches!(
            other.accept(frame.bytes()),
            Ok(AcceptOutcome::PeerResigned)
        ));
        assert_eq!(other.winner(), Some(current.other()));
        assert_eq!(resigner.winner(), Some(current.other()));
        assert_eq!(other.expected_sender(), None);
        assert_eq!(resigner.expected_sender(), None);
        assert!(other.game().is_some());
        assert!(resigner.game().is_some());
        assert_eq!(
            other.game().unwrap().state(),
            GameState::Finished {
                winner: current.other()
            }
        );
        assert_eq!(
            resigner.game().unwrap().state(),
            GameState::Finished {
                winner: current.other()
            }
        );
    }

    #[test]
    fn session_from_bootstrap_and_self_key_rejection() {
        let params = Parameters::standard();
        let params_id = *params.params_id();
        let ka = keypair(0x11);
        let kb = keypair(0x22);
        let mut r = rng(0x33);

        // Same key as both local and peer must be rejected.
        assert!(matches!(
            Session::new(
                params,
                &ka,
                Role::A,
                auth(&ka),
                SID,
                GENESIS,
                placement_a(),
                blinders(0xA0),
            ),
            Err(SessionError::WrongLocalState(_))
        ));

        let ha = hello::Hello::create(&ka, params_id, &mut r);
        let hb = hello::Hello::create(&kb, params_id, &mut r);
        let ca = hello::check_hello(ha, &params_id, &ExpectedKey::new(ka.peer_key())).unwrap();
        let cb = hello::check_hello(hb, &params_id, &ExpectedKey::new(kb.peer_key())).unwrap();
        let bootstrap = hello::complete_bootstrap(ca, cb).unwrap();
        let (a_key, b_key) = if bootstrap.role_of(&ka.peer_key()) == Role::A {
            (&ka, &kb)
        } else {
            (&kb, &ka)
        };
        let s = Session::from_bootstrap(
            params,
            a_key,
            &bootstrap,
            auth(b_key),
            placement_a(),
            blinders(0xA0),
        )
        .unwrap();
        assert_eq!(s.local_role(), Role::A);
        assert_eq!(s.phase_kind(), PhaseKind::Commit);
        assert!(s.needs_produce());
        assert!(!s.can_fire_shot());

        // Mismatched peer key rejected.
        let kc = keypair(0x33);
        assert!(matches!(
            Session::from_bootstrap(
                params,
                a_key,
                &bootstrap,
                auth(&kc),
                placement_a(),
                blinders(0xA0),
            ),
            Err(SessionError::WrongLocalState(_))
        ));
    }

    #[test]
    fn snapshot_restore_mid_game_matches_uninterrupted_answers() {
        let params = Parameters::standard();
        let ka = keypair(0x11);
        let kb = keypair(0x22);
        let mut r = rng(0x55);

        let mut sa = session(&ka, Role::A, &kb);
        let mut sb = Session::new(
            params,
            &kb,
            Role::B,
            auth(&ka),
            SID,
            GENESIS,
            placement_b(),
            blinders(0xB0),
        )
        .unwrap();

        // Snapshot before any commit, then restore and continue.
        let snap0 = sa.export_snapshot().unwrap();
        sa = Session::restore_snapshot(params, &ka, auth(&kb), &snap0).unwrap();

        let f = sa.produce(&mut r).unwrap().unwrap();
        sb.accept(f.bytes()).unwrap();
        // Snapshot A right after sending Commit, and B before sending Commit.
        let snap_a1 = sa.export_snapshot().unwrap();
        let snap_b1 = sb.export_snapshot().unwrap();
        sa = Session::restore_snapshot(params, &ka, auth(&kb), &snap_a1).unwrap();
        sb = Session::restore_snapshot(params, &kb, auth(&ka), &snap_b1).unwrap();

        let f = sb.produce(&mut r).unwrap().unwrap();
        sa.accept(f.bytes()).unwrap();
        let f = sa.produce(&mut r).unwrap().unwrap(); // CoinCommit
        sb.accept(f.bytes()).unwrap();
        let f = sb.produce(&mut r).unwrap().unwrap(); // CoinNonce
        sa.accept(f.bytes()).unwrap();

        // Snapshot A right between CoinNonce and CoinReveal (game already initialized, r_A held).
        let snap_coin = sa.export_snapshot().unwrap();
        sa = Session::restore_snapshot(params, &ka, auth(&kb), &snap_coin).unwrap();

        let f = sa.produce(&mut r).unwrap().unwrap(); // CoinReveal
        let AcceptOutcome::GameReady { first_mover } = sb.accept(f.bytes()).unwrap() else {
            panic!("expected GameReady");
        };
        assert_eq!(sa.first_mover(), Some(first_mover));
        assert_eq!(sb.first_mover(), Some(first_mover));

        // Play a few turns including hits, misses, and a sink, then snapshot both sides
        // and verify restored sessions produce byte-for-byte identical answers and finish.
        let mut current = first_mover;
        for turn in 0..24 {
            let (attacker, defender) = if current == Role::A {
                (&mut sa, &mut sb)
            } else {
                (&mut sb, &mut sa)
            };
            let cell = (0..100u8)
                .map(|i| CellIndex::from_index(i).unwrap())
                .find(|c| {
                    !attacker
                        .game()
                        .unwrap()
                        .shots_on_board(current.other())
                        .is_shot(*c)
                })
                .unwrap();
            let shot = attacker.fire_shot(cell).unwrap();
            if turn == 12 {
                // Also test snapshot when local player has a pending shot out.
                let (key, peer) = if current == Role::A {
                    (&ka, auth(&kb))
                } else {
                    (&kb, auth(&ka))
                };
                let snap = attacker.export_snapshot().unwrap();
                *attacker = Session::restore_snapshot(params, key, peer, &snap).unwrap();
            }
            let AcceptOutcome::ShotReceived { answer, winner, .. } =
                defender.accept(shot.bytes()).unwrap()
            else {
                panic!("expected ShotReceived");
            };
            attacker.accept(answer.bytes()).unwrap();
            if winner.is_some() {
                break;
            }
            current = current.other();
        }

        // Snapshot both mid-game, restore into clones, and compare the next hit proof byte-for-byte.
        let snap_a = sa.export_snapshot().unwrap();
        let snap_b = sb.export_snapshot().unwrap();
        let mut sa_restored = Session::restore_snapshot(params, &ka, auth(&kb), &snap_a).unwrap();
        let mut sb_restored = Session::restore_snapshot(params, &kb, auth(&ka), &snap_b).unwrap();

        let (orig_att, orig_def, rest_att, rest_def) = if current == Role::A {
            (&mut sa, &mut sb, &mut sa_restored, &mut sb_restored)
        } else {
            (&mut sb, &mut sa, &mut sb_restored, &mut sa_restored)
        };
        let next_cell = (0..100u8)
            .map(|i| CellIndex::from_index(i).unwrap())
            .find(|c| {
                !orig_att
                    .game()
                    .unwrap()
                    .shots_on_board(current.other())
                    .is_shot(*c)
            })
            .unwrap();
        let orig_shot = orig_att.fire_shot(next_cell).unwrap();
        let rest_shot = rest_att.fire_shot(next_cell).unwrap();
        assert_eq!(orig_shot.bytes(), rest_shot.bytes());
        let AcceptOutcome::ShotReceived {
            answer: orig_ans, ..
        } = orig_def.accept(orig_shot.bytes()).unwrap()
        else {
            panic!();
        };
        let AcceptOutcome::ShotReceived {
            answer: rest_ans, ..
        } = rest_def.accept(rest_shot.bytes()).unwrap()
        else {
            panic!();
        };
        assert_eq!(orig_ans.bytes(), rest_ans.bytes());
        orig_att.accept(orig_ans.bytes()).unwrap();
        rest_att.accept(rest_ans.bytes()).unwrap();

        // Finish the restored game completely.
        current = current.other();
        let winner = loop {
            let (attacker, defender) = if current == Role::A {
                (&mut sa_restored, &mut sb_restored)
            } else {
                (&mut sb_restored, &mut sa_restored)
            };
            let cell = (0..100u8)
                .map(|i| CellIndex::from_index(i).unwrap())
                .find(|c| {
                    !attacker
                        .game()
                        .unwrap()
                        .shots_on_board(current.other())
                        .is_shot(*c)
                })
                .unwrap();
            let shot = attacker.fire_shot(cell).unwrap();
            let AcceptOutcome::ShotReceived { answer, .. } = defender.accept(shot.bytes()).unwrap()
            else {
                panic!();
            };
            match attacker.accept(answer.bytes()).unwrap() {
                AcceptOutcome::GameFinished { winner } => break winner,
                AcceptOutcome::Answer(_) => current = current.other(),
                other => panic!("unexpected {other:?}"),
            }
        };
        assert_eq!(sa_restored.winner(), Some(winner));
        assert_eq!(sb_restored.winner(), Some(winner));
        assert!(matches!(
            sa_restored.export_snapshot(),
            Err(SessionError::WrongLocalState(_))
        ));
    }
}
