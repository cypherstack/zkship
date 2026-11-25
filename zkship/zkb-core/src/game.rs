//! Pure deterministic game state (paper Section 5); no I/O.
//!
//! Paper Section 5.4 (not in the abstract): the game ends on BOTH sides at
//! the same chain position. The shooter finishes on accepting its T-th
//! verified hit; the defender finishes when it answers the shot conceding its
//! T-th hit. After that no sender is expected, so both peers agree on the
//! linear transcript.
//! The T-th hit is always a sink announcement of the last ship.

use crate::answers::{
    self, AnswerContext, AnswerDecodeError, AnswerOutcome, AnswerRejection, BoardShots,
    ResponderSecrets, ShotAnswer,
};
use crate::fleet::{Fleet, PlacementError, SHIP_BITS};
use crate::params::{CellIndex, Parameters, K, T};
use crate::setup::VerifiedSetup;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Fixed by the session bootstrap: lower identity key is A and commits first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    A,
    B,
}

impl Role {
    pub fn other(self) -> Role {
        match self {
            Role::A => Role::B,
            Role::B => Role::A,
        }
    }
}

/// At every nonterminal position exactly one sender is expected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    AwaitingShot { shooter: Role },
    AwaitingAnswer { shooter: Role, cell: CellIndex },
    Finished { winner: Role },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShotOutcome {
    Miss,
    Hit,
    /// Ship `ship` (fleet order 5, 4, 3, 3, 2) was announced sunk.
    Sunk {
        ship: u8,
    },
    /// The last ship sank.
    Win,
}

/// Deliberately no "peer cheated" variant: opening failures are
/// `AnswerRejected`; `InternalInvariantFailure` is a local incident.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GameError {
    WrongState,
    OutOfRangeShot {
        cell: u8,
    },
    RepeatedShot {
        cell: u8,
    },
    IllegalPlacement(PlacementError),
    WrongWitnessLength {
        expected: usize,
        actual: usize,
    },
    WrongCommitmentCount {
        expected: usize,
        actual: usize,
    },
    AnswerRejected(AnswerRejection),
    /// Class D: fail closed; an implementation incident, never proof of
    /// peer cheating.
    InternalInvariantFailure(&'static str),
}

impl fmt::Display for GameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GameError::WrongState => write!(f, "message does not match the current game state"),
            GameError::OutOfRangeShot { cell } => write!(f, "shot cell {cell} is out of range"),
            GameError::RepeatedShot { cell } => write!(f, "cell {cell} has already been shot"),
            GameError::IllegalPlacement(e) => write!(f, "illegal local placement: {e}"),
            GameError::WrongWitnessLength { expected, actual } => {
                write!(f, "blinder vector has length {actual}, expected {expected}")
            }
            GameError::WrongCommitmentCount { expected, actual } => {
                write!(f, "got {actual} ship-cell commitments, expected {expected}")
            }
            GameError::AnswerRejected(e) => write!(f, "answer rejected: {e}"),
            GameError::InternalInvariantFailure(what) => {
                write!(f, "internal invariant failure: {what}")
            }
        }
    }
}

impl std::error::Error for GameError {}

/// Identities and session of the two proof contexts: the local player's
/// answers are bound to `own_id`, the peer's to `peer_id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GameContext {
    pub own_id: [u8; 32],
    pub peer_id: [u8; 32],
    pub sid: [u8; 32],
}

/// Nonce source for answers: a Merlin transcript keyed by a 32-byte seed,
/// advanced once per answer and hedged with the witness (see `answer_shot`).
/// Only a not-sunk proof consumes the result.
#[cfg_attr(fuzzing, derive(Clone))]
struct SeededRng(Transcript);

impl SeededRng {
    fn new(seed: &[u8; 32]) -> SeededRng {
        let mut transcript = Transcript::new(b"zkbattleship/paper/v1/answer-rng");
        transcript.append_message(b"seed", seed);
        SeededRng(transcript)
    }
}

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.challenge_bytes(b"rng", dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SeededRng {}

/// Secret material required to snapshot and restore an in-progress [`Game`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GameSecrets {
    pub fleet_bytes: [u8; 3 * K],
    pub rho: Vec<Scalar>,
    pub answer_seed: [u8; 32],
}

#[cfg_attr(fuzzing, derive(Clone))]
pub struct Game<'a> {
    params: &'a Parameters,
    local_role: Role,
    state: State,
    ctx: GameContext,
    own_ship_cells: Vec<RistrettoPoint>,
    own_board: BoardShots,
    own_secrets: Option<Box<ResponderSecrets>>,
    answer_rng: Option<SeededRng>,
    answer_seed: Option<Zeroizing<[u8; 32]>>,
    peer: VerifiedSetup,
    peer_board: BoardShots,
    verified_hits: u8,
    hits_conceded: u8,
}

impl<'a> Game<'a> {
    /// `own_ship_cells` are the commitments of the local setup; `rho` their
    /// blinders; `answer_seed` keys the not-sunk proof nonces.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        params: &'a Parameters,
        local_role: Role,
        first_mover: Role,
        ctx: GameContext,
        own_ship_cells: Vec<RistrettoPoint>,
        fleet: &Fleet,
        rho: Vec<Scalar>,
        answer_seed: &[u8; 32],
        peer: VerifiedSetup,
    ) -> Result<Game<'a>, GameError> {
        let mut rho = Zeroizing::new(rho);
        if rho.len() != SHIP_BITS {
            return Err(GameError::WrongWitnessLength {
                expected: SHIP_BITS,
                actual: rho.len(),
            });
        }
        if own_ship_cells.len() != SHIP_BITS {
            return Err(GameError::WrongCommitmentCount {
                expected: SHIP_BITS,
                actual: own_ship_cells.len(),
            });
        }
        Fleet::new(*fleet.ships(), params.rules()).map_err(GameError::IllegalPlacement)?;
        Ok(Game {
            params,
            local_role,
            state: State::AwaitingShot {
                shooter: first_mover,
            },
            ctx,
            own_ship_cells,
            own_board: BoardShots::default(),
            own_secrets: Some(Box::new(ResponderSecrets::new(
                fleet,
                std::mem::take(&mut *rho),
            ))),
            answer_rng: Some(SeededRng::new(answer_seed)),
            answer_seed: Some(Zeroizing::new(*answer_seed)),
            peer,
            peer_board: BoardShots::default(),
            verified_hits: 0,
            hits_conceded: 0,
        })
    }

    pub fn params(&self) -> &'a Parameters {
        self.params
    }

    pub fn context(&self) -> &GameContext {
        &self.ctx
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn local_role(&self) -> Role {
        self.local_role
    }

    /// Incremented only after a valid hit or sink opening.
    pub fn verified_hits(&self) -> u8 {
        self.verified_hits
    }

    /// Honest hit answers on the own board; T of them finish the game.
    pub fn hits_conceded(&self) -> u8 {
        self.hits_conceded
    }

    /// Ships announced sunk on the peer's board, fleet order.
    pub fn peer_sunk(&self) -> [bool; K] {
        *self.peer_board.sunk()
    }

    /// Ships announced sunk on the own board, fleet order.
    pub fn own_sunk(&self) -> [bool; K] {
        *self.own_board.sunk()
    }

    /// Verified cells of peer ship `j`, once announced sunk.
    pub fn peer_sunk_cells(&self, ship: usize) -> Option<&[CellIndex]> {
        self.peer_board.sunk_cells(ship)
    }

    /// Announced cells of own ship `j`, once sunk.
    pub fn own_sunk_cells(&self, ship: usize) -> Option<&[CellIndex]> {
        self.own_board.sunk_cells(ship)
    }

    pub fn shots_on_board(&self, role: Role) -> &BoardShots {
        if role == self.local_role {
            &self.own_board
        } else {
            &self.peer_board
        }
    }

    pub fn has_secrets(&self) -> bool {
        self.own_secrets.is_some()
    }

    pub fn has_answer_rng(&self) -> bool {
        self.answer_rng.is_some()
    }

    pub fn snapshot_secrets(&self) -> Option<GameSecrets> {
        let (Some(secrets), Some(seed)) = (&self.own_secrets, &self.answer_seed) else {
            return None;
        };
        Some(GameSecrets {
            fleet_bytes: secrets.fleet_bytes(),
            rho: secrets.rho().to_vec(),
            answer_seed: **seed,
        })
    }

    pub fn fire_shot(&mut self, cell: CellIndex) -> Result<u8, GameError> {
        let State::AwaitingShot { shooter } = self.state else {
            return Err(GameError::WrongState);
        };
        if shooter != self.local_role {
            return Err(GameError::WrongState);
        }
        if self.peer_board.is_shot(cell) {
            return Err(GameError::RepeatedShot { cell: cell.index() });
        }
        self.peer_board.register(self.peer.ship_cells(), cell);
        self.state = State::AwaitingAnswer {
            shooter: self.local_role,
            cell,
        };
        Ok(cell.index())
    }

    /// The cell joins the own board's public shot set before the answer.
    pub fn receive_shot(&mut self, cell: u8) -> Result<(), GameError> {
        let State::AwaitingShot { shooter } = self.state else {
            return Err(GameError::WrongState);
        };
        if shooter == self.local_role {
            return Err(GameError::WrongState);
        }
        let cell = CellIndex::from_index(cell).ok_or(GameError::OutOfRangeShot { cell })?;
        if self.own_board.is_shot(cell) {
            return Err(GameError::RepeatedShot { cell: cell.index() });
        }
        let secrets = self
            .own_secrets
            .as_mut()
            .ok_or(GameError::InternalInvariantFailure(
                "shot received but the own-board secrets are gone",
            ))?;
        self.own_board.register(&self.own_ship_cells, cell);
        secrets.register(cell);
        self.state = State::AwaitingAnswer {
            shooter: self.local_role.other(),
            cell,
        };
        Ok(())
    }

    /// Conceding the T-th hit finishes the game with the peer as winner; the
    /// returned answer is still sent as the final frame.
    pub fn answer_shot(&mut self) -> Result<ShotAnswer, GameError> {
        let State::AwaitingAnswer { shooter, cell } = self.state else {
            return Err(GameError::WrongState);
        };
        if shooter == self.local_role {
            return Err(GameError::WrongState);
        }
        let secrets = self
            .own_secrets
            .as_ref()
            .ok_or(GameError::InternalInvariantFailure(
                "answer owed but the own-board secrets are gone",
            ))?;
        let answer_rng = self
            .answer_rng
            .as_mut()
            .ok_or(GameError::InternalInvariantFailure(
                "answer owed but the answer RNG is gone",
            ))?;
        let ctx = AnswerContext {
            defender_id: &self.ctx.own_id,
            sid: &self.ctx.sid,
        };
        // Hedge the seeded nonce source with the secrets, as the setup prover does.
        let mut hedge = Transcript::new(b"zkbattleship/paper/v1/answer-hedge");
        hedge.append_message(b"shots", &[self.own_board.shots()]);
        let mut rng = secrets.rekey(hedge.build_rng()).finalize(answer_rng);
        let answer =
            answers::try_answer_shot(self.params, &ctx, &self.own_board, secrets, cell, &mut rng)
                .map_err(|_| {
                GameError::InternalInvariantFailure("not-sunk range proof generation failed")
            })?;
        if let ShotAnswer::Sunk { ship, openings, .. } = &answer {
            self.own_board
                .mark_sunk_with_cells(*ship, openings.iter().map(|(c, _)| *c).collect());
        }
        // Whether it hit is public (it is being sent).
        if answer.is_hit() {
            self.hits_conceded += 1;
        }
        if self.hits_conceded == T as u8 {
            self.finish(self.local_role.other());
        } else {
            self.state = State::AwaitingShot {
                shooter: self.local_role,
            };
        }
        Ok(answer)
    }

    /// Replays a previously sent own `Answer` (used when restoring a session
    /// snapshot) so board tallies and `answer_rng` advance identically without
    /// re-running proof generation.
    pub fn replay_own_answer(&mut self, answer: &ShotAnswer) -> Result<(), GameError> {
        let State::AwaitingAnswer { shooter, .. } = self.state else {
            return Err(GameError::WrongState);
        };
        if shooter == self.local_role {
            return Err(GameError::WrongState);
        }
        let mut scratch = Zeroizing::new([0u8; 32]);
        self.answer_rng
            .as_mut()
            .ok_or(GameError::InternalInvariantFailure(
                "answer replay owed but the answer RNG is gone",
            ))?
            .fill_bytes(&mut *scratch);
        if let ShotAnswer::Sunk { ship, openings, .. } = answer {
            self.own_board
                .mark_sunk_with_cells(*ship, openings.iter().map(|(c, _)| *c).collect());
        }
        if answer.is_hit() {
            self.hits_conceded += 1;
        }
        if self.hits_conceded == T as u8 {
            self.finish(self.local_role.other());
        } else {
            self.state = State::AwaitingShot {
                shooter: self.local_role,
            };
        }
        Ok(())
    }

    /// Parses an answer to the local player's pending shot; the hit proof's
    /// length depends on the peer's unsunk ships.
    pub fn decode_answer(&self, bytes: &[u8]) -> Result<ShotAnswer, AnswerDecodeError> {
        ShotAnswer::decode(bytes, self.peer_board.unsunk_count())
    }

    /// Session-layer forfeit; erases secrets, keeps public tallies.
    pub fn finish_by_forfeit(&mut self, winner: Role) -> Result<(), GameError> {
        if matches!(self.state, State::Finished { .. }) {
            return Err(GameError::WrongState);
        }
        self.finish(winner);
        Ok(())
    }

    fn finish(&mut self, winner: Role) {
        self.state = State::Finished { winner };
        self.own_secrets = None;
        self.answer_rng = None;
        self.answer_seed = None;
    }

    /// At T verified hits every ship must have been announced sunk, else
    /// class-D internal failure.
    pub fn accept_answer(&mut self, answer: &ShotAnswer) -> Result<ShotOutcome, GameError> {
        let State::AwaitingAnswer { shooter, cell } = self.state else {
            return Err(GameError::WrongState);
        };
        if shooter != self.local_role {
            return Err(GameError::WrongState);
        }
        let ctx = AnswerContext {
            defender_id: &self.ctx.peer_id,
            sid: &self.ctx.sid,
        };
        let outcome = answers::verify_answer(
            self.params,
            &ctx,
            self.peer.ship_cells(),
            self.peer.cell_commitments(),
            &self.peer_board,
            cell,
            answer,
        )
        .map_err(GameError::AnswerRejected)?;

        let result = match outcome {
            AnswerOutcome::Miss => ShotOutcome::Miss,
            AnswerOutcome::Hit => ShotOutcome::Hit,
            AnswerOutcome::Sunk { ship, cells } => {
                self.peer_board.mark_sunk_with_cells(ship, cells);
                ShotOutcome::Sunk { ship }
            }
        };
        if result != ShotOutcome::Miss {
            self.verified_hits += 1;
        }
        if self.verified_hits == T as u8 {
            if self.peer_board.unsunk_count() != 0 {
                return Err(GameError::InternalInvariantFailure(
                    "hit count reached T but some ship was never announced sunk",
                ));
            }
            self.finish(self.local_role);
            return Ok(ShotOutcome::Win);
        }
        if self.peer_board.unsunk_count() == 0 {
            return Err(GameError::InternalInvariantFailure(
                "all ships announced sunk before T verified hits",
            ));
        }
        self.state = State::AwaitingShot {
            shooter: self.local_role.other(),
        };
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::tests::{fleet_a, fleet_b};
    use crate::setup;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const ID_A: [u8; 32] = [0x0A; 32];
    const ID_B: [u8; 32] = [0x0B; 32];
    const SID: [u8; 32] = [0x77; 32];

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn blinders(seed: u8) -> Vec<Scalar> {
        let mut rng = rng(seed);
        (0..SHIP_BITS).map(|_| Scalar::random(&mut rng)).collect()
    }

    fn context(role: Role) -> GameContext {
        let (own_id, peer_id) = match role {
            Role::A => (ID_A, ID_B),
            Role::B => (ID_B, ID_A),
        };
        GameContext {
            own_id,
            peer_id,
            sid: SID,
        }
    }

    /// Two games wired to each other with real setup proofs.
    pub(crate) fn pair<'a>(
        params: &'a Parameters,
        fleets: [&Fleet; 2],
        first_mover: Role,
    ) -> (Game<'a>, Game<'a>) {
        let rho = [blinders(0xA0), blinders(0xB0)];
        let ids = [ID_A, ID_B];
        let msgs: Vec<setup::SetupMessage> = (0..2)
            .map(|k| {
                setup::prove_with_rng(
                    params,
                    &ids[k],
                    &SID,
                    fleets[k],
                    &rho[k],
                    rng(0xC0 + k as u8),
                )
                .unwrap()
            })
            .collect();
        let verified: Vec<VerifiedSetup> = (0..2)
            .map(|k| setup::verify(params, &ids[k], &SID, &msgs[k]).unwrap())
            .collect();
        let game = |k: usize, role: Role| {
            Game::new(
                params,
                role,
                first_mover,
                context(role),
                msgs[k].ship_cells().to_vec(),
                fleets[k],
                rho[k].clone(),
                &[0x5E + k as u8; 32],
                verified[1 - k].clone(),
            )
            .unwrap()
        };
        (game(0, Role::A), game(1, Role::B))
    }

    /// Plays one turn over the wire encoding.
    pub(crate) fn turn(attacker: &mut Game, attacked: &mut Game, cell: CellIndex) -> ShotOutcome {
        let byte = attacker.fire_shot(cell).unwrap();
        attacked.receive_shot(byte).unwrap();
        let answer = attacked.answer_shot().unwrap();
        let decoded = attacker.decode_answer(&answer.encode()).unwrap();
        assert_eq!(decoded, answer);
        attacker.accept_answer(&decoded).unwrap()
    }

    #[test]
    fn honest_full_game_completes() {
        for params in [Parameters::standard(), Parameters::no_touch()] {
            let (fa, fb) = (fleet_a(), fleet_b());
            let (mut game_a, mut game_b) = pair(params, [&fa, &fb], Role::A);
            let mut current = Role::A;
            let mut sunk_seen = Vec::new();
            let winner = loop {
                let defender = current.other();
                let (attacker, attacked) = match current {
                    Role::A => (&mut game_a, &mut game_b),
                    Role::B => (&mut game_b, &mut game_a),
                };
                let cell = (0..100u8)
                    .map(|i| CellIndex::from_index(i).unwrap())
                    .find(|c| !attacker.shots_on_board(defender).is_shot(*c))
                    .expect("unshot cells remain");
                match turn(attacker, attacked, cell) {
                    ShotOutcome::Win => break current,
                    ShotOutcome::Sunk { ship } => {
                        if current == Role::A {
                            sunk_seen.push(ship);
                        }
                        current = defender;
                    }
                    ShotOutcome::Miss | ShotOutcome::Hit => current = defender,
                }
            };
            // A sweeps rows 0-9 and reaches B's column fleet's last cell first.
            assert_eq!(winner, Role::A);
            assert_eq!(sunk_seen.len(), K - 1);
            assert_eq!(game_a.state(), State::Finished { winner: Role::A });
            assert_eq!(game_a.verified_hits(), T as u8);
            assert_eq!(game_a.peer_sunk(), [true; K]);
            for j in 0..K {
                assert_eq!(game_a.peer_sunk_cells(j).unwrap(), fb.cells(j).as_slice());
                assert_eq!(game_b.own_sunk_cells(j).unwrap(), fb.cells(j).as_slice());
            }
            assert!(game_b.verified_hits() < T as u8);
            assert!(!game_a.has_secrets() && !game_b.has_secrets());
            assert!(!game_a.has_answer_rng() && !game_b.has_answer_rng());
            assert!(game_a.snapshot_secrets().is_none() && game_b.snapshot_secrets().is_none());
            assert_eq!(game_b.state(), State::Finished { winner: Role::A });
            assert_eq!(game_b.hits_conceded(), T as u8);
            assert_eq!(game_a.hits_conceded(), game_b.verified_hits());
            let cell = CellIndex::from_index(99).unwrap();
            assert_eq!(game_a.fire_shot(cell), Err(GameError::WrongState));
            assert_eq!(game_b.receive_shot(99), Err(GameError::WrongState));
            assert_eq!(game_b.answer_shot(), Err(GameError::WrongState));
        }
    }

    #[test]
    fn state_machine_rejects_wrong_state_out_of_range_and_repeated_shots() {
        let (fa, fb) = (fleet_a(), fleet_b());
        let (mut game_a, mut game_b) = pair(Parameters::standard(), [&fa, &fb], Role::A);
        assert_eq!(game_a.state(), State::AwaitingShot { shooter: Role::A });
        assert_eq!(game_a.receive_shot(3), Err(GameError::WrongState));
        assert_eq!(game_a.answer_shot(), Err(GameError::WrongState));
        assert_eq!(
            game_b.fire_shot(CellIndex::from_index(3).unwrap()),
            Err(GameError::WrongState)
        );

        let cell = CellIndex::from_index(10).unwrap();
        assert_eq!(turn(&mut game_a, &mut game_b, cell), ShotOutcome::Miss);
        assert_eq!(game_a.state(), State::AwaitingShot { shooter: Role::B });
        assert_eq!(
            game_a.receive_shot(200),
            Err(GameError::OutOfRangeShot { cell: 200 })
        );
        assert_eq!(turn(&mut game_b, &mut game_a, cell), ShotOutcome::Miss);
        assert_eq!(
            game_a.fire_shot(cell),
            Err(GameError::RepeatedShot { cell: 10 })
        );
        // B cannot be made to answer the same cell twice either.
        game_a
            .fire_shot(CellIndex::from_index(11).unwrap())
            .unwrap();
        assert_eq!(
            game_b.receive_shot(10),
            Err(GameError::RepeatedShot { cell: 10 })
        );
    }

    #[test]
    fn answers_are_bound_to_the_defender() {
        let (fa, fb) = (fleet_a(), fleet_b());
        let (mut game_a, mut game_b) = pair(Parameters::standard(), [&fa, &fb], Role::A);
        // B's column 9 ship is hit at cell 9; a replay of B's hit proof
        // against A's context must fail.
        let cell = CellIndex::from_index(9).unwrap();
        let byte = game_a.fire_shot(cell).unwrap();
        game_b.receive_shot(byte).unwrap();
        let answer = game_b.answer_shot().unwrap();
        let mut wrong = game_a.clone_for_test();
        wrong.ctx.peer_id = ID_A;
        assert!(matches!(
            wrong.accept_answer(&answer),
            Err(GameError::AnswerRejected(
                AnswerRejection::NotSunkProofFailed
            ))
        ));
        assert_eq!(game_a.accept_answer(&answer), Ok(ShotOutcome::Hit));
    }

    #[test]
    fn forfeit_erases_secrets_and_stops_game() {
        let (fa, fb) = (fleet_a(), fleet_b());
        let (mut game, _) = pair(Parameters::standard(), [&fa, &fb], Role::A);
        assert!(game.has_secrets());
        assert!(game.has_answer_rng());
        game.finish_by_forfeit(Role::B).unwrap();
        assert_eq!(game.state(), State::Finished { winner: Role::B });
        assert!(!game.has_secrets());
        assert!(!game.has_answer_rng());
        assert_eq!(game.finish_by_forfeit(Role::A), Err(GameError::WrongState));
        assert_eq!(game.receive_shot(0), Err(GameError::WrongState));
        assert_eq!(game.answer_shot(), Err(GameError::WrongState));
    }

    #[test]
    fn construction_checks_witness_shapes() {
        let params = Parameters::standard();
        let (fa, fb) = (fleet_a(), fleet_b());
        let (game, _) = pair(params, [&fa, &fb], Role::A);
        let peer = game.peer.clone();
        let cells = game.own_ship_cells.clone();
        let make = |cells: Vec<RistrettoPoint>, rho: Vec<Scalar>| {
            Game::new(
                params,
                Role::A,
                Role::A,
                context(Role::A),
                cells,
                &fa,
                rho,
                &[0; 32],
                peer.clone(),
            )
            .err()
        };
        assert!(matches!(
            make(cells.clone(), blinders(1)[1..].to_vec()),
            Some(GameError::WrongWitnessLength { .. })
        ));
        assert!(matches!(
            make(cells[1..].to_vec(), blinders(1)),
            Some(GameError::WrongCommitmentCount { .. })
        ));
        let touching = Fleet::new(
            [
                crate::fleet::tests::ship(0, 0, false),
                crate::fleet::tests::ship(1, 0, false),
                crate::fleet::tests::ship(4, 0, false),
                crate::fleet::tests::ship(6, 0, false),
                crate::fleet::tests::ship(8, 0, false),
            ],
            crate::params::Rules::Standard,
        )
        .unwrap();
        assert!(matches!(
            Game::new(
                Parameters::no_touch(),
                Role::A,
                Role::A,
                context(Role::A),
                cells,
                &touching,
                blinders(1),
                &[0; 32],
                peer
            ),
            Err(GameError::IllegalPlacement(PlacementError::Touching { .. }))
        ));
    }

    impl Game<'_> {
        fn clone_for_test(&self) -> Self {
            Game {
                params: self.params,
                local_role: self.local_role,
                state: self.state,
                ctx: self.ctx,
                own_ship_cells: self.own_ship_cells.clone(),
                own_board: self.own_board.clone(),
                own_secrets: None,
                answer_rng: self.answer_rng.as_ref().map(|r| SeededRng(r.0.clone())),
                answer_seed: None,
                peer: self.peer.clone(),
                peer_board: self.peer_board.clone(),
                verified_hits: self.verified_hits,
                hits_conceded: self.hits_conceded,
            }
        }
    }
}
