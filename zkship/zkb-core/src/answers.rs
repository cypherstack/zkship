//! Shot answers (paper Constructions 5.2, 5.3; abstract, Methods): a shot at
//! cell `i` is answered by opening the derived board commitment `B_i`. After
//! a hit the defender either announces the sunk ship by opening its `l_j`
//! cell commitments, or proves with one aggregated range proof that every
//! unsunk ship has fewer than `l_j` hit cells, so a delayed sink announcement
//! fails on the turn it should have been made.
//!
//! The hit count of ship `j` is the value of `H_j = sum_{c in S} C_{j,c}`
//! over the shot set `S`; the proof shows `h_j + 8 - l_j in [0, 8)` for the
//! unsunk ships in index order. The setup's bit proof and length openings
//! already bound `h_j <= l_j`, so this rules out exactly `h_j = l_j`.
//!
//! Wire formats (the tag byte is framing, not part of the abstract's count):
//! * miss: `0x00 || rho` (33 bytes);
//! * hit: `0x01 || rho || proof`; the proof is 416, 480 or 544 bytes for 1,
//!   2 or 3-5 unsunk ships (3, 6 or 9-15 bits padded to 4, 8 or 16), so the
//!   abstract's hit cost of `rho` plus proof is at most 576 bytes;
//! * sunk: `0x02 || rho || ship u8 || l_j * (cell u8 || sigma)`, cells
//!   strictly increasing.
//!
//! Fiat-Shamir for the not-sunk proof: Merlin `zkbattleship/paper/v1/not-sunk`
//! over `pp`, the defender's id, `sid`, the number of shots on this board
//! (this one included) and the cell.

use crate::bp::range::{self, RangeProof};
use crate::bp::{read_scalar, BpError, PedersenBases};
use crate::fleet::{Fleet, SHIP_BITS};
use crate::params::{CellIndex, Parameters, FLEET_LENGTHS, K, N};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use std::fmt;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const TRANSCRIPT_LABEL: &[u8] = b"zkbattleship/paper/v1/not-sunk";

/// Bit width of the not-sunk range proof and the offset that maps
/// `h_j in [0, l_j)` to `[8 - l_j, 8)`.
pub const NOT_SUNK_BITS: usize = 3;
pub const NOT_SUNK_OFFSET: u64 = 1 << NOT_SUNK_BITS;

pub const MISS_LEN: usize = 33;

/// Encoded hit answer for `unsunk` unsunk ships (1..=K).
pub fn hit_len(unsunk: usize) -> usize {
    33 + range::encoded_len(NOT_SUNK_BITS, unsunk)
}

/// Encoded sunk answer for a ship of `length` cells.
pub fn sunk_len(length: u8) -> usize {
    34 + 33 * length as usize
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShotAnswer {
    Miss {
        rho: Scalar,
    },
    Hit {
        rho: Scalar,
        not_sunk: Box<RangeProof>,
    },
    Sunk {
        rho: Scalar,
        ship: u8,
        /// `(cell, sigma)` with `C_{ship,cell} = G + sigma H`, cells increasing.
        openings: Vec<(CellIndex, Scalar)>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnswerDecodeError {
    Empty,
    InvalidTag(u8),
    WrongLength { expected: usize, actual: usize },
    NoShipLeft,
    InvalidUnsunkCount(usize),
    InvalidShip(u8),
    InvalidCell { offset: usize },
    CellsNotIncreasing,
    NonCanonical { offset: usize },
}

impl fmt::Display for AnswerDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnswerDecodeError::Empty => write!(f, "empty answer"),
            AnswerDecodeError::InvalidTag(t) => write!(f, "answer tag {t}, expected 0, 1 or 2"),
            AnswerDecodeError::WrongLength { expected, actual } => {
                write!(f, "answer is {actual} bytes, expected {expected}")
            }
            AnswerDecodeError::NoShipLeft => write!(f, "hit answered after every ship sank"),
            AnswerDecodeError::InvalidUnsunkCount(n) => {
                write!(f, "unsunk ship count {n} exceeds fleet size {K}")
            }
            AnswerDecodeError::InvalidShip(s) => write!(f, "sunk ship index {s} out of range"),
            AnswerDecodeError::InvalidCell { offset } => {
                write!(f, "cell index at byte offset {offset} is off the board")
            }
            AnswerDecodeError::CellsNotIncreasing => {
                write!(f, "sunk-ship cells are not strictly increasing")
            }
            AnswerDecodeError::NonCanonical { offset } => {
                write!(f, "answer element at byte offset {offset} is not canonical")
            }
        }
    }
}

impl std::error::Error for AnswerDecodeError {}

impl ShotAnswer {
    pub fn is_hit(&self) -> bool {
        !matches!(self, ShotAnswer::Miss { .. })
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            ShotAnswer::Miss { rho } => {
                let mut out = Vec::with_capacity(MISS_LEN);
                out.push(0);
                out.extend_from_slice(rho.as_bytes());
                out
            }
            ShotAnswer::Hit { rho, not_sunk } => {
                let mut out = vec![1];
                out.extend_from_slice(rho.as_bytes());
                out.extend_from_slice(&not_sunk.encode());
                out
            }
            ShotAnswer::Sunk {
                rho,
                ship,
                openings,
            } => {
                let mut out = vec![2];
                out.extend_from_slice(rho.as_bytes());
                out.push(*ship);
                for (cell, sigma) in openings {
                    out.push(cell.index());
                    out.extend_from_slice(sigma.as_bytes());
                }
                out
            }
        }
    }

    /// Every length an answer can have, for framing checks that run before
    /// the game state is consulted.
    pub fn is_possible_length(tag: u8, len: usize) -> bool {
        match tag {
            0 => len == MISS_LEN,
            1 => (1..=K).any(|m| hit_len(m) == len),
            2 => FLEET_LENGTHS.iter().any(|&l| sunk_len(l) == len),
            _ => false,
        }
    }

    /// `unsunk` is the public number of ships not yet announced sunk; it fixes
    /// the hit proof's length.
    pub fn decode(bytes: &[u8], unsunk: usize) -> Result<ShotAnswer, AnswerDecodeError> {
        let (&tag, _) = bytes.split_first().ok_or(AnswerDecodeError::Empty)?;
        let expect = |expected: usize| {
            if bytes.len() == expected {
                Ok(())
            } else {
                Err(AnswerDecodeError::WrongLength {
                    expected,
                    actual: bytes.len(),
                })
            }
        };
        let scalar = |offset: usize| {
            read_scalar(bytes, offset).map_err(|_| AnswerDecodeError::NonCanonical { offset })
        };
        match tag {
            0 => {
                expect(MISS_LEN)?;
                Ok(ShotAnswer::Miss { rho: scalar(1)? })
            }
            1 => {
                if unsunk == 0 {
                    return Err(AnswerDecodeError::NoShipLeft);
                }
                if unsunk > K {
                    return Err(AnswerDecodeError::InvalidUnsunkCount(unsunk));
                }
                expect(hit_len(unsunk))?;
                let not_sunk = RangeProof::decode(&bytes[33..], NOT_SUNK_BITS, unsunk).map_err(
                    |e| match e {
                        crate::bp::BpError::InvalidPoint { offset }
                        | crate::bp::BpError::NonCanonicalScalar { offset } => {
                            AnswerDecodeError::NonCanonical {
                                offset: 33 + offset,
                            }
                        }
                        _ => AnswerDecodeError::WrongLength {
                            expected: hit_len(unsunk),
                            actual: bytes.len(),
                        },
                    },
                )?;
                Ok(ShotAnswer::Hit {
                    rho: scalar(1)?,
                    not_sunk: Box::new(not_sunk),
                })
            }
            2 => {
                let ship = *bytes.get(33).ok_or(AnswerDecodeError::WrongLength {
                    expected: 34,
                    actual: bytes.len(),
                })?;
                if ship as usize >= K {
                    return Err(AnswerDecodeError::InvalidShip(ship));
                }
                let length = FLEET_LENGTHS[ship as usize];
                expect(sunk_len(length))?;
                let rho = scalar(1)?;
                let mut openings = Vec::with_capacity(length as usize);
                for t in 0..length as usize {
                    let offset = 34 + 33 * t;
                    let cell = CellIndex::from_index(bytes[offset])
                        .ok_or(AnswerDecodeError::InvalidCell { offset })?;
                    if let Some((prev, _)) = openings.last() {
                        if cell <= *prev {
                            return Err(AnswerDecodeError::CellsNotIncreasing);
                        }
                    }
                    openings.push((cell, scalar(offset + 1)?));
                }
                Ok(ShotAnswer::Sunk {
                    rho,
                    ship,
                    openings,
                })
            }
            other => Err(AnswerDecodeError::InvalidTag(other)),
        }
    }
}

/// Public per-board tracking, identical on both sides: the shot set, the
/// running hit-count commitments `H_j` and which ships were announced sunk.
#[derive(Clone)]
pub struct BoardShots {
    shot: [bool; N],
    shots: u8,
    hit_commitments: [RistrettoPoint; K],
    sunk: [bool; K],
    sunk_cells: [Option<Vec<CellIndex>>; K],
}

impl Default for BoardShots {
    fn default() -> Self {
        BoardShots {
            shot: [false; N],
            shots: 0,
            hit_commitments: [RistrettoPoint::identity(); K],
            sunk: [false; K],
            sunk_cells: std::array::from_fn(|_| None),
        }
    }
}

impl BoardShots {
    pub fn is_shot(&self, cell: CellIndex) -> bool {
        self.shot[cell.index() as usize]
    }

    /// Shots on this board so far.
    pub fn shots(&self) -> u8 {
        self.shots
    }

    pub fn sunk(&self) -> &[bool; K] {
        &self.sunk
    }

    pub fn sunk_cells(&self, ship: usize) -> Option<&[CellIndex]> {
        self.sunk_cells.get(ship).and_then(|c| c.as_deref())
    }

    pub fn unsunk(&self) -> impl Iterator<Item = usize> + '_ {
        (0..K).filter(|&j| !self.sunk[j])
    }

    pub fn unsunk_count(&self) -> usize {
        self.unsunk().count()
    }

    /// Adds `cell` to the shot set; the caller has checked it is fresh.
    pub fn register(&mut self, ship_cells: &[RistrettoPoint], cell: CellIndex) {
        debug_assert!(!self.is_shot(cell));
        debug_assert_eq!(ship_cells.len(), SHIP_BITS);
        self.shot[cell.index() as usize] = true;
        self.shots += 1;
        for j in 0..K {
            self.hit_commitments[j] += ship_cells[j * N + cell.index() as usize];
        }
    }

    /// `V_j = H_j + (8 - l_j) G` for the unsunk ships, in index order.
    fn not_sunk_commitments(&self, params: &Parameters) -> Vec<RistrettoPoint> {
        self.unsunk()
            .map(|j| {
                self.hit_commitments[j]
                    + Scalar::from(NOT_SUNK_OFFSET - u64::from(FLEET_LENGTHS[j])) * params.g()
            })
            .collect()
    }
}

/// The defender's secrets for play: the fleet description, bits, blinders,
/// and running hit counts and hit-blinder sums per ship. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(fuzzing, derive(Clone))]
pub struct ResponderSecrets {
    fleet_bytes: [u8; 3 * K],
    bits: Vec<u8>,
    rho: Vec<Scalar>,
    hits: [u8; K],
    hit_blinders: [Scalar; K],
}

impl ResponderSecrets {
    pub fn new(fleet: &Fleet, rho: Vec<Scalar>) -> ResponderSecrets {
        assert_eq!(rho.len(), SHIP_BITS, "one blinder per ship cell");
        ResponderSecrets {
            fleet_bytes: *fleet.to_bytes(),
            bits: fleet.ship_bits().to_vec(),
            rho,
            hits: [0; K],
            hit_blinders: [Scalar::ZERO; K],
        }
    }

    pub(crate) fn fleet_bytes(&self) -> [u8; 3 * K] {
        self.fleet_bytes
    }

    pub(crate) fn rho(&self) -> &[Scalar] {
        &self.rho
    }

    /// Rekeys a nonce RNG with the defender's witness (the prover's hedge).
    pub(crate) fn rekey(
        &self,
        builder: merlin::TranscriptRngBuilder,
    ) -> merlin::TranscriptRngBuilder {
        let mut blinders = zeroize::Zeroizing::new(Vec::with_capacity(32 * K));
        for b in &self.hit_blinders {
            blinders.extend_from_slice(b.as_bytes());
        }
        builder
            .rekey_with_witness_bytes(b"bits", &self.bits)
            .rekey_with_witness_bytes(b"hit-blinders", &blinders)
    }

    /// Mirrors `BoardShots::register` on the secret side. The updates touch
    /// every ship, so which one was hit does not show in the access pattern.
    pub fn register(&mut self, cell: CellIndex) {
        for j in 0..K {
            let k = j * N + cell.index() as usize;
            self.hits[j] += self.bits[k];
            self.hit_blinders[j] += self.rho[k];
        }
    }
}

/// Session context of the defender's proofs.
#[derive(Clone, Copy)]
pub struct AnswerContext<'a> {
    pub defender_id: &'a [u8; 32],
    pub sid: &'a [u8; 32],
}

fn not_sunk_transcript(
    params: &Parameters,
    ctx: &AnswerContext,
    shots: u8,
    cell: CellIndex,
) -> Transcript {
    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    transcript.append_message(b"pp", params.canonical_params_bytes());
    transcript.append_message(b"defender-id", ctx.defender_id);
    transcript.append_message(b"sid", ctx.sid);
    transcript.append_message(b"shots", &[shots]);
    transcript.append_message(b"cell", &[cell.index()]);
    transcript
}

/// Fallible version of [`answer_shot`], returning an error if `range::prove`
/// fails (zero challenge or no unsunk ships).
pub fn try_answer_shot<R: RngCore + CryptoRng>(
    params: &Parameters,
    ctx: &AnswerContext,
    board: &BoardShots,
    secrets: &ResponderSecrets,
    cell: CellIndex,
    rng: &mut R,
) -> Result<ShotAnswer, BpError> {
    debug_assert!(board.is_shot(cell));
    let i = cell.index() as usize;
    let rho: Scalar = (0..K).map(|j| secrets.rho[j * N + i]).sum();
    // `hit`: some ship covers the cell; `sinks`: that ship now has all its
    // cells hit; `ship`: its index, meaningful only when it sinks.
    let mut hit = Choice::from(0);
    let mut sinks = Choice::from(0);
    let mut ship = 0u8;
    for (j, length) in FLEET_LENGTHS.iter().enumerate() {
        let covers = secrets.bits[j * N + i].ct_eq(&1);
        let full = secrets.hits[j].ct_eq(length);
        hit |= covers;
        sinks |= covers & full;
        ship.conditional_assign(&(j as u8), covers & full);
    }
    // Both branches are on what the answer's tag reveals anyway.
    if !bool::from(hit) {
        return Ok(ShotAnswer::Miss { rho });
    }
    if bool::from(sinks) {
        let ship = usize::from(ship);
        let openings = (0..N)
            .filter(|&c| secrets.bits[ship * N + c] == 1)
            .map(|c| {
                (
                    CellIndex::from_index(c as u8).expect("c < N"),
                    secrets.rho[ship * N + c],
                )
            })
            .collect();
        return Ok(ShotAnswer::Sunk {
            rho,
            ship: ship as u8,
            openings,
        });
    }
    let unsunk: Vec<usize> = board.unsunk().collect();
    let values = Zeroizing::new(
        unsunk
            .iter()
            .map(|&j| u64::from(secrets.hits[j]) + NOT_SUNK_OFFSET - u64::from(FLEET_LENGTHS[j]))
            .collect::<Vec<_>>(),
    );
    let blindings = Zeroizing::new(
        unsunk
            .iter()
            .map(|&j| secrets.hit_blinders[j])
            .collect::<Vec<_>>(),
    );
    let commitments = board.not_sunk_commitments(params);
    let mut transcript = not_sunk_transcript(params, ctx, board.shots(), cell);
    let not_sunk = range::prove(
        &mut transcript,
        params.bp_gens(),
        PedersenBases {
            g: params.g(),
            h: params.h(),
        },
        &commitments,
        &values,
        &blindings,
        NOT_SUNK_BITS,
        rng,
    )?;
    Ok(ShotAnswer::Hit {
        rho,
        not_sunk: Box::new(not_sunk),
    })
}

/// Honest answer to the shot at `cell`, which both `board` and `secrets`
/// have already registered. Visits every ship in constant time and branches
/// only on the public outcome.
pub fn answer_shot<R: RngCore + CryptoRng>(
    params: &Parameters,
    ctx: &AnswerContext,
    board: &BoardShots,
    secrets: &ResponderSecrets,
    cell: CellIndex,
    rng: &mut R,
) -> ShotAnswer {
    try_answer_shot(params, ctx, board, secrets, cell, rng)
        .expect("honest values are below 8; fails only on a zero challenge (paper Lemma 5.5)")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnswerOutcome {
    Miss,
    Hit,
    Sunk { ship: u8, cells: Vec<CellIndex> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnswerRejection {
    /// Setup ship-cell commitment slice does not have length `SHIP_BITS`.
    InvalidShipCommitments,
    /// `B_i` does not open to the claimed hit or miss.
    CellOpeningFailed,
    NotSunkProofFailed,
    ShipAlreadySunk {
        ship: u8,
    },
    SunkCellNotShot {
        cell: u8,
    },
    SunkShipMissesShotCell,
    SunkOpeningFailed {
        cell: u8,
    },
    /// Unknown ship, wrong number of cells, or cells not strictly increasing.
    MalformedSunkAnnouncement,
}

impl fmt::Display for AnswerRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnswerRejection::InvalidShipCommitments => {
                write!(f, "setup ship-cell commitment slice has the wrong length")
            }
            AnswerRejection::CellOpeningFailed => {
                write!(f, "hit/miss opening does not match the cell commitment")
            }
            AnswerRejection::NotSunkProofFailed => write!(f, "not-sunk proof does not verify"),
            AnswerRejection::ShipAlreadySunk { ship } => {
                write!(f, "ship {ship} was already announced sunk")
            }
            AnswerRejection::SunkCellNotShot { cell } => {
                write!(f, "sunk-ship cell {cell} has not been shot")
            }
            AnswerRejection::SunkShipMissesShotCell => {
                write!(f, "announced ship does not cover the shot cell")
            }
            AnswerRejection::SunkOpeningFailed { cell } => {
                write!(f, "sunk-ship opening at cell {cell} does not match")
            }
            AnswerRejection::MalformedSunkAnnouncement => {
                write!(f, "sunk-ship announcement has the wrong shape")
            }
        }
    }
}

impl std::error::Error for AnswerRejection {}

/// Checks an answer to the shot at `cell` against the verified setup's cell
/// commitments and the public board state (which has registered `cell`).
pub fn verify_answer(
    params: &Parameters,
    ctx: &AnswerContext,
    ship_cells: &[RistrettoPoint],
    cell_commitments: &[RistrettoPoint; N],
    board: &BoardShots,
    cell: CellIndex,
    answer: &ShotAnswer,
) -> Result<AnswerOutcome, AnswerRejection> {
    if ship_cells.len() != SHIP_BITS {
        return Err(AnswerRejection::InvalidShipCommitments);
    }
    let g = params.g();
    let h = params.h();
    let b_i = &cell_commitments[cell.index() as usize];
    match answer {
        ShotAnswer::Miss { rho } => {
            if *b_i != rho * h {
                return Err(AnswerRejection::CellOpeningFailed);
            }
            Ok(AnswerOutcome::Miss)
        }
        ShotAnswer::Hit { rho, not_sunk } => {
            if *b_i != g + rho * h {
                return Err(AnswerRejection::CellOpeningFailed);
            }
            let commitments = board.not_sunk_commitments(params);
            let mut transcript = not_sunk_transcript(params, ctx, board.shots(), cell);
            not_sunk
                .verify(
                    &mut transcript,
                    params.bp_gens(),
                    PedersenBases { g, h },
                    &commitments,
                    NOT_SUNK_BITS,
                )
                .map_err(|_| AnswerRejection::NotSunkProofFailed)?;
            Ok(AnswerOutcome::Hit)
        }
        ShotAnswer::Sunk {
            rho,
            ship,
            openings,
        } => {
            if *b_i != g + rho * h {
                return Err(AnswerRejection::CellOpeningFailed);
            }
            let j = *ship as usize;
            // The decoder enforces shape; checked again here because
            // answers can also be built in-process.
            if j >= K
                || openings.len() != FLEET_LENGTHS[j] as usize
                || openings.windows(2).any(|w| w[0].0 >= w[1].0)
            {
                return Err(AnswerRejection::MalformedSunkAnnouncement);
            }
            if board.sunk()[j] {
                return Err(AnswerRejection::ShipAlreadySunk { ship: *ship });
            }
            if !openings.iter().any(|(c, _)| *c == cell) {
                return Err(AnswerRejection::SunkShipMissesShotCell);
            }
            for (c, sigma) in openings {
                if !board.is_shot(*c) {
                    return Err(AnswerRejection::SunkCellNotShot { cell: c.index() });
                }
                if ship_cells[j * N + c.index() as usize] != g + sigma * h {
                    return Err(AnswerRejection::SunkOpeningFailed { cell: c.index() });
                }
            }
            Ok(AnswerOutcome::Sunk {
                ship: *ship,
                cells: openings.iter().map(|(c, _)| *c).collect(),
            })
        }
    }
}

impl BoardShots {
    /// Records an accepted sink announcement.
    pub fn mark_sunk(&mut self, ship: u8) {
        if let Some(slot) = self.sunk.get_mut(ship as usize) {
            *slot = true;
        }
    }

    /// Records an accepted sink announcement together with its verified cells.
    pub fn mark_sunk_with_cells(&mut self, ship: u8, cells: Vec<CellIndex>) {
        let j = ship as usize;
        if j < K {
            self.sunk[j] = true;
            self.sunk_cells[j] = Some(cells);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::tests::{fleet_a, fleet_b};
    use crate::setup;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const DEFENDER: [u8; 32] = [0xD1; 32];
    const SID: [u8; 32] = [0x5D; 32];

    fn ctx() -> AnswerContext<'static> {
        AnswerContext {
            defender_id: &DEFENDER,
            sid: &SID,
        }
    }

    struct Board {
        params: &'static Parameters,
        verified: setup::VerifiedSetup,
        public: BoardShots,
        secrets: ResponderSecrets,
        rng: ChaCha20Rng,
    }

    impl Board {
        fn new(fleet: &Fleet) -> Board {
            let params = Parameters::standard();
            let mut rng = ChaCha20Rng::from_seed([4; 32]);
            let rho: Vec<Scalar> = (0..SHIP_BITS).map(|_| Scalar::random(&mut rng)).collect();
            let msg =
                setup::prove_with_rng(params, &DEFENDER, &SID, fleet, &rho, rng.clone()).unwrap();
            let verified = setup::verify(params, &DEFENDER, &SID, &msg).unwrap();
            Board {
                params,
                verified,
                public: BoardShots::default(),
                secrets: ResponderSecrets::new(fleet, rho),
                rng,
            }
        }

        fn shoot(&mut self, cell: u8) -> (ShotAnswer, Result<AnswerOutcome, AnswerRejection>) {
            let cell = CellIndex::from_index(cell).unwrap();
            self.public.register(self.verified.ship_cells(), cell);
            self.secrets.register(cell);
            let answer = answer_shot(
                self.params,
                &ctx(),
                &self.public,
                &self.secrets,
                cell,
                &mut self.rng,
            );
            let outcome = self.check(cell, &answer);
            if let Ok(AnswerOutcome::Sunk { ship, .. }) = &outcome {
                self.public.mark_sunk(*ship);
            }
            (answer, outcome)
        }

        fn check_unencoded(
            &self,
            cell: CellIndex,
            answer: &ShotAnswer,
        ) -> Result<AnswerOutcome, AnswerRejection> {
            verify_answer(
                self.params,
                &ctx(),
                self.verified.ship_cells(),
                self.verified.cell_commitments(),
                &self.public,
                cell,
                answer,
            )
        }

        fn check(
            &self,
            cell: CellIndex,
            answer: &ShotAnswer,
        ) -> Result<AnswerOutcome, AnswerRejection> {
            let bytes = answer.encode();
            assert!(ShotAnswer::is_possible_length(bytes[0], bytes.len()));
            let decoded = ShotAnswer::decode(&bytes, self.public.unsunk_count()).unwrap();
            assert_eq!(&decoded, answer);
            verify_answer(
                self.params,
                &ctx(),
                self.verified.ship_cells(),
                self.verified.cell_commitments(),
                &self.public,
                cell,
                answer,
            )
        }
    }

    #[test]
    fn full_board_sweep() {
        let fleet = fleet_b();
        let occupied = fleet.occupied();
        let mut board = Board::new(&fleet);
        let (mut hits, mut sunk, mut sizes) = (0, Vec::new(), Vec::new());
        for cell in 0..N as u8 {
            let (answer, outcome) = board.shoot(cell);
            let outcome = outcome.unwrap();
            assert_eq!(answer.is_hit(), occupied[cell as usize]);
            sizes.push((answer.encode()[0], answer.encode().len()));
            match outcome {
                AnswerOutcome::Miss => {}
                AnswerOutcome::Hit => hits += 1,
                AnswerOutcome::Sunk { ship, cells } => {
                    hits += 1;
                    assert_eq!(cells, fleet.cells(ship as usize));
                    sunk.push(ship);
                }
            }
        }
        assert_eq!(hits, 17);
        sunk.sort();
        assert_eq!(sunk, [0, 1, 2, 3, 4]);
        assert!(sizes.contains(&(0, 33)));
        assert!(sizes.contains(&(1, 33 + 544)));
        assert!(sizes.contains(&(2, sunk_len(5))));
        assert_eq!(hit_len(5), 577);
        assert_eq!([1, 2, 3, 4, 5].map(hit_len), [449, 513, 577, 577, 577]);
    }

    /// The constant-time scan in `answer_shot` must pick the same outcome as
    /// a plain early-exit search for the covering ship, on every cell of two
    /// fleets shot in a scrambled order, so plain hits and sinks land on
    /// every ship at different points of the game.
    #[test]
    fn answers_match_an_early_exit_reference() {
        for fleet in [fleet_a(), fleet_b()] {
            let mut board = Board::new(&fleet);
            let mut kinds = [0usize; 3];
            for t in 0..N {
                let index = ((t * 37 + 11) % N) as u8;
                let i = index as usize;
                let expected = match (0..K).find(|&j| board.secrets.bits[j * N + i] == 1) {
                    None => AnswerOutcome::Miss,
                    Some(j) if board.secrets.hits[j] + 1 == FLEET_LENGTHS[j] => {
                        AnswerOutcome::Sunk {
                            ship: j as u8,
                            cells: fleet.cells(j),
                        }
                    }
                    Some(_) => AnswerOutcome::Hit,
                };
                let (answer, outcome) = board.shoot(index);
                let expected_rho: Scalar = (0..K).map(|j| board.secrets.rho[j * N + i]).sum();
                let rho = match &answer {
                    ShotAnswer::Miss { rho }
                    | ShotAnswer::Hit { rho, .. }
                    | ShotAnswer::Sunk { rho, .. } => *rho,
                };
                assert_eq!(rho, expected_rho, "cell {index}");
                kinds[answer.encode()[0] as usize] += 1;
                assert_eq!(outcome, Ok(expected), "cell {index}");
            }
            assert_eq!(kinds, [N - 17, 17 - K, K]);
        }
    }

    #[test]
    fn lying_about_a_cell_is_rejected() {
        let mut board = Board::new(&fleet_a());
        // Cell 0 is a hit: answering "miss" with the right blinder fails.
        let (answer, _) = board.shoot(0);
        let ShotAnswer::Hit { rho, .. } = answer else {
            panic!("expected hit")
        };
        let cell = CellIndex::from_index(0).unwrap();
        assert_eq!(
            board.check(cell, &ShotAnswer::Miss { rho }),
            Err(AnswerRejection::CellOpeningFailed)
        );
        // Cell 10 is a miss: claiming a hit fails whatever the proof.
        let (miss, _) = board.shoot(10);
        let ShotAnswer::Miss { rho } = miss else {
            panic!("expected miss")
        };
        let cell = CellIndex::from_index(10).unwrap();
        let ShotAnswer::Hit { not_sunk, .. } = answer else {
            unreachable!()
        };
        assert_eq!(
            board.check(cell, &ShotAnswer::Hit { rho, not_sunk }),
            Err(AnswerRejection::CellOpeningFailed)
        );
    }

    /// A defender who hides a sinking by sending a "hit" whose range proof
    /// is produced over the wrapped value.
    #[test]
    fn delayed_sink_announcement_is_rejected() {
        let fleet = fleet_a();
        let mut board = Board::new(&fleet);
        // Ship 4 (length 2) is cells 80, 81.
        board.shoot(80).1.unwrap();
        let cell = CellIndex::from_index(81).unwrap();
        board.public.register(board.verified.ship_cells(), cell);
        board.secrets.register(cell);
        let rho: Scalar = (0..K).map(|j| board.secrets.rho[j * N + 81]).sum();
        let unsunk: Vec<usize> = board.public.unsunk().collect();
        let values: Vec<u64> = unsunk
            .iter()
            .map(|&j| {
                u64::from(board.secrets.hits[j]) + NOT_SUNK_OFFSET - u64::from(FLEET_LENGTHS[j])
            })
            .collect();
        assert_eq!(values[4], 8);
        let blindings: Vec<Scalar> = unsunk
            .iter()
            .map(|&j| board.secrets.hit_blinders[j])
            .collect();
        let not_sunk = range::prove_unchecked_for_test(
            &mut not_sunk_transcript(board.params, &ctx(), board.public.shots(), cell),
            board.params.bp_gens(),
            PedersenBases {
                g: board.params.g(),
                h: board.params.h(),
            },
            &board.public.not_sunk_commitments(board.params),
            &values,
            &blindings,
            NOT_SUNK_BITS,
            &mut board.rng,
        )
        .unwrap();
        assert_eq!(
            board.check(
                cell,
                &ShotAnswer::Hit {
                    rho,
                    not_sunk: Box::new(not_sunk)
                }
            ),
            Err(AnswerRejection::NotSunkProofFailed)
        );
        // The honest answer is the sink announcement.
        let honest = answer_shot(
            board.params,
            &ctx(),
            &board.public,
            &board.secrets,
            cell,
            &mut board.rng,
        );
        assert!(matches!(
            board.check(cell, &honest),
            Ok(AnswerOutcome::Sunk { ship: 4, .. })
        ));
    }

    #[test]
    fn premature_or_wrong_sink_announcements_are_rejected() {
        let fleet = fleet_a();
        let mut board = Board::new(&fleet);
        let rho_of =
            |b: &Board, c: usize| -> Scalar { (0..K).map(|j| b.secrets.rho[j * N + c]).sum() };
        let opening = |b: &Board, j: usize, c: u8| {
            (
                CellIndex::from_index(c).unwrap(),
                b.secrets.rho[j * N + c as usize],
            )
        };
        // One hit on ship 4 (cells 80, 81): announcing it sunk is premature.
        board.shoot(80).1.unwrap();
        let cell = CellIndex::from_index(80).unwrap();
        let premature = ShotAnswer::Sunk {
            rho: rho_of(&board, 80),
            ship: 4,
            openings: vec![opening(&board, 4, 80), opening(&board, 4, 81)],
        };
        assert_eq!(
            board.check(cell, &premature),
            Err(AnswerRejection::SunkCellNotShot { cell: 81 })
        );
        // Sink ship 4 properly, then try to announce it again.
        let (_, outcome) = board.shoot(81);
        assert!(matches!(outcome, Ok(AnswerOutcome::Sunk { ship: 4, .. })));
        let again = ShotAnswer::Sunk {
            rho: rho_of(&board, 81),
            ship: 4,
            openings: vec![opening(&board, 4, 80), opening(&board, 4, 81)],
        };
        let cell = CellIndex::from_index(81).unwrap();
        assert_eq!(
            board.check(cell, &again),
            Err(AnswerRejection::ShipAlreadySunk { ship: 4 })
        );
        // Ship 3 is cells 60-62; cell 70 is empty. At the hit on 61, claim
        // ship 3 sunk with 70 in place of 62.
        for c in [60u8, 70, 61] {
            board.shoot(c).1.unwrap();
        }
        let cell = CellIndex::from_index(61).unwrap();
        let wrong = ShotAnswer::Sunk {
            rho: rho_of(&board, 61),
            ship: 3,
            openings: vec![
                opening(&board, 3, 60),
                opening(&board, 3, 61),
                opening(&board, 3, 70),
            ],
        };
        assert_eq!(
            board.check(cell, &wrong),
            Err(AnswerRejection::SunkOpeningFailed { cell: 70 })
        );
        // An announcement that does not include the shot cell.
        let elsewhere = ShotAnswer::Sunk {
            rho: rho_of(&board, 61),
            ship: 0,
            openings: (0..5).map(|c| opening(&board, 0, c)).collect(),
        };
        assert_eq!(
            board.check(cell, &elsewhere),
            Err(AnswerRejection::SunkShipMissesShotCell)
        );
    }

    /// Built in-process, bypassing the decoder: one real cell opened twice
    /// must not pass for a sunk length-2 ship, nor may an unknown ship index.
    #[test]
    fn malformed_sink_announcements_are_rejected_without_the_decoder() {
        let mut board = Board::new(&fleet_a());
        board.shoot(80).1.unwrap();
        let cell = CellIndex::from_index(80).unwrap();
        let rho: Scalar = (0..K).map(|j| board.secrets.rho[j * N + 80]).sum();
        let sigma = board.secrets.rho[4 * N + 80];
        let doubled = ShotAnswer::Sunk {
            rho,
            ship: 4,
            openings: vec![(cell, sigma), (cell, sigma)],
        };
        assert_eq!(
            board.check_unencoded(cell, &doubled),
            Err(AnswerRejection::MalformedSunkAnnouncement)
        );
        let short = ShotAnswer::Sunk {
            rho,
            ship: 4,
            openings: vec![(cell, sigma)],
        };
        assert_eq!(
            board.check_unencoded(cell, &short),
            Err(AnswerRejection::MalformedSunkAnnouncement)
        );
        let unknown = ShotAnswer::Sunk {
            rho,
            ship: K as u8,
            openings: vec![(cell, sigma)],
        };
        assert_eq!(
            board.check_unencoded(cell, &unknown),
            Err(AnswerRejection::MalformedSunkAnnouncement)
        );
    }

    #[test]
    fn not_sunk_proofs_are_bound_to_turn_and_session() {
        let mut board = Board::new(&fleet_a());
        let (answer, outcome) = board.shoot(0);
        assert_eq!(outcome, Ok(AnswerOutcome::Hit));
        let cell = CellIndex::from_index(0).unwrap();
        let other_sid = [0xEE; 32];
        let other = AnswerContext {
            defender_id: &DEFENDER,
            sid: &other_sid,
        };
        let result = verify_answer(
            board.params,
            &other,
            board.verified.ship_cells(),
            board.verified.cell_commitments(),
            &board.public,
            cell,
            &answer,
        );
        assert_eq!(result, Err(AnswerRejection::NotSunkProofFailed));
        // Replayed on the next hit of the same ship: the shot count differs.
        board.shoot(1).1.unwrap();
        let cell = CellIndex::from_index(1).unwrap();
        let ShotAnswer::Hit { not_sunk, .. } = answer else {
            unreachable!()
        };
        let rho: Scalar = (0..K).map(|j| board.secrets.rho[j * N + 1]).sum();
        assert_eq!(
            board.check(cell, &ShotAnswer::Hit { rho, not_sunk }),
            Err(AnswerRejection::NotSunkProofFailed)
        );
    }

    #[test]
    fn decode_rejects_malformed_answers() {
        let mut board = Board::new(&fleet_a());
        let (hit, _) = board.shoot(0);
        let bytes = hit.encode();
        assert_eq!(ShotAnswer::decode(&[], 5), Err(AnswerDecodeError::Empty));
        assert_eq!(
            ShotAnswer::decode(&[3; 33], 5),
            Err(AnswerDecodeError::InvalidTag(3))
        );
        assert!(matches!(
            ShotAnswer::decode(&bytes, 2),
            Err(AnswerDecodeError::WrongLength { .. })
        ));
        assert_eq!(
            ShotAnswer::decode(&bytes, 0),
            Err(AnswerDecodeError::NoShipLeft)
        );
        let mut bad = bytes.clone();
        bad[1..33].fill(0xff);
        assert_eq!(
            ShotAnswer::decode(&bad, 5),
            Err(AnswerDecodeError::NonCanonical { offset: 1 })
        );
        let mut bad = bytes.clone();
        bad[33..65].fill(0xff);
        assert_eq!(
            ShotAnswer::decode(&bad, 5),
            Err(AnswerDecodeError::NonCanonical { offset: 33 })
        );

        board.shoot(80).1.unwrap();
        let (sunk, _) = board.shoot(81);
        let bytes = sunk.encode();
        assert_eq!(bytes.len(), sunk_len(2));
        let mut bad = bytes.clone();
        bad[33] = 5;
        assert_eq!(
            ShotAnswer::decode(&bad, 5),
            Err(AnswerDecodeError::InvalidShip(5))
        );
        let mut bad = bytes.clone();
        bad[33] = 0;
        assert!(matches!(
            ShotAnswer::decode(&bad, 5),
            Err(AnswerDecodeError::WrongLength { .. })
        ));
        let mut bad = bytes.clone();
        bad[34] = 100;
        assert_eq!(
            ShotAnswer::decode(&bad, 5),
            Err(AnswerDecodeError::InvalidCell { offset: 34 })
        );
        let mut bad = bytes.clone();
        bad[67] = bad[34];
        assert_eq!(
            ShotAnswer::decode(&bad, 5),
            Err(AnswerDecodeError::CellsNotIncreasing)
        );
        assert!(!ShotAnswer::is_possible_length(1, 34));
        assert!(ShotAnswer::is_possible_length(2, sunk_len(3)));
        assert_eq!(
            ShotAnswer::decode(&hit.encode(), usize::MAX),
            Err(AnswerDecodeError::InvalidUnsunkCount(usize::MAX))
        );
    }

    #[test]
    fn guards_reject_bad_ship_cells_and_out_of_range_mark_sunk() {
        let mut board = Board::new(&fleet_a());
        let (hit, _) = board.shoot(0);
        let cell = CellIndex::from_index(0).unwrap();
        assert_eq!(
            verify_answer(
                board.params,
                &ctx(),
                &board.verified.ship_cells()[..SHIP_BITS - 1],
                board.verified.cell_commitments(),
                &board.public,
                cell,
                &hit,
            ),
            Err(AnswerRejection::InvalidShipCommitments)
        );
        board.public.mark_sunk(u8::MAX);
        board.public.mark_sunk_with_cells(4, fleet_a().cells(4));
        assert!(board.public.sunk()[4]);
        assert_eq!(
            board.public.sunk_cells(4),
            Some(fleet_a().cells(4).as_slice())
        );
    }
}
