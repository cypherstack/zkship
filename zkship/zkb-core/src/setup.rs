//! The setup message (paper Construction 4.1; abstract, Methods): a fleet
//! committed as one indicator vector per ship, with a proof of legality, sent
//! once before play.
//!
//! Commitments: `C_{j,i} = s_{j,i} G + rho_{j,i} H` for ship `j`, cell `i`;
//! `O_j` to the orientation bit `o_j`; and `Q_{j,x}`, `Q_{j,y}` to the squared
//! first moments `(sum_i x_i s_{j,i})^2`, `(sum_i y_i s_{j,i})^2`, where
//! `x_i`, `y_i` are the row and column of cell `i`.
//!
//! Derived by both sides: board cells `B_i = sum_j C_{j,i}`, ship sums
//! `L_j = sum_i C_{j,i}`, and the moment commitments `X1_j = sum_i x_i C_{j,i}`,
//! `X2_j = sum_i x_i^2 C_{j,i}` (and `Y1_j`, `Y2_j` with columns).
//!
//! Proof:
//! * length: `L_j - l_j G = lambda_j H`, one revealed scalar per ship;
//! * squares: the Σ-protocol of `sigma::square` for `(X1_j, Q_{j,x})` and
//!   `(Y1_j, Q_{j,y})`;
//! * straightness, paper eq. (5) (abstract eq. (2)):
//!   `l X2_j - Q_{j,x} - K_l O_j = delta_{j,x} H` and
//!   `l Y2_j - Q_{j,y} - K_l (G - O_j) = delta_{j,y} H`, one revealed scalar
//!   per axis per ship, with `K_l = l^2 (l^2 - 1) / 12`;
//! * bits and non-overlap: one aggregated Bulletproof that every `C_{j,i}`,
//!   every `B_i` and every `O_j` commits to a bit (605 values);
//! * no-touch profile only: one aggregated Bulletproof that
//!   `y_{j,i} = 255 (1 - s_{j,i}) - sum_{i' ~ i} (b_{i'} - s_{j,i'})` is in
//!   `[0, 2^8)` for every ship and cell (500 values), where `i' ~ i` ranges
//!   over the eight neighbours. If ship `j` covers `i` this forces the count
//!   of other ships' cells around `i` to zero; otherwise it is at most 8.
//!
//! Fiat-Shamir: one Merlin transcript `zkbattleship/paper/v1/setup` over
//! `pp`, `prover-id`, `sid`, `C`, `O`, `Q`, the Σ first messages, challenge
//! `c`, the responses and revealed scalars, then the range proofs.
//!
//! Size (standard): 559 group elements and 50 scalars, 19,488 bytes.

use crate::bp::range::{self, RangeProof};
use crate::bp::{read_point, read_scalar, BpError, PedersenBases};
use crate::fleet::{self, Fleet, PlacementError, SHIP_BITS};
use crate::params::{CellIndex, Parameters, Rules, FLEET_LENGTHS, K, N};
use crate::sigma::square::{self, SquareFirstMessage, SquareProver, SquareResponse};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use merlin::Transcript;
use rand_core::{CryptoRng, OsRng, RngCore};
use std::fmt;
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroizing;

const TRANSCRIPT_LABEL: &[u8] = b"zkbattleship/paper/v1/setup";

/// Values in the bit proof: ship cells, board cells, orientations.
pub const BIT_VALUES: usize = SHIP_BITS + N + K;
/// Big-M constant and bit width of the no-touch proof.
pub const NO_TOUCH_M: u64 = 255;
pub const NO_TOUCH_BITS: usize = 8;

const COMMITMENT_POINTS: usize = SHIP_BITS + K + 2 * K;
const SIGMA_POINTS: usize = 2 * 2 * K;
const SIGMA_SCALARS: usize = 3 * 2 * K;
const OPENING_SCALARS: usize = K + 2 * K;

/// `K_l = l^2 (l^2 - 1) / 12`, the least spread of `l` distinct integers.
pub const fn min_spread(length: u8) -> u64 {
    if length <= 1 {
        return 0;
    }
    let l2 = (length as u64) * (length as u64);
    l2 * (l2 - 1) / 12
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupError {
    IllegalFleet(PlacementError),
    WrongBlinderLength { expected: usize, actual: usize },
    WrongLength { expected: usize, actual: usize },
    InvalidPoint { offset: usize },
    NonCanonicalScalar { offset: usize },
    VerificationFailed,
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetupError::IllegalFleet(e) => write!(f, "illegal fleet: {e}"),
            SetupError::WrongBlinderLength { expected, actual } => {
                write!(f, "blinder vector has length {actual}, expected {expected}")
            }
            SetupError::WrongLength { expected, actual } => {
                write!(f, "setup message is {actual} bytes, expected {expected}")
            }
            SetupError::InvalidPoint { offset } => {
                write!(f, "setup point at byte offset {offset} is invalid")
            }
            SetupError::NonCanonicalScalar { offset } => {
                write!(f, "setup scalar at byte offset {offset} is not canonical")
            }
            SetupError::VerificationFailed => write!(f, "setup proof does not verify"),
        }
    }
}

impl std::error::Error for SetupError {}

fn from_bp(offset: usize, e: BpError) -> SetupError {
    match e {
        BpError::InvalidPoint { offset: o } => SetupError::InvalidPoint { offset: offset + o },
        BpError::NonCanonicalScalar { offset: o } => {
            SetupError::NonCanonicalScalar { offset: offset + o }
        }
        BpError::WrongLength { expected, actual } => SetupError::WrongLength { expected, actual },
        _ => SetupError::VerificationFailed,
    }
}

/// Commitments and proof, as sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupMessage {
    /// `C_{j,i}` at `j*N + i`.
    pub ship_cells: Vec<RistrettoPoint>,
    pub orientation: [RistrettoPoint; K],
    /// `[Q_{j,x}, Q_{j,y}]`.
    pub squares: [[RistrettoPoint; 2]; K],
    pub square_firsts: [[SquareFirstMessage; 2]; K],
    pub square_responses: [[SquareResponse; 2]; K],
    pub length_openings: [Scalar; K],
    pub moment_openings: [[Scalar; 2]; K],
    pub bits: RangeProof,
    pub no_touch: Option<RangeProof>,
}

/// A setup whose proof verified under the session context. Caches the board
/// cell commitments for play.
#[derive(Clone)]
pub struct VerifiedSetup {
    ship_cells: Vec<RistrettoPoint>,
    cell_commitments: [RistrettoPoint; N],
}

impl VerifiedSetup {
    pub fn ship_cells(&self) -> &[RistrettoPoint] {
        &self.ship_cells
    }

    pub fn cell_commitments(&self) -> &[RistrettoPoint; N] {
        &self.cell_commitments
    }
}

#[cfg(test)]
impl VerifiedSetup {
    /// Skips proof verification; test-only.
    pub(crate) fn from_ship_cells_for_test(ship_cells: Vec<RistrettoPoint>) -> VerifiedSetup {
        let cell_commitments = cell_commitments(&ship_cells);
        VerifiedSetup {
            ship_cells,
            cell_commitments,
        }
    }
}

/// `B_i = sum_j C_{j,i}`.
pub fn cell_commitments(ship_cells: &[RistrettoPoint]) -> [RistrettoPoint; N] {
    assert_eq!(ship_cells.len(), SHIP_BITS);
    std::array::from_fn(|i| (0..K).map(|j| ship_cells[j * N + i]).sum())
}

fn coordinate(i: usize, axis: usize) -> u64 {
    let cell = CellIndex::from_index(i as u8).expect("i < N");
    u64::from(if axis == 0 { cell.row() } else { cell.col() })
}

/// `[X1, X2]` for `axis = 0` (rows) or `[Y1, Y2]` for `axis = 1` (columns).
fn moment_commitments(ship: &[RistrettoPoint], axis: usize) -> [RistrettoPoint; 2] {
    std::array::from_fn(|power| {
        RistrettoPoint::vartime_multiscalar_mul(
            (0..N).map(|i| Scalar::from(coordinate(i, axis).pow(power as u32 + 1))),
            ship,
        )
    })
}

/// `l D2 - Q - K_l O` (rows) or `l D2 - Q - K_l (G - O)` (columns): commits
/// to zero exactly when paper eq. (5) holds for that axis.
fn straightness_commitment(
    params: &Parameters,
    j: usize,
    axis: usize,
    second_moment: &RistrettoPoint,
    square: &RistrettoPoint,
    orientation: &RistrettoPoint,
) -> RistrettoPoint {
    let l = Scalar::from(u64::from(FLEET_LENGTHS[j]));
    let k = Scalar::from(min_spread(FLEET_LENGTHS[j]));
    let base = l * second_moment - square;
    if axis == 0 {
        base - k * orientation
    } else {
        base - k * params.g() + k * orientation
    }
}

/// `Y_{j,i} = 255 G - 255 C_{j,i} - sum_{i' ~ i} (B_{i'} - C_{j,i'})`.
pub fn no_touch_commitments(
    params: &Parameters,
    ship_cells: &[RistrettoPoint],
    cells: &[RistrettoPoint; N],
) -> Vec<RistrettoPoint> {
    let big_m = Scalar::from(NO_TOUCH_M);
    let m_g = big_m * params.g();
    let mut out = Vec::with_capacity(SHIP_BITS);
    for j in 0..K {
        for i in 0..N {
            let cell = CellIndex::from_index(i as u8).expect("i < N");
            let others: RistrettoPoint = fleet::neighbours(cell)
                .map(|c| cells[c.index() as usize] - ship_cells[j * N + c.index() as usize])
                .sum();
            out.push(m_g - big_m * ship_cells[j * N + i] - others);
        }
    }
    out
}

pub fn encoded_len(rules: Rules) -> usize {
    let base = 32 * (COMMITMENT_POINTS + SIGMA_POINTS + SIGMA_SCALARS + OPENING_SCALARS)
        + range::encoded_len(1, BIT_VALUES);
    match rules {
        Rules::Standard => base,
        Rules::NoTouch => base + range::encoded_len(NO_TOUCH_BITS, SHIP_BITS),
    }
}

fn statement_transcript(
    params: &Parameters,
    prover_id: &[u8; 32],
    sid: &[u8; 32],
    msg_points: &[u8],
) -> Transcript {
    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    transcript.append_message(b"pp", params.canonical_params_bytes());
    transcript.append_message(b"prover-id", prover_id);
    transcript.append_message(b"sid", sid);
    transcript.append_message(b"commitments", msg_points);
    transcript
}

fn append_firsts(transcript: &mut Transcript, firsts: &[[SquareFirstMessage; 2]; K]) {
    for pair in firsts {
        for first in pair {
            transcript.append_message(b"sq-T1", first.t1.compress().as_bytes());
            transcript.append_message(b"sq-T2", first.t2.compress().as_bytes());
        }
    }
}

fn append_responses(
    transcript: &mut Transcript,
    responses: &[[SquareResponse; 2]; K],
    lengths: &[Scalar; K],
    moments: &[[Scalar; 2]; K],
) {
    for pair in responses {
        for z in pair {
            transcript.append_message(b"sq-za", z.za.as_bytes());
            transcript.append_message(b"sq-z1", z.z1.as_bytes());
            transcript.append_message(b"sq-z2", z.z2.as_bytes());
        }
    }
    for lambda in lengths {
        transcript.append_message(b"lambda", lambda.as_bytes());
    }
    for pair in moments {
        for delta in pair {
            transcript.append_message(b"delta", delta.as_bytes());
        }
    }
}

fn challenge(transcript: &mut Transcript) -> Scalar {
    let mut bytes = [0u8; 64];
    transcript.challenge_bytes(b"c", &mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

fn encode_commitment_points(
    ship_cells: &[RistrettoPoint],
    orientation: &[RistrettoPoint; K],
    squares: &[[RistrettoPoint; 2]; K],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * COMMITMENT_POINTS);
    for p in ship_cells
        .iter()
        .chain(orientation)
        .chain(squares.iter().flatten())
    {
        out.extend_from_slice(p.compress().as_bytes());
    }
    out
}

impl SetupMessage {
    pub fn ship_cells(&self) -> &[RistrettoPoint] {
        &self.ship_cells
    }

    /// `C || O || Q || T || z || lambda || delta || bits [|| no-touch]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = encode_commitment_points(&self.ship_cells, &self.orientation, &self.squares);
        for pair in &self.square_firsts {
            for first in pair {
                out.extend_from_slice(first.t1.compress().as_bytes());
                out.extend_from_slice(first.t2.compress().as_bytes());
            }
        }
        for pair in &self.square_responses {
            for z in pair {
                out.extend_from_slice(z.za.as_bytes());
                out.extend_from_slice(z.z1.as_bytes());
                out.extend_from_slice(z.z2.as_bytes());
            }
        }
        for lambda in &self.length_openings {
            out.extend_from_slice(lambda.as_bytes());
        }
        for delta in self.moment_openings.iter().flatten() {
            out.extend_from_slice(delta.as_bytes());
        }
        out.extend_from_slice(&self.bits.encode());
        if let Some(proof) = &self.no_touch {
            out.extend_from_slice(&proof.encode());
        }
        out
    }

    /// Exact length for the profile; canonical points and scalars.
    pub fn decode(bytes: &[u8], rules: Rules) -> Result<SetupMessage, SetupError> {
        let expected = encoded_len(rules);
        if bytes.len() != expected {
            return Err(SetupError::WrongLength {
                expected,
                actual: bytes.len(),
            });
        }
        let point = |k: usize| read_point(bytes, 32 * k).map_err(|e| from_bp(0, e));
        let scalar = |k: usize| read_scalar(bytes, 32 * k).map_err(|e| from_bp(0, e));

        let ship_cells = (0..SHIP_BITS).map(point).collect::<Result<Vec<_>, _>>()?;
        let mut k = SHIP_BITS;
        let mut orientation = [RistrettoPoint::identity(); K];
        for o in &mut orientation {
            *o = point(k)?;
            k += 1;
        }
        let mut squares = [[RistrettoPoint::identity(); 2]; K];
        for q in squares.iter_mut().flatten() {
            *q = point(k)?;
            k += 1;
        }
        let mut square_firsts = [[SquareFirstMessage {
            t1: RistrettoPoint::identity(),
            t2: RistrettoPoint::identity(),
        }; 2]; K];
        for first in square_firsts.iter_mut().flatten() {
            first.t1 = point(k)?;
            first.t2 = point(k + 1)?;
            k += 2;
        }
        let mut square_responses = [[SquareResponse {
            za: Scalar::ZERO,
            z1: Scalar::ZERO,
            z2: Scalar::ZERO,
        }; 2]; K];
        for z in square_responses.iter_mut().flatten() {
            z.za = scalar(k)?;
            z.z1 = scalar(k + 1)?;
            z.z2 = scalar(k + 2)?;
            k += 3;
        }
        let mut length_openings = [Scalar::ZERO; K];
        for lambda in &mut length_openings {
            *lambda = scalar(k)?;
            k += 1;
        }
        let mut moment_openings = [[Scalar::ZERO; 2]; K];
        for delta in moment_openings.iter_mut().flatten() {
            *delta = scalar(k)?;
            k += 1;
        }
        let bits_start = 32 * k;
        let bits_end = bits_start + range::encoded_len(1, BIT_VALUES);
        let bits = RangeProof::decode(&bytes[bits_start..bits_end], 1, BIT_VALUES)
            .map_err(|e| from_bp(bits_start, e))?;
        let no_touch = match rules {
            Rules::Standard => None,
            Rules::NoTouch => Some(
                RangeProof::decode(&bytes[bits_end..], NO_TOUCH_BITS, SHIP_BITS)
                    .map_err(|e| from_bp(bits_end, e))?,
            ),
        };
        Ok(SetupMessage {
            ship_cells,
            orientation,
            squares,
            square_firsts,
            square_responses,
            length_openings,
            moment_openings,
            bits,
            no_touch,
        })
    }
}

/// Production prover; finalizes the hedged RNG with `OsRng`.
pub fn prove(
    params: &Parameters,
    prover_id: &[u8; 32],
    sid: &[u8; 32],
    fleet: &Fleet,
    blinders: &[Scalar],
) -> Result<SetupMessage, SetupError> {
    prove_with_rng(params, prover_id, sid, fleet, blinders, OsRng)
}

/// Prover with injected finalization RNG so tests can pin proof bytes. Never
/// pass a deterministic RNG outside tests. `blinders` are the `rho_{j,i}`
/// (ship-major), which the defender keeps for play.
pub fn prove_with_rng<R: RngCore + CryptoRng>(
    params: &Parameters,
    prover_id: &[u8; 32],
    sid: &[u8; 32],
    fleet: &Fleet,
    blinders: &[Scalar],
    finalize_rng: R,
) -> Result<SetupMessage, SetupError> {
    if blinders.len() != SHIP_BITS {
        return Err(SetupError::WrongBlinderLength {
            expected: SHIP_BITS,
            actual: blinders.len(),
        });
    }
    // The fleet may have been validated under other rules.
    Fleet::new(*fleet.ships(), params.rules()).map_err(SetupError::IllegalFleet)?;
    let bits = fleet.ship_bits();
    let orientation = Zeroizing::new(fleet.orientation_bits());
    let witness = Witness {
        bits: &bits,
        orientation: &orientation,
        blinders,
        fleet_bytes: &fleet.to_bytes()[..],
    };
    prove_witness(params, prover_id, sid, &witness, finalize_rng, true)
}

struct Witness<'a> {
    bits: &'a [u8],
    orientation: &'a [u8; K],
    blinders: &'a [Scalar],
    fleet_bytes: &'a [u8],
}

/// The prover algorithm over a raw witness. `checked = false` lets tests play
/// a cheating prover: range proofs are then produced over the low bits of
/// out-of-range values instead of being refused.
fn prove_witness<R: RngCore + CryptoRng>(
    params: &Parameters,
    prover_id: &[u8; 32],
    sid: &[u8; 32],
    w: &Witness,
    mut finalize_rng: R,
    checked: bool,
) -> Result<SetupMessage, SetupError> {
    let g = params.g();
    let h = params.h();
    let rho = w.blinders;

    // C_{j,i} = s G + rho H: fixed-base table for the secret blinder, and a
    // branch-free select for the secret bit.
    let identity = RistrettoPoint::identity();
    let ship_cells: Vec<RistrettoPoint> = (0..SHIP_BITS)
        .map(|k| {
            params.h_table() * &rho[k]
                + RistrettoPoint::conditional_select(&identity, g, Choice::from(w.bits[k] & 1))
        })
        .collect();
    let cells = cell_commitments(&ship_cells);

    // Hedged nonces (paper Remark 8.8): Merlin RNG over the label, `pp`,
    // prover id and `sid`, rekeyed with the witness (fleet bytes, `rho`),
    // finalized with external entropy.
    let mut prefix = Transcript::new(TRANSCRIPT_LABEL);
    prefix.append_message(b"pp", params.canonical_params_bytes());
    prefix.append_message(b"prover-id", prover_id);
    prefix.append_message(b"sid", sid);
    let mut rho_bytes = Zeroizing::new(Vec::with_capacity(32 * SHIP_BITS));
    for r in rho {
        rho_bytes.extend_from_slice(r.as_bytes());
    }
    let mut rng = prefix
        .build_rng()
        .rekey_with_witness_bytes(b"fleet", w.fleet_bytes)
        .rekey_with_witness_bytes(b"rho", &rho_bytes)
        .finalize(&mut finalize_rng);
    drop(rho_bytes);

    let r_o: Zeroizing<[Scalar; K]> =
        Zeroizing::new(std::array::from_fn(|_| Scalar::random(&mut rng)));
    let r_q: Zeroizing<[[Scalar; 2]; K]> = Zeroizing::new(std::array::from_fn(|_| {
        [Scalar::random(&mut rng), Scalar::random(&mut rng)]
    }));

    // The value goes through the fixed-base table rather than a select so the
    // cheating test prover can commit to non-bits.
    let orientation: [RistrettoPoint; K] = std::array::from_fn(|j| {
        params.h_table() * &r_o[j] + params.g_table() * &Scalar::from(w.orientation[j])
    });

    // Moments over the integers: a = sum coord * s, and the blinders of
    // the derived X1 = sum coord C and X2 = sum coord^2 C.
    let mut first_moment = Zeroizing::new([[0u64; 2]; K]);
    let mut r1 = Zeroizing::new([[Scalar::ZERO; 2]; K]);
    let mut r2 = Zeroizing::new([[Scalar::ZERO; 2]; K]);
    for j in 0..K {
        for axis in 0..2 {
            for i in 0..N {
                let c = coordinate(i, axis);
                first_moment[j][axis] += c * u64::from(w.bits[j * N + i]);
                r1[j][axis] += Scalar::from(c) * rho[j * N + i];
                r2[j][axis] += Scalar::from(c * c) * rho[j * N + i];
            }
        }
    }
    let squares: [[RistrettoPoint; 2]; K] = std::array::from_fn(|j| {
        std::array::from_fn(|axis| {
            let a = Zeroizing::new(Scalar::from(first_moment[j][axis]));
            params.g_table() * &(*a * *a) + params.h_table() * &r_q[j][axis]
        })
    });

    let commitment_bytes = encode_commitment_points(&ship_cells, &orientation, &squares);
    let mut transcript = statement_transcript(params, prover_id, sid, &commitment_bytes);

    let moments: Vec<[[RistrettoPoint; 2]; 2]> = (0..K)
        .map(|j| {
            let ship = &ship_cells[j * N..(j + 1) * N];
            [moment_commitments(ship, 0), moment_commitments(ship, 1)]
        })
        .collect();

    let mut provers: Vec<SquareProver> = Vec::with_capacity(2 * K);
    let mut square_firsts = [[SquareFirstMessage {
        t1: identity,
        t2: identity,
    }; 2]; K];
    for j in 0..K {
        for axis in 0..2 {
            let (prover, first) = SquareProver::new(
                g,
                h,
                &moments[j][axis][0],
                &Scalar::from(first_moment[j][axis]),
                &r1[j][axis],
                &r_q[j][axis],
                &mut rng,
            );
            provers.push(prover);
            square_firsts[j][axis] = first;
        }
    }
    append_firsts(&mut transcript, &square_firsts);
    let c = challenge(&mut transcript);

    let mut square_responses = [[SquareResponse {
        za: Scalar::ZERO,
        z1: Scalar::ZERO,
        z2: Scalar::ZERO,
    }; 2]; K];
    for (k, prover) in provers.iter_mut().enumerate() {
        square_responses[k / 2][k % 2] = prover.respond_in_place(&c);
    }
    let length_openings: [Scalar; K] =
        std::array::from_fn(|j| rho[j * N..(j + 1) * N].iter().sum());
    let moment_openings: [[Scalar; 2]; K] = std::array::from_fn(|j| {
        let l = Scalar::from(u64::from(FLEET_LENGTHS[j]));
        let k = Scalar::from(min_spread(FLEET_LENGTHS[j]));
        [
            l * r2[j][0] - r_q[j][0] - k * r_o[j],
            l * r2[j][1] - r_q[j][1] + k * r_o[j],
        ]
    });
    append_responses(
        &mut transcript,
        &square_responses,
        &length_openings,
        &moment_openings,
    );

    // Bits: ship cells, board cells, orientations.
    let beta: Zeroizing<Vec<Scalar>> = Zeroizing::new(
        (0..N)
            .map(|i| (0..K).map(|j| rho[j * N + i]).sum())
            .collect(),
    );
    let board_bits: Zeroizing<Vec<u64>> = Zeroizing::new(
        (0..N)
            .map(|i| (0..K).map(|j| u64::from(w.bits[j * N + i])).sum())
            .collect(),
    );
    let bit_commitments: Vec<RistrettoPoint> = ship_cells
        .iter()
        .chain(&cells)
        .chain(&orientation)
        .copied()
        .collect();
    let bit_values: Zeroizing<Vec<u64>> = Zeroizing::new(
        w.bits
            .iter()
            .map(|&b| u64::from(b))
            .chain(board_bits.iter().copied())
            .chain(w.orientation.iter().map(|&o| u64::from(o)))
            .collect(),
    );
    let bit_blindings: Zeroizing<Vec<Scalar>> = Zeroizing::new(
        rho.iter()
            .chain(beta.iter())
            .chain(r_o.iter())
            .copied()
            .collect(),
    );
    let bits = range_prove(
        params,
        checked,
        &mut transcript,
        &bit_commitments,
        &bit_values,
        &bit_blindings,
        1,
        &mut rng,
    )?;

    let no_touch = match params.rules() {
        Rules::Standard => None,
        Rules::NoTouch => {
            let commitments = no_touch_commitments(params, &ship_cells, &cells);
            let mut values = Zeroizing::new(Vec::with_capacity(SHIP_BITS));
            let mut blindings = Zeroizing::new(Vec::with_capacity(SHIP_BITS));
            let big_m = Scalar::from(NO_TOUCH_M);
            for j in 0..K {
                for i in 0..N {
                    let cell = CellIndex::from_index(i as u8).expect("i < N");
                    let mut others = 0i64;
                    let mut others_blind = Scalar::ZERO;
                    for c in fleet::neighbours(cell) {
                        let c = c.index() as usize;
                        others += board_bits[c] as i64 - i64::from(w.bits[j * N + c]);
                        others_blind += beta[c] - rho[j * N + c];
                    }
                    let own = i64::from(w.bits[j * N + i]);
                    let y = NO_TOUCH_M as i64 * (1 - own) - others;
                    // Mask to 8 bits branchlessly: negative only for an illegal fleet,
                    // which then proves `y mod 2^8` while `Y_{j,i}` commits to `p - |y|`.
                    values.push((y as u64) & ((1u64 << NO_TOUCH_BITS) - 1));
                    blindings.push(-big_m * rho[j * N + i] - others_blind);
                }
            }
            Some(range_prove(
                params,
                checked,
                &mut transcript,
                &commitments,
                &values,
                &blindings,
                NO_TOUCH_BITS,
                &mut rng,
            )?)
        }
    };

    Ok(SetupMessage {
        ship_cells,
        orientation,
        squares,
        square_firsts,
        square_responses,
        length_openings,
        moment_openings,
        bits,
        no_touch,
    })
}

#[allow(clippy::too_many_arguments)]
fn range_prove<R: RngCore + CryptoRng>(
    params: &Parameters,
    checked: bool,
    transcript: &mut Transcript,
    commitments: &[RistrettoPoint],
    values: &[u64],
    blindings: &[Scalar],
    n: usize,
    rng: &mut R,
) -> Result<RangeProof, SetupError> {
    let bases = PedersenBases {
        g: params.g(),
        h: params.h(),
    };
    let gens = params.bp_gens();
    let result = if checked {
        range::prove(
            transcript,
            gens,
            bases,
            commitments,
            values,
            blindings,
            n,
            rng,
        )
    } else {
        range::prove_unchecked_for_test(
            transcript,
            gens,
            bases,
            commitments,
            values,
            blindings,
            n,
            rng,
        )
    };
    result.map_err(|_| SetupError::VerificationFailed)
}

/// Verifier. Variable-time arithmetic is fine here: all inputs are public.
pub fn verify(
    params: &Parameters,
    prover_id: &[u8; 32],
    sid: &[u8; 32],
    msg: &SetupMessage,
) -> Result<VerifiedSetup, SetupError> {
    if msg.ship_cells.len() != SHIP_BITS
        || msg.no_touch.is_some() != (params.rules() == Rules::NoTouch)
    {
        return Err(SetupError::VerificationFailed);
    }
    let g = params.g();
    let h = params.h();
    let cells = cell_commitments(&msg.ship_cells);

    let commitment_bytes =
        encode_commitment_points(&msg.ship_cells, &msg.orientation, &msg.squares);
    let mut transcript = statement_transcript(params, prover_id, sid, &commitment_bytes);
    append_firsts(&mut transcript, &msg.square_firsts);
    let c = challenge(&mut transcript);

    for (j, &length) in FLEET_LENGTHS.iter().enumerate() {
        let ship = &msg.ship_cells[j * N..(j + 1) * N];

        // Length.
        let sum: RistrettoPoint = ship.iter().sum();
        let l = Scalar::from(u64::from(length));
        if sum - l * g != msg.length_openings[j] * h {
            return Err(SetupError::VerificationFailed);
        }

        for axis in 0..2 {
            let [first, second] = moment_commitments(ship, axis);
            let square = &msg.squares[j][axis];
            if !square::verify(
                g,
                h,
                &first,
                square,
                &msg.square_firsts[j][axis],
                &c,
                &msg.square_responses[j][axis],
            ) {
                return Err(SetupError::VerificationFailed);
            }
            let d = straightness_commitment(params, j, axis, &second, square, &msg.orientation[j]);
            if d != msg.moment_openings[j][axis] * h {
                return Err(SetupError::VerificationFailed);
            }
        }
    }
    append_responses(
        &mut transcript,
        &msg.square_responses,
        &msg.length_openings,
        &msg.moment_openings,
    );

    let bases = PedersenBases { g, h };
    let bit_commitments: Vec<RistrettoPoint> = msg
        .ship_cells
        .iter()
        .chain(&cells)
        .chain(&msg.orientation)
        .copied()
        .collect();
    msg.bits
        .verify(
            &mut transcript,
            params.bp_gens(),
            bases,
            &bit_commitments,
            1,
        )
        .map_err(|_| SetupError::VerificationFailed)?;

    if let Some(proof) = &msg.no_touch {
        let commitments = no_touch_commitments(params, &msg.ship_cells, &cells);
        proof
            .verify(
                &mut transcript,
                params.bp_gens(),
                bases,
                &commitments,
                NO_TOUCH_BITS,
            )
            .map_err(|_| SetupError::VerificationFailed)?;
    }

    Ok(VerifiedSetup {
        ship_cells: msg.ship_cells.clone(),
        cell_commitments: cells,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::tests::{fleet_a, fleet_b, ship};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const PROVER_ID: [u8; 32] = [0xA1; 32];
    const SID: [u8; 32] = [0x5D; 32];

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn blinders(seed: u8) -> Vec<Scalar> {
        let mut rng = rng(seed);
        (0..SHIP_BITS).map(|_| Scalar::random(&mut rng)).collect()
    }

    fn setup(params: &Parameters, fleet: &Fleet) -> SetupMessage {
        prove_with_rng(params, &PROVER_ID, &SID, fleet, &blinders(0x42), rng(0x77)).unwrap()
    }

    fn rejects(params: &Parameters, msg: &SetupMessage) -> bool {
        matches!(
            verify(params, &PROVER_ID, &SID, msg),
            Err(SetupError::VerificationFailed)
        )
    }

    #[test]
    fn abstract_sizes() {
        assert_eq!(COMMITMENT_POINTS + SIGMA_POINTS + 24, 559);
        assert_eq!(SIGMA_SCALARS + OPENING_SCALARS + 5, 50);
        assert_eq!(encoded_len(Rules::Standard), (559 + 50) * 32);
        assert_eq!(encoded_len(Rules::Standard), 19_488);
        assert_eq!(encoded_len(Rules::NoTouch), 19_488 + (28 + 5) * 32);
        assert_eq!(BIT_VALUES, 605);
        assert_eq!(
            [5, 4, 3, 2, 1, 0].map(min_spread),
            [50, 20, 6, 1, 0, 0],
            "K_l = l^2 (l^2 - 1) / 12"
        );
    }

    #[test]
    fn honest_setups_verify_and_roundtrip() {
        let mut chacha = rng(0x11);
        for params in [Parameters::standard(), Parameters::no_touch()] {
            let rules = params.rules();
            let mut fleets = vec![fleet_a(), fleet_b()];
            fleets.push(Fleet::random(&mut chacha, rules));
            for fleet in fleets {
                let msg = setup(params, &fleet);
                let verified = verify(params, &PROVER_ID, &SID, &msg).unwrap();
                assert_eq!(verified.ship_cells(), msg.ship_cells());
                let bytes = msg.encode();
                assert_eq!(bytes.len(), encoded_len(rules));
                assert_eq!(SetupMessage::decode(&bytes, rules).unwrap(), msg);
            }
        }
    }

    #[test]
    fn board_cells_open_to_occupancy() {
        let params = Parameters::standard();
        let fleet = fleet_a();
        let rho = blinders(0x42);
        let msg = setup(params, &fleet);
        let cells = cell_commitments(msg.ship_cells());
        let occupied = fleet.occupied();
        for i in 0..N {
            let beta: Scalar = (0..K).map(|j| rho[j * N + i]).sum();
            let b = Scalar::from(u64::from(occupied[i]));
            assert_eq!(cells[i], b * params.g() + beta * params.h());
        }
    }

    #[test]
    fn deterministic_vector_is_pinned() {
        use sha2::{Digest, Sha512_256};
        let fleet = Fleet::from_bytes(
            &[0, 0, 0, 2, 0, 0, 4, 0, 0, 5, 0, 0, 7, 0, 0],
            Rules::Standard,
        )
        .unwrap();
        let mut chacha = rng(0x42);
        let rho: Vec<Scalar> = (0..SHIP_BITS)
            .map(|_| Scalar::random(&mut chacha))
            .collect();
        let msg = prove_with_rng(
            Parameters::standard(),
            &PROVER_ID,
            &SID,
            &fleet,
            &rho,
            rng(0x77),
        )
        .unwrap();
        let digest: String = Sha512_256::digest(msg.encode())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        // Mirrors examples/generate_setup_vector.rs.
        assert_eq!(
            digest,
            "0080ba7f74eaf6c8e425032324a57540094b5722ab9650cc02609d90ffce4c85"
        );
    }

    #[test]
    fn deterministic_with_injected_rng() {
        let params = Parameters::standard();
        assert_eq!(setup(params, &fleet_a()), setup(params, &fleet_a()));
        let other = prove_with_rng(
            params,
            &PROVER_ID,
            &SID,
            &fleet_a(),
            &blinders(0x42),
            rng(0x78),
        )
        .unwrap();
        assert_ne!(other, setup(params, &fleet_a()));
    }

    #[test]
    fn context_and_profile_binding() {
        let params = Parameters::standard();
        let msg = setup(params, &fleet_a());
        assert!(verify(params, &[0xEE; 32], &SID, &msg).is_err());
        assert!(verify(params, &PROVER_ID, &[0xEE; 32], &msg).is_err());
        assert!(verify(Parameters::no_touch(), &PROVER_ID, &SID, &msg).is_err());
        let with_rule = setup(Parameters::no_touch(), &fleet_a());
        assert!(verify(params, &PROVER_ID, &SID, &with_rule).is_err());
        // Strip the no-touch proof: the other profile's transcript differs.
        let mut stripped = with_rule.clone();
        stripped.no_touch = None;
        assert!(rejects(params, &stripped));
    }

    #[test]
    fn tampering_is_rejected() {
        let params = Parameters::no_touch();
        let msg = setup(params, &fleet_a());
        let g = *params.g();
        let one = Scalar::ONE;
        let mut cases: Vec<(&str, SetupMessage)> = Vec::new();
        let mut push = |name, f: &dyn Fn(&mut SetupMessage)| {
            let mut m = msg.clone();
            f(&mut m);
            cases.push((name, m));
        };
        push("C", &|m| m.ship_cells[7] += g);
        push("C swap", &|m| m.ship_cells.swap(0, 100));
        push("O", &|m| m.orientation[2] += g);
        push("Q", &|m| m.squares[1][0] += g);
        push("T", &|m| m.square_firsts[3][1].t2 += g);
        push("z", &|m| m.square_responses[0][1].z1 += one);
        push("lambda", &|m| m.length_openings[4] += one);
        push("delta", &|m| m.moment_openings[2][0] += one);
        push("bits", &|m| m.bits.tamper_t_hat());
        push("no-touch swap", &|m| {
            let other = setup(Parameters::no_touch(), &fleet_b());
            m.no_touch = other.no_touch;
        });
        for (name, m) in cases {
            assert!(rejects(params, &m), "accepted tampered {name}");
        }
    }

    type Ships<'a> = [&'a [(u8, u8)]; K];

    fn raw_witness(ships: Ships, orientation: [u8; K]) -> (Vec<u8>, [u8; K]) {
        let mut bits = vec![0u8; SHIP_BITS];
        for (j, cells) in ships.iter().enumerate() {
            for &(r, c) in *cells {
                bits[j * N + (r as usize) * 10 + c as usize] = 1;
            }
        }
        (bits, orientation)
    }

    fn cheat(params: &Parameters, ships: Ships, orientation: [u8; K]) -> SetupMessage {
        let (bits, orientation) = raw_witness(ships, orientation);
        let rho = blinders(0x42);
        let w = Witness {
            bits: &bits,
            orientation: &orientation,
            blinders: &rho,
            fleet_bytes: &[],
        };
        prove_witness(params, &PROVER_ID, &SID, &w, rng(0x55), false).unwrap()
    }

    const S5: &[(u8, u8)] = &[(0, 0), (0, 1), (0, 2), (0, 3), (0, 4)];
    const S4: &[(u8, u8)] = &[(2, 0), (2, 1), (2, 2), (2, 3)];
    const S3A: &[(u8, u8)] = &[(4, 0), (4, 1), (4, 2)];
    const S3B: &[(u8, u8)] = &[(6, 0), (6, 1), (6, 2)];
    const S2: &[(u8, u8)] = &[(8, 0), (8, 1)];

    #[test]
    fn cheating_prover_with_the_honest_fleet_verifies() {
        // Sanity check of the cheating harness itself.
        for params in [Parameters::standard(), Parameters::no_touch()] {
            let msg = cheat(params, [S5, S4, S3A, S3B, S2], [0; K]);
            verify(params, &PROVER_ID, &SID, &msg).unwrap();
        }
    }

    #[test]
    fn illegal_fleets_are_rejected() {
        let params = Parameters::standard();
        let bent: &[(u8, u8)] = &[(0, 0), (0, 1), (0, 2), (0, 3), (1, 3)];
        let gapped: &[(u8, u8)] = &[(0, 0), (0, 1), (0, 2), (0, 3), (0, 5)];
        let diagonal: &[(u8, u8)] = &[(0, 5), (1, 6), (2, 7), (3, 8), (4, 9)];
        let short: &[(u8, u8)] = &[(0, 0), (0, 1), (0, 2), (0, 3)];
        let long: &[(u8, u8)] = &[(0, 0), (0, 1), (0, 2), (0, 3), (0, 4), (0, 5)];
        let split: &[(u8, u8)] = &[(0, 0), (0, 1), (0, 2), (5, 5), (5, 6)];
        let overlap: &[(u8, u8)] = &[(0, 3), (0, 4)];
        let cases: [(&str, Ships, [u8; K]); 9] = [
            ("bent", [bent, S4, S3A, S3B, S2], [0; K]),
            (
                "bent, other orientation",
                [bent, S4, S3A, S3B, S2],
                [1, 0, 0, 0, 0],
            ),
            ("gapped", [gapped, S4, S3A, S3B, S2], [0; K]),
            ("diagonal", [diagonal, S4, S3A, S3B, S2], [0; K]),
            (
                "diagonal, vertical",
                [diagonal, S4, S3A, S3B, S2],
                [1, 0, 0, 0, 0],
            ),
            ("short", [short, S4, S3A, S3B, S2], [0; K]),
            ("long", [long, S4, S3A, S3B, S2], [0; K]),
            ("split", [split, S4, S3A, S3B, S2], [0; K]),
            ("overlap", [S5, S4, S3A, S3B, overlap], [0; K]),
        ];
        for (name, ships, orientation) in cases {
            assert!(
                rejects(params, &cheat(params, ships, orientation)),
                "accepted {name}"
            );
        }
        // Orientation that disagrees with the ship, or is not a bit.
        assert!(rejects(
            params,
            &cheat(params, [S5, S4, S3A, S3B, S2], [0, 0, 1, 0, 0])
        ));
        assert!(rejects(
            params,
            &cheat(params, [S5, S4, S3A, S3B, S2], [0, 0, 0, 0, 2])
        ));
    }

    #[test]
    fn touching_fleet_is_rejected_only_under_no_touch() {
        let s4: &[(u8, u8)] = &[(1, 0), (1, 1), (1, 2), (1, 3)];
        let diagonal_s2: &[(u8, u8)] = &[(1, 5), (1, 6)];
        for ships in [[S5, s4, S3A, S3B, S2], [S5, S4, S3A, S3B, diagonal_s2]] {
            let standard = Parameters::standard();
            verify(standard, &PROVER_ID, &SID, &cheat(standard, ships, [0; K])).unwrap();
            let no_touch = Parameters::no_touch();
            assert!(rejects(no_touch, &cheat(no_touch, ships, [0; K])));
        }
    }

    #[test]
    fn prover_refuses_bad_witnesses() {
        let touching = Fleet::new(
            [
                ship(0, 0, false),
                ship(1, 0, false),
                ship(4, 0, false),
                ship(6, 0, false),
                ship(8, 0, false),
            ],
            Rules::Standard,
        )
        .unwrap();
        assert!(matches!(
            prove(
                Parameters::no_touch(),
                &PROVER_ID,
                &SID,
                &touching,
                &blinders(1)
            ),
            Err(SetupError::IllegalFleet(PlacementError::Touching { .. }))
        ));
        prove(
            Parameters::standard(),
            &PROVER_ID,
            &SID,
            &touching,
            &blinders(1),
        )
        .unwrap();
        assert!(matches!(
            prove(
                Parameters::standard(),
                &PROVER_ID,
                &SID,
                &fleet_a(),
                &blinders(1)[1..]
            ),
            Err(SetupError::WrongBlinderLength { .. })
        ));
    }

    #[test]
    fn decode_rejects_bad_encodings() {
        let msg = setup(Parameters::standard(), &fleet_a());
        let bytes = msg.encode();
        assert!(matches!(
            SetupMessage::decode(&bytes[1..], Rules::Standard),
            Err(SetupError::WrongLength { .. })
        ));
        assert!(matches!(
            SetupMessage::decode(&bytes, Rules::NoTouch),
            Err(SetupError::WrongLength { .. })
        ));
        let mut bad = bytes.clone();
        bad[64..96].fill(0xff);
        assert_eq!(
            SetupMessage::decode(&bad, Rules::Standard),
            Err(SetupError::InvalidPoint { offset: 64 })
        );
        let scalar_offset = 32 * (COMMITMENT_POINTS + SIGMA_POINTS);
        let mut bad = bytes.clone();
        bad[scalar_offset..scalar_offset + 32].fill(0xff);
        assert_eq!(
            SetupMessage::decode(&bad, Rules::Standard),
            Err(SetupError::NonCanonicalScalar {
                offset: scalar_offset
            })
        );
        let mut bad = bytes.clone();
        let last = bad.len() - 32;
        bad[last..].fill(0xff);
        assert_eq!(
            SetupMessage::decode(&bad, Rules::Standard),
            Err(SetupError::NonCanonicalScalar { offset: last })
        );
    }
}
