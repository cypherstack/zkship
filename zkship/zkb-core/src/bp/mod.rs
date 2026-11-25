//! Bulletproofs (Bünz et al. 2018): the inner-product argument and aggregated
//! range proofs used by the setup proof and the not-sunk proofs. Values are
//! committed as `v*G + gamma*H` with the protocol's own `G`, `H`; the vector
//! generators are hashed to the group, so nobody knows relations among them.
//!
//! Unlike the dalek `bulletproofs` crate, the bit width may be any `n >= 1`
//! and the number of values any `m >= 1`: the `n*m` bit slots are padded to
//! a power of two with free slots that carry no value weight. The paper's
//! bit proof is `n = 1, m = 605` (1,024 slots, 24 group elements).

pub mod ipa;
pub mod range;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use sha2::Sha512;

/// Vector generators `G_k`, `H_k`, `k < capacity`: `hash_to_group(domain ||
/// label || k as u32 LE)` for labels `G` and `H`.
pub struct BpGens {
    g_vec: Vec<RistrettoPoint>,
    h_vec: Vec<RistrettoPoint>,
}

impl BpGens {
    pub fn derive(domain: &[u8], capacity: usize) -> BpGens {
        assert!(
            capacity > 0 && capacity.is_power_of_two(),
            "capacity must be a non-zero power of two"
        );
        let point = |label: &[u8], k: usize| {
            let idx = u32::try_from(k).expect("generator index fits u32");
            let mut input = Vec::with_capacity(domain.len() + label.len() + 4);
            input.extend_from_slice(domain);
            input.extend_from_slice(label);
            input.extend_from_slice(&idx.to_le_bytes());
            RistrettoPoint::hash_from_bytes::<Sha512>(&input)
        };
        BpGens {
            g_vec: (0..capacity).map(|k| point(b"/G", k)).collect(),
            h_vec: (0..capacity).map(|k| point(b"/H", k)).collect(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.g_vec.len()
    }

    pub fn g(&self, n: usize) -> &[RistrettoPoint] {
        &self.g_vec[..n]
    }

    pub fn h(&self, n: usize) -> &[RistrettoPoint] {
        &self.h_vec[..n]
    }
}

/// Value and blinding bases of the commitments a range proof talks about.
#[derive(Clone, Copy)]
pub struct PedersenBases<'a> {
    pub g: &'a RistrettoPoint,
    pub h: &'a RistrettoPoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpError {
    /// Too many bit slots for the generator capacity, or zero values.
    BadShape,
    /// A value does not fit in the declared bit width (prover side).
    ValueOutOfRange,
    /// Wrong encoded length for the declared shape.
    WrongLength {
        expected: usize,
        actual: usize,
    },
    InvalidPoint {
        offset: usize,
    },
    NonCanonicalScalar {
        offset: usize,
    },
    VerificationFailed,
}

impl std::fmt::Display for BpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BpError::BadShape => write!(f, "range proof shape exceeds the generators"),
            BpError::ValueOutOfRange => write!(f, "value does not fit the bit width"),
            BpError::WrongLength { expected, actual } => {
                write!(f, "range proof is {actual} bytes, expected {expected}")
            }
            BpError::InvalidPoint { offset } => {
                write!(f, "range proof point at byte offset {offset} is invalid")
            }
            BpError::NonCanonicalScalar { offset } => {
                write!(
                    f,
                    "range proof scalar at byte offset {offset} is not canonical"
                )
            }
            BpError::VerificationFailed => write!(f, "range proof does not verify"),
        }
    }
}

impl std::error::Error for BpError {}

pub(crate) fn append_point(transcript: &mut Transcript, label: &'static [u8], p: &RistrettoPoint) {
    transcript.append_message(label, p.compress().as_bytes());
}

pub(crate) fn append_scalar(transcript: &mut Transcript, label: &'static [u8], s: &Scalar) {
    transcript.append_message(label, s.as_bytes());
}

pub(crate) fn append_u64(transcript: &mut Transcript, label: &'static [u8], v: u64) {
    transcript.append_message(label, &v.to_le_bytes());
}

/// 64 challenge bytes reduced mod the group order.
pub(crate) fn challenge_scalar(transcript: &mut Transcript, label: &'static [u8]) -> Scalar {
    let mut bytes = [0u8; 64];
    transcript.challenge_bytes(label, &mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

/// `1, x, x^2, ...`
pub(crate) fn powers(x: &Scalar, n: usize) -> Vec<Scalar> {
    let mut out = Vec::with_capacity(n);
    let mut acc = Scalar::ONE;
    for _ in 0..n {
        out.push(acc);
        acc *= x;
    }
    out
}

pub(crate) fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(a, b)| a * b).sum()
}

/// Canonical 32-byte chunk readers shared by the proof decoders.
pub(crate) fn read_point(bytes: &[u8], offset: usize) -> Result<RistrettoPoint, BpError> {
    CompressedRistretto::from_slice(&bytes[offset..offset + 32])
        .expect("32-byte chunk")
        .decompress()
        .ok_or(BpError::InvalidPoint { offset })
}

pub(crate) fn read_scalar(bytes: &[u8], offset: usize) -> Result<Scalar, BpError> {
    let chunk: [u8; 32] = bytes[offset..offset + 32]
        .try_into()
        .expect("32-byte chunk");
    Option::from(Scalar::from_canonical_bytes(chunk)).ok_or(BpError::NonCanonicalScalar { offset })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generators_are_distinct_and_deterministic() {
        let a = BpGens::derive(b"zkbattleship/test-only/bp", 8);
        let b = BpGens::derive(b"zkbattleship/test-only/bp", 8);
        assert_eq!(a.g(8), b.g(8));
        let mut all: Vec<[u8; 32]> = a
            .g(8)
            .iter()
            .chain(a.h(8))
            .map(|p| p.compress().to_bytes())
            .collect();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 16);
        let other = BpGens::derive(b"zkbattleship/test-only/bp2", 8);
        assert_ne!(a.g(1), other.g(1));
    }
}
