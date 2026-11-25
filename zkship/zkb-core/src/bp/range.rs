//! Aggregated range proof (Bulletproofs §4.3; paper Construction 2.11) for
//! `m` committed values, each in `[0, 2^n)`, with the `n*m` bit slots padded
//! to `N' = next_pow2(n*m)`.
//!
//! Padding: slot `k >= n*m` carries `a_L = 0`, `a_R = -1` and weight 0. The
//! bit constraints `a_L o a_R = 0`, `a_R = a_L - 1` still hold on it and it
//! contributes to no value, so the only change to the dalek protocol is the
//! weight vector `w_k = z^{2+j} 2^i` (`k = j*n + i`, zero on padding) and
//! `delta(y, z) = (z - z^2) <1, y^N'> - z <1, w>`.
//!
//! Transcript order: `rp-n`, `rp-m`, `V_0..V_{m-1}`, `A`, `S`, challenges
//! `y`, `z`, then `T1`, `T2`, challenge `x`, then `t_hat`, `tau_x`, `mu`,
//! challenge `w` (inner-product base `Q = w G`), and the inner-product
//! rounds. The verifier's batching challenge `c` comes from a fork of the
//! transcript at that point that has also absorbed `a` and `b` (`ipa-a`,
//! `ipa-b`), leaving the shared transcript where the prover's ends.
//!
//! Size: `4 + 2 lg N'` group elements and 5 scalars.

use super::ipa::{self, InnerProductProof};
use super::{
    append_point, append_scalar, append_u64, challenge_scalar, inner_product, powers, read_point,
    read_scalar, BpError, BpGens, PedersenBases,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, MultiscalarMul, VartimeMultiscalarMul};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeProof {
    a: RistrettoPoint,
    s: RistrettoPoint,
    t1: RistrettoPoint,
    t2: RistrettoPoint,
    t_hat: Scalar,
    tau_x: Scalar,
    mu: Scalar,
    ipa: InnerProductProof,
}

/// Checked `next_pow2(n*m)` for `1 <= n <= 64`, `m >= 1`.
pub fn checked_padded_slots(n: usize, m: usize) -> Option<usize> {
    if n == 0 || n > 64 || m == 0 {
        return None;
    }
    n.checked_mul(m)?.checked_next_power_of_two()
}

/// Checked `32 * (4 + 2 lg N' + 5)`.
pub fn checked_encoded_len(n: usize, m: usize) -> Option<usize> {
    let lg = checked_padded_slots(n, m)?.trailing_zeros() as usize;
    32usize.checked_mul(9usize.checked_add(2usize.checked_mul(lg)?)?)
}

/// `next_pow2(n*m)`.
pub fn padded_slots(n: usize, m: usize) -> usize {
    checked_padded_slots(n, m).expect("range proof shape must be non-zero and fit usize")
}

/// `32 * (4 + 2 lg N' + 5)`.
pub fn encoded_len(n: usize, m: usize) -> usize {
    checked_encoded_len(n, m).expect("range proof shape must fit usize")
}

fn check_shape(gens: &BpGens, n: usize, m: usize) -> Result<usize, BpError> {
    let slots = checked_padded_slots(n, m).ok_or(BpError::BadShape)?;
    if slots > gens.capacity() {
        return Err(BpError::BadShape);
    }
    Ok(slots)
}

/// `w_k = z^{2+j} 2^i` for `k = j*n + i < n*m`, else 0.
fn weights(z: &Scalar, n: usize, m: usize, slots: usize) -> Vec<Scalar> {
    let two_pows = powers(&Scalar::from(2u64), n);
    let z_pows = powers(z, m + 2);
    let mut w = Vec::with_capacity(slots);
    for j in 0..m {
        for two in &two_pows {
            w.push(z_pows[j + 2] * two);
        }
    }
    w.resize(slots, Scalar::ZERO);
    w
}

fn delta(y_pows: &[Scalar], z: &Scalar, w: &[Scalar]) -> Scalar {
    let sum_y: Scalar = y_pows.iter().sum();
    let sum_w: Scalar = w.iter().sum();
    (z - z * z) * sum_y - z * sum_w
}

fn append_statement(transcript: &mut Transcript, n: usize, commitments: &[RistrettoPoint]) {
    append_u64(transcript, b"rp-n", n as u64);
    append_u64(transcript, b"rp-m", commitments.len() as u64);
    for v in commitments {
        append_point(transcript, b"V", v);
    }
}

fn nonzero_challenge(transcript: &mut Transcript, label: &'static [u8]) -> Result<Scalar, BpError> {
    let c = challenge_scalar(transcript, label);
    if c == Scalar::ZERO {
        Err(BpError::VerificationFailed)
    } else {
        Ok(c)
    }
}

/// `commitments[j]` must equal `values[j] G + blindings[j] H`; they are the
/// public statement and go into the transcript as given.
#[allow(clippy::too_many_arguments)]
pub fn prove<R: RngCore + CryptoRng>(
    transcript: &mut Transcript,
    gens: &BpGens,
    bases: PedersenBases,
    commitments: &[RistrettoPoint],
    values: &[u64],
    blindings: &[Scalar],
    n: usize,
    rng: &mut R,
) -> Result<RangeProof, BpError> {
    let m = values.len();
    if blindings.len() != m || commitments.len() != m {
        return Err(BpError::BadShape);
    }
    let slots = check_shape(gens, n, m)?;
    if n < 64 && values.iter().fold(0u64, |acc, &v| acc | (v >> n)) != 0 {
        return Err(BpError::ValueOutOfRange);
    }
    debug_assert!(values
        .iter()
        .zip(blindings)
        .zip(commitments)
        .all(|((v, r), c)| Scalar::from(*v) * bases.g + r * bases.h == *c));
    prove_unchecked(
        transcript,
        gens,
        bases,
        commitments,
        values,
        blindings,
        n,
        slots,
        rng,
    )
}

/// Cheating-prover hook for tests of the protocols built on range proofs:
/// proves over the low `n` bits of each value without refusing, so the proof
/// fails verification whenever a value is out of range.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_unchecked_for_test<R: RngCore + CryptoRng>(
    transcript: &mut Transcript,
    gens: &BpGens,
    bases: PedersenBases,
    commitments: &[RistrettoPoint],
    values: &[u64],
    blindings: &[Scalar],
    n: usize,
    rng: &mut R,
) -> Result<RangeProof, BpError> {
    let slots = check_shape(gens, n, values.len())?;
    let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
    let low: Vec<u64> = values.iter().map(|v| v & mask).collect();
    prove_unchecked(
        transcript,
        gens,
        bases,
        commitments,
        &low,
        blindings,
        n,
        slots,
        rng,
    )
}

/// The prover algorithm without the statement consistency check, so tests can
/// play a cheating prover.
#[allow(clippy::too_many_arguments)]
fn prove_unchecked<R: RngCore + CryptoRng>(
    transcript: &mut Transcript,
    gens: &BpGens,
    bases: PedersenBases,
    commitments: &[RistrettoPoint],
    values: &[u64],
    blindings: &[Scalar],
    n: usize,
    slots: usize,
    rng: &mut R,
) -> Result<RangeProof, BpError> {
    let m = values.len();
    append_statement(transcript, n, commitments);

    // Secret bits; padding slots are 0.
    let mut a_l = Zeroizing::new(vec![0u8; slots]);
    for (j, v) in values.iter().enumerate() {
        for i in 0..n {
            a_l[j * n + i] = ((v >> i) & 1) as u8;
        }
    }

    let alpha = Zeroizing::new(Scalar::random(rng));
    let mut a = *alpha * bases.h;
    for (k, bit) in a_l.iter().enumerate() {
        // bit ? G_k : -H_k, without branching on the bit.
        let neg_h = -gens.h(slots)[k];
        a += RistrettoPoint::conditional_select(&neg_h, &gens.g(slots)[k], Choice::from(*bit));
    }

    let s_l = Zeroizing::new((0..slots).map(|_| Scalar::random(rng)).collect::<Vec<_>>());
    let s_r = Zeroizing::new((0..slots).map(|_| Scalar::random(rng)).collect::<Vec<_>>());
    let rho = Zeroizing::new(Scalar::random(rng));
    let s = RistrettoPoint::multiscalar_mul(
        std::iter::once(&*rho).chain(s_l.iter()).chain(s_r.iter()),
        std::iter::once(bases.h)
            .chain(gens.g(slots))
            .chain(gens.h(slots)),
    );

    append_point(transcript, b"A", &a);
    append_point(transcript, b"S", &s);
    let y = nonzero_challenge(transcript, b"y")?;
    let z = nonzero_challenge(transcript, b"z")?;

    let y_pows = powers(&y, slots);
    let w = weights(&z, n, m, slots);

    // l(X) = l0 + l1 X, r(X) = r0 + r1 X.
    let l0 = Zeroizing::new(a_l.iter().map(|&b| Scalar::from(b) - z).collect::<Vec<_>>());
    let r0 = Zeroizing::new(
        (0..slots)
            .map(|k| y_pows[k] * (Scalar::from(a_l[k]) - Scalar::ONE + z) + w[k])
            .collect::<Vec<_>>(),
    );
    let r1 = Zeroizing::new((0..slots).map(|k| y_pows[k] * s_r[k]).collect::<Vec<_>>());
    drop(a_l);
    let t1 = Zeroizing::new(inner_product(&l0, &r1) + inner_product(&s_l, &r0));
    let t2 = Zeroizing::new(inner_product(&s_l, &r1));

    let tau1 = Zeroizing::new(Scalar::random(rng));
    let tau2 = Zeroizing::new(Scalar::random(rng));
    let big_t1 = RistrettoPoint::multiscalar_mul([*t1, *tau1], [bases.g, bases.h]);
    let big_t2 = RistrettoPoint::multiscalar_mul([*t2, *tau2], [bases.g, bases.h]);
    append_point(transcript, b"T1", &big_t1);
    append_point(transcript, b"T2", &big_t2);
    let x = nonzero_challenge(transcript, b"x")?;

    let l: Vec<Scalar> = (0..slots).map(|k| l0[k] + s_l[k] * x).collect();
    let r: Vec<Scalar> = (0..slots).map(|k| r0[k] + r1[k] * x).collect();
    let t_hat = inner_product(&l, &r);
    let z_pows = powers(&z, m + 2);
    let tau_x = *tau2 * x * x
        + *tau1 * x
        + blindings
            .iter()
            .enumerate()
            .map(|(j, gamma)| z_pows[j + 2] * gamma)
            .sum::<Scalar>();
    let mu = *alpha + *rho * x;

    append_scalar(transcript, b"t_hat", &t_hat);
    append_scalar(transcript, b"tau_x", &tau_x);
    append_scalar(transcript, b"mu", &mu);
    let w_ipa = nonzero_challenge(transcript, b"w")?;
    let q = w_ipa * bases.g;

    let y_inv_pows = powers(&y.invert(), slots);
    let ipa = ipa::prove(
        transcript,
        &q,
        &vec![Scalar::ONE; slots],
        &y_inv_pows,
        gens.g(slots).to_vec(),
        gens.h(slots).to_vec(),
        l,
        r,
    )?;

    Ok(RangeProof {
        a,
        s,
        t1: big_t1,
        t2: big_t2,
        t_hat,
        tau_x,
        mu,
        ipa,
    })
}

impl RangeProof {
    /// Batching weight for the t-hat equation, drawn after all proof data,
    /// including `a` and `b`, from a fork so the caller's transcript stays in
    /// step with the prover's for any proof that follows on it.
    fn batching_weight(&self, transcript: &Transcript) -> Result<Scalar, BpError> {
        let mut fork = transcript.clone();
        append_scalar(&mut fork, b"ipa-a", &self.ipa.a);
        append_scalar(&mut fork, b"ipa-b", &self.ipa.b);
        nonzero_challenge(&mut fork, b"c")
    }

    #[cfg(test)]
    pub(crate) fn tamper_t_hat(&mut self) {
        self.t_hat += Scalar::ONE;
    }

    pub fn verify(
        &self,
        transcript: &mut Transcript,
        gens: &BpGens,
        bases: PedersenBases,
        commitments: &[RistrettoPoint],
        n: usize,
    ) -> Result<(), BpError> {
        let m = commitments.len();
        let slots = check_shape(gens, n, m)?;
        if self.ipa.rounds() != slots.trailing_zeros() as usize {
            return Err(BpError::VerificationFailed);
        }

        append_statement(transcript, n, commitments);
        append_point(transcript, b"A", &self.a);
        append_point(transcript, b"S", &self.s);
        let y = nonzero_challenge(transcript, b"y")?;
        let z = nonzero_challenge(transcript, b"z")?;
        append_point(transcript, b"T1", &self.t1);
        append_point(transcript, b"T2", &self.t2);
        let x = nonzero_challenge(transcript, b"x")?;
        append_scalar(transcript, b"t_hat", &self.t_hat);
        append_scalar(transcript, b"tau_x", &self.tau_x);
        append_scalar(transcript, b"mu", &self.mu);
        let w_ipa = nonzero_challenge(transcript, b"w")?;
        let v = self.ipa.verification_scalars(slots, transcript)?;
        let c = self.batching_weight(transcript)?;

        let y_pows = powers(&y, slots);
        let y_inv_pows = powers(&y.invert(), slots);
        let w = weights(&z, n, m, slots);
        let z_pows = powers(&z, m + 2);
        let (a, b) = (self.ipa.a, self.ipa.b);

        let g_scalars = v.s.iter().map(|s_k| -z - a * s_k);
        let h_scalars =
            v.s.iter()
                .rev()
                .zip(&y_inv_pows)
                .zip(&w)
                .map(|((s_inv_k, y_inv_k), w_k)| z + y_inv_k * (w_k - b * s_inv_k));
        let value_scalars = (0..m).map(|j| c * z_pows[j + 2]);
        let g_base = w_ipa * (self.t_hat - a * b) + c * (delta(&y_pows, &z, &w) - self.t_hat);
        let h_base = -self.mu - c * self.tau_x;

        let check = RistrettoPoint::vartime_multiscalar_mul(
            [Scalar::ONE, x, c * x, c * x * x, h_base, g_base]
                .into_iter()
                .chain(v.u_sq.iter().copied())
                .chain(v.u_inv_sq.iter().copied())
                .chain(g_scalars)
                .chain(h_scalars)
                .chain(value_scalars),
            [&self.a, &self.s, &self.t1, &self.t2, bases.h, bases.g]
                .into_iter()
                .chain(&self.ipa.l_vec)
                .chain(&self.ipa.r_vec)
                .chain(gens.g(slots))
                .chain(gens.h(slots))
                .chain(commitments),
        );
        if check.is_identity() {
            Ok(())
        } else {
            Err(BpError::VerificationFailed)
        }
    }

    /// `A || S || T1 || T2 || L_0..L_{r-1} || R_0..R_{r-1} || t_hat || tau_x || mu || a || b`.
    pub fn encode(&self) -> Vec<u8> {
        let r = self.ipa.rounds();
        let mut out = Vec::with_capacity(32 * (9 + 2 * r));
        for p in [&self.a, &self.s, &self.t1, &self.t2]
            .into_iter()
            .chain(&self.ipa.l_vec)
            .chain(&self.ipa.r_vec)
        {
            out.extend_from_slice(p.compress().as_bytes());
        }
        for s in [&self.t_hat, &self.tau_x, &self.mu, &self.ipa.a, &self.ipa.b] {
            out.extend_from_slice(s.as_bytes());
        }
        out
    }

    /// Exact length for the shape `(n, m)`; canonical points and scalars.
    pub fn decode(bytes: &[u8], n: usize, m: usize) -> Result<RangeProof, BpError> {
        let expected = checked_encoded_len(n, m).ok_or(BpError::BadShape)?;
        if bytes.len() != expected {
            return Err(BpError::WrongLength {
                expected,
                actual: bytes.len(),
            });
        }
        let r = checked_padded_slots(n, m)
            .ok_or(BpError::BadShape)?
            .trailing_zeros() as usize;
        let point = |i: usize| read_point(bytes, 32 * i);
        let scalar = |i: usize| read_scalar(bytes, 32 * i);
        let l_vec = (0..r)
            .map(|i| point(4 + i))
            .collect::<Result<Vec<_>, _>>()?;
        let r_vec = (0..r)
            .map(|i| point(4 + r + i))
            .collect::<Result<Vec<_>, _>>()?;
        let base = 4 + 2 * r;
        Ok(RangeProof {
            a: point(0)?,
            s: point(1)?,
            t1: point(2)?,
            t2: point(3)?,
            t_hat: scalar(base)?,
            tau_x: scalar(base + 1)?,
            mu: scalar(base + 2)?,
            ipa: InnerProductProof {
                l_vec,
                r_vec,
                a: scalar(base + 3)?,
                b: scalar(base + 4)?,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::Identity;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use sha2::Sha512;

    struct Fixture {
        gens: BpGens,
        g: RistrettoPoint,
        h: RistrettoPoint,
    }

    fn fixture() -> Fixture {
        Fixture {
            gens: BpGens::derive(b"zkbattleship/test-only/range", 1024),
            g: curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT,
            h: RistrettoPoint::hash_from_bytes::<Sha512>(b"zkbattleship/test-only/range-H"),
        }
    }

    impl Fixture {
        fn bases(&self) -> PedersenBases<'_> {
            PedersenBases {
                g: &self.g,
                h: &self.h,
            }
        }

        fn commit(&self, v: &Scalar, r: &Scalar) -> RistrettoPoint {
            v * self.g + r * self.h
        }

        fn prove(&self, values: &[u64], n: usize, seed: u8) -> (Vec<RistrettoPoint>, RangeProof) {
            let mut rng = ChaCha20Rng::from_seed([seed; 32]);
            let blindings: Vec<Scalar> = values.iter().map(|_| Scalar::random(&mut rng)).collect();
            let commitments: Vec<RistrettoPoint> = values
                .iter()
                .zip(&blindings)
                .map(|(v, r)| self.commit(&Scalar::from(*v), r))
                .collect();
            let proof = prove(
                &mut Transcript::new(b"range-test"),
                &self.gens,
                self.bases(),
                &commitments,
                values,
                &blindings,
                n,
                &mut rng,
            )
            .unwrap();
            (commitments, proof)
        }

        fn verify(
            &self,
            commitments: &[RistrettoPoint],
            proof: &RangeProof,
            n: usize,
        ) -> Result<(), BpError> {
            proof.verify(
                &mut Transcript::new(b"range-test"),
                &self.gens,
                self.bases(),
                commitments,
                n,
            )
        }
    }

    #[test]
    fn completeness_across_shapes() {
        let f = fixture();
        for (n, m) in [
            (1, 1),
            (1, 2),
            (1, 3),
            (1, 605),
            (3, 1),
            (3, 5),
            (8, 3),
            (64, 2),
            (4, 7),
        ] {
            let values: Vec<u64> = (0..m as u64)
                .map(|j| {
                    let max = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
                    j.wrapping_mul(0x9E37_79B9_7F4A_7C15) & max
                })
                .collect();
            let (commitments, proof) = f.prove(&values, n, (n + m) as u8);
            f.verify(&commitments, &proof, n)
                .unwrap_or_else(|e| panic!("n={n} m={m}: {e}"));
            assert_eq!(proof.encode().len(), encoded_len(n, m));
            let decoded = RangeProof::decode(&proof.encode(), n, m).unwrap();
            assert_eq!(decoded, proof);
        }
    }

    #[test]
    fn paper_sizes() {
        // Setup bit proof: 605 one-bit values -> 24 elements + 5 scalars.
        assert_eq!(encoded_len(1, 605), 32 * (24 + 5));
        // Not-sunk proof: 5 three-bit values -> 12 elements + 5 scalars.
        assert_eq!(encoded_len(3, 5), 544);
        // No-touch proof: 500 eight-bit values -> 28 elements + 5 scalars.
        assert_eq!(encoded_len(8, 500), 32 * (28 + 5));
    }

    #[test]
    fn prover_refuses_out_of_range_values() {
        let f = fixture();
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let r = Scalar::random(&mut rng);
        let c = f.commit(&Scalar::from(8u64), &r);
        assert_eq!(
            prove(
                &mut Transcript::new(b"range-test"),
                &f.gens,
                f.bases(),
                &[c],
                &[8],
                &[r],
                3,
                &mut rng,
            ),
            Err(BpError::ValueOutOfRange)
        );
    }

    /// A cheating prover that commits to out-of-range values but runs the
    /// prover algorithm on their low bits. Verification must fail.
    fn forged(f: &Fixture, true_values: &[Scalar], n: usize) -> (Vec<RistrettoPoint>, RangeProof) {
        let mut rng = ChaCha20Rng::from_seed([9; 32]);
        let blindings: Vec<Scalar> = true_values
            .iter()
            .map(|_| Scalar::random(&mut rng))
            .collect();
        let commitments: Vec<RistrettoPoint> = true_values
            .iter()
            .zip(&blindings)
            .map(|(v, r)| f.commit(v, r))
            .collect();
        let low: Vec<u64> = true_values
            .iter()
            .map(|v| u64::from_le_bytes(v.as_bytes()[..8].try_into().unwrap()) & ((1 << n) - 1))
            .collect();
        let proof = prove_unchecked(
            &mut Transcript::new(b"range-test"),
            &f.gens,
            f.bases(),
            &commitments,
            &low,
            &blindings,
            n,
            padded_slots(n, low.len()),
            &mut rng,
        )
        .unwrap();
        (commitments, proof)
    }

    #[test]
    fn out_of_range_commitments_are_rejected() {
        let f = fixture();
        // Two as a "bit", minus one, and 2^n for n = 3.
        for (vals, n) in [
            (vec![Scalar::from(2u64)], 1),
            (vec![Scalar::ONE, -Scalar::ONE, Scalar::ZERO], 1),
            (vec![Scalar::from(8u64), Scalar::from(3u64)], 3),
            (vec![-Scalar::ONE; 5], 3),
        ] {
            let (commitments, proof) = forged(&f, &vals, n);
            assert_eq!(
                f.verify(&commitments, &proof, n),
                Err(BpError::VerificationFailed)
            );
        }
    }

    #[test]
    fn tampering_is_rejected() {
        let f = fixture();
        let (commitments, proof) = f.prove(&[1, 0, 1, 1, 0], 1, 3);
        f.verify(&commitments, &proof, 1).unwrap();

        // Wrong bit width, commitment order, or any proof component.
        assert!(f.verify(&commitments, &proof, 2).is_err());
        let mut swapped = commitments.clone();
        swapped.swap(0, 1);
        assert!(f.verify(&swapped, &proof, 1).is_err());
        assert!(f.verify(&commitments[..4], &proof, 1).is_err());
        assert!(f
            .verify(&[RistrettoPoint::identity(); 5], &proof, 1)
            .is_err());

        let bytes = proof.encode();
        let points = 4 + 2 * 3;
        for i in 0..points + 5 {
            let mut t = RangeProof::decode(&bytes, 1, 5).unwrap();
            let one = Scalar::ONE;
            match i {
                0 => t.a += f.g,
                1 => t.s += f.g,
                2 => t.t1 += f.g,
                3 => t.t2 += f.g,
                i if i < 7 => t.ipa.l_vec[i - 4] += f.g,
                i if i < points => t.ipa.r_vec[i - 7] += f.g,
                i if i == points => t.t_hat += one,
                i if i == points + 1 => t.tau_x += one,
                i if i == points + 2 => t.mu += one,
                i if i == points + 3 => t.ipa.a += one,
                _ => t.ipa.b += one,
            }
            assert_eq!(
                f.verify(&commitments, &t, 1),
                Err(BpError::VerificationFailed),
                "component {i}"
            );
        }
    }

    #[test]
    fn batching_weight_binds_final_scalars() {
        let f = fixture();
        let (_, proof) = f.prove(&[1, 0, 1], 1, 8);
        let at = Transcript::new(b"range-test");
        let c = proof.batching_weight(&at).unwrap();
        let mut t = proof.clone();
        t.ipa.a += Scalar::ONE;
        assert_ne!(t.batching_weight(&at).unwrap(), c);
        let mut t = proof.clone();
        t.ipa.b += Scalar::ONE;
        assert_ne!(t.batching_weight(&at).unwrap(), c);
        assert_eq!(proof.batching_weight(&at).unwrap(), c);
    }

    #[test]
    fn decode_and_shape_reject_zero_or_overflow() {
        let f = fixture();
        let (_, proof) = f.prove(&[1], 1, 1);
        let bytes = proof.encode();
        for (n, m) in [(0, 1), (1, 0), (65, 1), (8, usize::MAX), (usize::MAX, 2)] {
            assert_eq!(RangeProof::decode(&bytes, n, m), Err(BpError::BadShape));
            assert_eq!(check_shape(&f.gens, n, m), Err(BpError::BadShape));
            assert!(checked_encoded_len(n, m).is_none());
        }
    }

    #[test]
    fn consecutive_proofs_share_a_transcript() {
        let f = fixture();
        let mut rng = ChaCha20Rng::from_seed([6; 32]);
        let values = [[1u64, 0], [3, 2]];
        let mut prover = Transcript::new(b"range-test");
        let mut statements = Vec::new();
        for (k, vals) in values.iter().enumerate() {
            let n = k + 1;
            let blindings: Vec<Scalar> = vals.iter().map(|_| Scalar::random(&mut rng)).collect();
            let commitments: Vec<RistrettoPoint> = vals
                .iter()
                .zip(&blindings)
                .map(|(v, r)| f.commit(&Scalar::from(*v), r))
                .collect();
            let proof = prove(
                &mut prover,
                &f.gens,
                f.bases(),
                &commitments,
                vals,
                &blindings,
                n,
                &mut rng,
            )
            .unwrap();
            statements.push((commitments, proof, n));
        }
        let mut verifier = Transcript::new(b"range-test");
        for (commitments, proof, n) in &statements {
            proof
                .verify(&mut verifier, &f.gens, f.bases(), commitments, *n)
                .unwrap();
        }
    }

    #[test]
    fn transcript_binding() {
        let f = fixture();
        let (commitments, proof) = f.prove(&[5, 2], 3, 4);
        assert!(proof
            .verify(
                &mut Transcript::new(b"other-context"),
                &f.gens,
                f.bases(),
                &commitments,
                3,
            )
            .is_err());
    }

    #[test]
    fn decode_rejects_bad_encodings() {
        let f = fixture();
        let (_, proof) = f.prove(&[1, 2, 3], 2, 5);
        let bytes = proof.encode();
        assert!(matches!(
            RangeProof::decode(&bytes[1..], 2, 3),
            Err(BpError::WrongLength { .. })
        ));
        assert!(matches!(
            RangeProof::decode(&bytes, 2, 5),
            Err(BpError::WrongLength { .. })
        ));
        let mut bad = bytes.clone();
        bad[..32].fill(0xff);
        assert_eq!(
            RangeProof::decode(&bad, 2, 3),
            Err(BpError::InvalidPoint { offset: 0 })
        );
        let mut bad = bytes.clone();
        let last = bad.len() - 32;
        bad[last..].fill(0xff);
        assert_eq!(
            RangeProof::decode(&bad, 2, 3),
            Err(BpError::NonCanonicalScalar { offset: last })
        );
    }
}
