//! Inner-product argument (Bulletproofs §3, Protocol 2), made
//! non-interactive over a Merlin transcript.
//!
//! Statement: `P = <a, G'> + <b, H'> + <a, b> Q` with `G'_i = g_factors[i] G_i`
//! and `H'_i = h_factors[i] H_i`. The proof is `lg n` pairs `(L, R)` and the
//! final scalars `(a, b)`. The verifier never runs the recursion: it gets the
//! folded scalars from `verification_scalars` and checks everything in one
//! multiscalar multiplication (§3.1; see `range`).
//!
//! Everything here runs variable-time. The vectors being compressed are the
//! range proof's `l(x)`, `r(x)`, which the linear-size range proof
//! (Bulletproofs §4.1) sends in the clear: they are masked by `s_L`, `s_R`,
//! so leaking them through timing reveals nothing the uncompressed
//! proof would not. The secrets that must stay hidden (`a_L`, `s_L`, `s_R`,
//! the blinders) are only used in constant-time code in `range`.

use super::{append_point, append_u64, challenge_scalar, inner_product, BpError};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InnerProductProof {
    pub(crate) l_vec: Vec<RistrettoPoint>,
    pub(crate) r_vec: Vec<RistrettoPoint>,
    pub(crate) a: Scalar,
    pub(crate) b: Scalar,
}

#[allow(clippy::too_many_arguments)]
pub fn prove(
    transcript: &mut Transcript,
    q: &RistrettoPoint,
    g_factors: &[Scalar],
    h_factors: &[Scalar],
    mut g_vec: Vec<RistrettoPoint>,
    mut h_vec: Vec<RistrettoPoint>,
    a_vec: Vec<Scalar>,
    b_vec: Vec<Scalar>,
) -> Result<InnerProductProof, BpError> {
    let mut n = g_vec.len();
    assert!(n.is_power_of_two());
    assert_eq!(h_vec.len(), n);
    assert_eq!(a_vec.len(), n);
    assert_eq!(b_vec.len(), n);
    assert_eq!(g_factors.len(), n);
    assert_eq!(h_factors.len(), n);

    append_u64(transcript, b"ipa-n", n as u64);

    let mut a_vec = Zeroizing::new(a_vec);
    let mut b_vec = Zeroizing::new(b_vec);
    let lg_n = n.trailing_zeros() as usize;
    let mut l_vec = Vec::with_capacity(lg_n);
    let mut r_vec = Vec::with_capacity(lg_n);

    // The factors apply only until the first fold absorbs them into G, H.
    let mut first = true;
    while n != 1 {
        n /= 2;
        let (a_l, a_r) = a_vec.split_at_mut(n);
        let (b_l, b_r) = b_vec.split_at_mut(n);
        let (g_l, g_r) = g_vec.split_at_mut(n);
        let (h_l, h_r) = h_vec.split_at_mut(n);
        let gf = |i: usize| if first { g_factors[i] } else { Scalar::ONE };
        let hf = |i: usize| if first { h_factors[i] } else { Scalar::ONE };

        let c_l = Zeroizing::new(inner_product(a_l, b_r));
        let c_r = Zeroizing::new(inner_product(a_r, b_l));

        let l_scalars = Zeroizing::new(
            (0..n)
                .map(|i| a_l[i] * gf(n + i))
                .chain((0..n).map(|i| b_r[i] * hf(i)))
                .chain(std::iter::once(*c_l))
                .collect::<Vec<Scalar>>(),
        );
        let l = RistrettoPoint::vartime_multiscalar_mul(
            l_scalars.iter(),
            g_r.iter().chain(h_l.iter()).chain(std::iter::once(q)),
        );
        drop(l_scalars);
        let r_scalars = Zeroizing::new(
            (0..n)
                .map(|i| a_r[i] * gf(i))
                .chain((0..n).map(|i| b_l[i] * hf(n + i)))
                .chain(std::iter::once(*c_r))
                .collect::<Vec<Scalar>>(),
        );
        let r = RistrettoPoint::vartime_multiscalar_mul(
            r_scalars.iter(),
            g_l.iter().chain(h_r.iter()).chain(std::iter::once(q)),
        );
        drop(r_scalars);

        append_point(transcript, b"L", &l);
        append_point(transcript, b"R", &r);
        l_vec.push(l);
        r_vec.push(r);

        let u = challenge_scalar(transcript, b"u");
        if u == Scalar::ZERO {
            return Err(BpError::VerificationFailed);
        }
        let u_inv = u.invert();

        for i in 0..n {
            a_l[i] = a_l[i] * u + u_inv * a_r[i];
            b_l[i] = b_l[i] * u_inv + u * b_r[i];
            g_l[i] = RistrettoPoint::vartime_multiscalar_mul(
                [u_inv * gf(i), u * gf(n + i)],
                [g_l[i], g_r[i]],
            );
            h_l[i] = RistrettoPoint::vartime_multiscalar_mul(
                [u * hf(i), u_inv * hf(n + i)],
                [h_l[i], h_r[i]],
            );
        }
        // Zeroize folded right halves before truncation.
        for x in a_r.iter_mut().chain(b_r.iter_mut()) {
            x.zeroize();
        }
        a_vec.truncate(n);
        b_vec.truncate(n);
        g_vec.truncate(n);
        h_vec.truncate(n);
        first = false;
    }

    Ok(InnerProductProof {
        l_vec,
        r_vec,
        a: a_vec[0],
        b: b_vec[0],
    })
}

/// Folded-scalar view of the verifier: `(u_k^2, u_k^-2, s)` where `s_i` is the
/// product over rounds of `u_k^{+1}` or `u_k^{-1}` by the bits of `i`.
pub struct VerificationScalars {
    pub u_sq: Vec<Scalar>,
    pub u_inv_sq: Vec<Scalar>,
    pub s: Vec<Scalar>,
}

impl InnerProductProof {
    pub fn rounds(&self) -> usize {
        self.l_vec.len()
    }

    pub fn verification_scalars(
        &self,
        n: usize,
        transcript: &mut Transcript,
    ) -> Result<VerificationScalars, BpError> {
        let lg_n = self.l_vec.len();
        if lg_n >= 32 || self.r_vec.len() != lg_n || n != (1usize << lg_n) {
            return Err(BpError::VerificationFailed);
        }
        append_u64(transcript, b"ipa-n", n as u64);

        let mut u = Vec::with_capacity(lg_n);
        for (l, r) in self.l_vec.iter().zip(&self.r_vec) {
            append_point(transcript, b"L", l);
            append_point(transcript, b"R", r);
            let challenge = challenge_scalar(transcript, b"u");
            if challenge == Scalar::ZERO {
                return Err(BpError::VerificationFailed);
            }
            u.push(challenge);
        }
        let mut u_inv = u.clone();
        let all_inv = Scalar::batch_invert(&mut u_inv);
        let u_sq: Vec<Scalar> = u.iter().map(|x| x * x).collect();
        let u_inv_sq: Vec<Scalar> = u_inv.iter().map(|x| x * x).collect();

        // s_0 = prod u_k^-1; bit j of i (MSB first in round order) flips the
        // round-(lg_n - 1 - j) factor from u^-1 to u, i.e. multiplies by u^2.
        let mut s = Vec::with_capacity(n);
        s.push(all_inv);
        for i in 1..n {
            let lg_i = (usize::BITS - 1 - i.leading_zeros()) as usize;
            let k = 1usize << lg_i;
            s.push(s[i - k] * u_sq[(lg_n - 1) - lg_i]);
        }
        Ok(VerificationScalars { u_sq, u_inv_sq, s })
    }

    /// Stand-alone check, for tests; the range proof folds this into its own
    /// multiscalar multiplication.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify(
        &self,
        transcript: &mut Transcript,
        g_factors: &[Scalar],
        h_factors: &[Scalar],
        p: &RistrettoPoint,
        q: &RistrettoPoint,
        g: &[RistrettoPoint],
        h: &[RistrettoPoint],
    ) -> Result<(), BpError> {
        let n = g.len();
        let v = self.verification_scalars(n, transcript)?;
        let s_inv = v.s.iter().rev();
        let g_scalars = g_factors.iter().zip(&v.s).map(|(f, s)| self.a * s * f);
        let h_scalars = h_factors.iter().zip(s_inv).map(|(f, s)| self.b * s * f);
        let expect = RistrettoPoint::vartime_multiscalar_mul(
            std::iter::once(self.a * self.b)
                .chain(g_scalars)
                .chain(h_scalars)
                .chain(v.u_sq.iter().map(|x| -x))
                .chain(v.u_inv_sq.iter().map(|x| -x)),
            std::iter::once(q)
                .chain(g)
                .chain(h)
                .chain(&self.l_vec)
                .chain(&self.r_vec),
        );
        if expect == *p {
            Ok(())
        } else {
            Err(BpError::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bp::BpGens;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn run(n: usize, tamper: bool) -> Result<(), BpError> {
        let mut rng = ChaCha20Rng::from_seed([n as u8; 32]);
        let gens = BpGens::derive(b"zkbattleship/test-only/ipa", 64);
        let g = gens.g(n).to_vec();
        let h = gens.h(n).to_vec();
        let q = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"zkbattleship/test-only/Q");
        let a: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let b: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let g_factors: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let h_factors: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let mut c = inner_product(&a, &b);
        if tamper {
            c += Scalar::ONE;
        }
        let p = RistrettoPoint::vartime_multiscalar_mul(
            a.iter()
                .zip(&g_factors)
                .map(|(a, f)| a * f)
                .chain(b.iter().zip(&h_factors).map(|(b, f)| b * f))
                .chain(std::iter::once(c)),
            g.iter().chain(&h).chain(std::iter::once(&q)),
        );
        let proof = prove(
            &mut Transcript::new(b"ipa-test"),
            &q,
            &g_factors,
            &h_factors,
            g.clone(),
            h.clone(),
            a,
            b,
        )?;
        assert_eq!(proof.rounds(), n.trailing_zeros() as usize);
        proof.verify(
            &mut Transcript::new(b"ipa-test"),
            &g_factors,
            &h_factors,
            &p,
            &q,
            &g,
            &h,
        )
    }

    #[test]
    fn completeness_for_every_size() {
        for lg in 0..=6 {
            run(1 << lg, false).unwrap();
        }
    }

    #[test]
    fn wrong_inner_product_is_rejected() {
        for lg in 0..=6 {
            assert_eq!(run(1 << lg, true), Err(BpError::VerificationFailed));
        }
    }
}
