//! Ed25519 identity and the peer-authentication hook. A key read from a `Hello` is only
//! *announced*; only the application's [`PeerAuthPolicy`] yields an [`AuthenticatedPeer`].
//! Nothing here claims MITM resistance from `Hello` keys alone.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    InvalidKey,
    InvalidSignature,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::InvalidKey => write!(f, "invalid Ed25519 verifying key encoding"),
            IdentityError::InvalidSignature => write!(f, "strict signature verification failed"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// Never transmitted.
#[cfg_attr(fuzzing, derive(Clone))]
pub struct IdentityKeypair(SigningKey);

impl IdentityKeypair {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> IdentityKeypair {
        IdentityKeypair(SigningKey::generate(rng))
    }

    pub fn from_seed(seed: &[u8; 32]) -> IdentityKeypair {
        IdentityKeypair(SigningKey::from_bytes(seed))
    }

    pub fn to_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn peer_key(&self) -> PeerKey {
        PeerKey {
            bytes: self.0.verifying_key().to_bytes(),
            key: self.0.verifying_key(),
        }
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Signature {
        self.0.sign(message)
    }
}

/// `Ord` is the lexicographic order of the 32-byte encoding (used for role assignment).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerKey {
    bytes: [u8; 32],
    key: VerifyingKey,
}

impl PeerKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<PeerKey, IdentityError> {
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| IdentityError::InvalidKey)?;
        if key.is_weak() {
            return Err(IdentityError::InvalidKey);
        }
        Ok(PeerKey { bytes, key })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn fingerprint_hex(&self) -> String {
        self.bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Strict: rejects non-canonical and small-order encodings.
    pub(crate) fn verify_strict(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), IdentityError> {
        self.key
            .verify_strict(message, signature)
            .map_err(|_| IdentityError::InvalidSignature)
    }
}

impl PartialOrd for PeerKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PeerKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl fmt::Debug for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerKey({})", hex_short(&self.bytes))
    }
}

fn hex_short(bytes: &[u8; 32]) -> String {
    bytes[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Authenticated by the application's policy; the only key under which frames are attributable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedPeer(PeerKey);

impl AuthenticatedPeer {
    pub fn key(&self) -> &PeerKey {
        &self.0
    }

    /// For [`PeerAuthPolicy`] implementations only; never wrap a key learned from an
    /// unauthenticated `Hello`.
    pub fn from_policy_decision(key: PeerKey) -> AuthenticatedPeer {
        AuthenticatedPeer(key)
    }

    pub(crate) fn verify_strict(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), IdentityError> {
        self.0.verify_strict(message, signature)
    }
}

pub trait PeerAuthPolicy {
    fn authenticate(&self, announced: &PeerKey) -> Option<AuthenticatedPeer>;
}

/// The peer key is already known (pinned, matchmaking, or TOFU).
pub struct ExpectedKey {
    expected: PeerKey,
}

impl ExpectedKey {
    pub fn new(expected: PeerKey) -> ExpectedKey {
        ExpectedKey { expected }
    }
}

impl PeerAuthPolicy for ExpectedKey {
    fn authenticate(&self, announced: &PeerKey) -> Option<AuthenticatedPeer> {
        if *announced == self.expected {
            Some(AuthenticatedPeer(*announced))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn sign_and_verify_strict() {
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let keypair = IdentityKeypair::generate(&mut rng);
        let key = keypair.peer_key();
        let sig = keypair.sign(b"message");
        assert!(key.verify_strict(b"message", &sig).is_ok());
        assert_eq!(
            key.verify_strict(b"other", &sig),
            Err(IdentityError::InvalidSignature)
        );
        let other = IdentityKeypair::generate(&mut rng).peer_key();
        assert_eq!(
            other.verify_strict(b"message", &sig),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn key_roundtrip_and_ordering() {
        let keypair = IdentityKeypair::from_seed(&[7; 32]);
        let key = keypair.peer_key();
        let parsed = PeerKey::from_bytes(*key.as_bytes()).unwrap();
        assert_eq!(parsed, key);

        let k1 = IdentityKeypair::from_seed(&[1; 32]).peer_key();
        let k2 = IdentityKeypair::from_seed(&[2; 32]).peer_key();
        assert_eq!(k1.cmp(&k2), k1.as_bytes().cmp(k2.as_bytes()));
    }

    #[test]
    fn expected_key_policy() {
        let keypair = IdentityKeypair::from_seed(&[3; 32]);
        let key = keypair.peer_key();
        let policy = ExpectedKey::new(key);
        assert!(policy.authenticate(&key).is_some());
        let stranger = IdentityKeypair::from_seed(&[4; 32]).peer_key();
        assert!(policy.authenticate(&stranger).is_none());
    }

    #[test]
    fn weak_keys_are_rejected() {
        // Known small-order / identity compressed Edwards Y points.
        let mut neg_identity = [0xffu8; 32];
        neg_identity[0] = 0xec;
        neg_identity[31] = 0x7f;
        let mut identity = [0u8; 32];
        identity[0] = 1;
        for weak in [[0u8; 32], identity, neg_identity] {
            assert_eq!(PeerKey::from_bytes(weak), Err(IdentityError::InvalidKey));
        }
        let kp = IdentityKeypair::from_seed(&[0x42; 32]);
        assert_eq!(*kp.to_seed(), [0x42; 32]);
        assert_eq!(kp.peer_key().fingerprint_hex().len(), 64);
    }
}
