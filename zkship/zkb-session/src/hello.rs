//! `Hello` bootstrap, A/B roles, sid, genesis hash. `Hello` has its own format because `sid`
//! does not exist until both Hellos are known.

use crate::identity::{AuthenticatedPeer, IdentityError, IdentityKeypair, PeerAuthPolicy, PeerKey};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512_256};
use std::fmt;
use zkb_core::game::Role;

/// Signature covers `HELLO_DOMAIN || version || params_id || verifying_key || nonce`.
pub const HELLO_DOMAIN: &[u8] = b"zkbattleship/reference/v1/hello";

pub const SID_DOMAIN: &[u8] = b"zkbattleship/reference/v1/sid";

pub const GENESIS_DOMAIN: &[u8] = b"zkbattleship/reference/v1/genesis";

pub const SAFETY_CODE_DOMAIN: &[u8] = b"zkbattleship/reference/v1/safety-code";

pub const WIRE_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelloError {
    WrongLength {
        expected: usize,
        actual: usize,
    },
    InvalidKey,
    WrongVersion {
        expected: u16,
        actual: u16,
    },
    ParamsIdMismatch,
    InvalidSignature,
    PeerNotAuthenticated,
    /// Paper Construction 7.1, S1: equal keys are rejected.
    EqualIdentityKeys,
}

impl fmt::Display for HelloError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HelloError::WrongLength { expected, actual } => {
                write!(f, "hello is {actual} bytes, expected {expected}")
            }
            HelloError::InvalidKey => write!(f, "invalid verifying key in hello"),
            HelloError::WrongVersion { expected, actual } => {
                write!(f, "hello version {actual}, expected {expected}")
            }
            HelloError::ParamsIdMismatch => write!(f, "hello params_id mismatch"),
            HelloError::InvalidSignature => write!(f, "hello signature does not verify"),
            HelloError::PeerNotAuthenticated => {
                write!(f, "application policy rejected the announced peer key")
            }
            HelloError::EqualIdentityKeys => write!(f, "both hellos use the same identity key"),
        }
    }
}

impl std::error::Error for HelloError {}

impl From<IdentityError> for HelloError {
    fn from(e: IdentityError) -> HelloError {
        match e {
            IdentityError::InvalidKey => HelloError::InvalidKey,
            IdentityError::InvalidSignature => HelloError::InvalidSignature,
        }
    }
}

/// Wire layout (162 bytes):
///
/// ```text
/// offset  size  field
/// 0       2     version       u16 little-endian (= 1)
/// 2       32    params_id
/// 34      32    Ed25519 verifying key
/// 66      32    bootstrap nonce
/// 98      64    Ed25519 signature over
///               HELLO_DOMAIN || the 98 preceding bytes
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    version: u16,
    params_id: [u8; 32],
    key: PeerKey,
    nonce: [u8; 32],
    signature: ed25519_dalek::Signature,
}

impl Hello {
    pub const LEN: usize = 2 + 32 + 32 + 32 + 64;

    pub fn create<R: RngCore + CryptoRng>(
        keypair: &IdentityKeypair,
        params_id: [u8; 32],
        rng: &mut R,
    ) -> Hello {
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let version = WIRE_VERSION;
        let key = keypair.peer_key();
        let message = hello_signing_message(version, &params_id, key.as_bytes(), &nonce);
        let signature = keypair.sign(&message);
        Hello {
            version,
            params_id,
            key,
            nonce,
            signature,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.params_id);
        out.extend_from_slice(self.key.as_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.signature.to_bytes());
        out
    }

    /// Structural only; the signature is checked by [`check_hello`].
    pub fn decode(bytes: &[u8]) -> Result<Hello, HelloError> {
        if bytes.len() != Self::LEN {
            return Err(HelloError::WrongLength {
                expected: Self::LEN,
                actual: bytes.len(),
            });
        }
        let version = u16::from_le_bytes(bytes[0..2].try_into().expect("length checked"));
        let params_id: [u8; 32] = bytes[2..34].try_into().expect("length checked");
        let key_bytes: [u8; 32] = bytes[34..66].try_into().expect("length checked");
        let key = PeerKey::from_bytes(key_bytes)?;
        let nonce: [u8; 32] = bytes[66..98].try_into().expect("length checked");
        let signature = ed25519_dalek::Signature::from_bytes(
            bytes[98..162].try_into().expect("length checked"),
        );
        Ok(Hello {
            version,
            params_id,
            key,
            nonce,
            signature,
        })
    }

    /// Announced, not authenticated.
    pub fn key(&self) -> &PeerKey {
        &self.key
    }

    /// Stays paired with the key that sent it.
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    pub fn params_id(&self) -> &[u8; 32] {
        &self.params_id
    }
}

fn hello_signing_message(
    version: u16,
    params_id: &[u8; 32],
    key: &[u8; 32],
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HELLO_DOMAIN.len() + 2 + 96);
    out.extend_from_slice(HELLO_DOMAIN);
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(params_id);
    out.extend_from_slice(key);
    out.extend_from_slice(nonce);
    out
}

/// Version, `params_id`, and signature verified; carries exactly the [`AuthenticatedPeer`]
/// the application's policy returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedHello {
    hello: Hello,
    peer: AuthenticatedPeer,
}

impl CheckedHello {
    pub fn hello(&self) -> &Hello {
        &self.hello
    }

    pub fn key(&self) -> &PeerKey {
        self.hello.key()
    }

    pub fn authenticated_peer(&self) -> &AuthenticatedPeer {
        &self.peer
    }
}

/// Exact version, exact `params_id`, strict signature, then the application policy.
pub fn check_hello(
    hello: Hello,
    expected_params_id: &[u8; 32],
    policy: &dyn PeerAuthPolicy,
) -> Result<CheckedHello, HelloError> {
    if hello.version != WIRE_VERSION {
        return Err(HelloError::WrongVersion {
            expected: WIRE_VERSION,
            actual: hello.version,
        });
    }
    if &hello.params_id != expected_params_id {
        return Err(HelloError::ParamsIdMismatch);
    }
    let message = hello_signing_message(
        hello.version,
        &hello.params_id,
        hello.key.as_bytes(),
        &hello.nonce,
    );
    hello.key.verify_strict(&message, &hello.signature)?;
    let peer = policy
        .authenticate(hello.key())
        .ok_or(HelloError::PeerNotAuthenticated)?;
    if peer.key() != hello.key() {
        // A policy must authenticate the announced key, not substitute one.
        return Err(HelloError::PeerNotAuthenticated);
    }
    Ok(CheckedHello { hello, peer })
}

/// The genesis hash is chain height 0.
#[derive(Debug, PartialEq, Eq)]
pub struct SessionBootstrap {
    hello_a: Hello,
    hello_b: Hello,
    sid: [u8; 32],
    genesis_hash: [u8; 32],
}

impl SessionBootstrap {
    pub fn sid(&self) -> &[u8; 32] {
        &self.sid
    }

    pub fn genesis_hash(&self) -> &[u8; 32] {
        &self.genesis_hash
    }

    pub fn params_id(&self) -> &[u8; 32] {
        self.hello_a.params_id()
    }

    pub fn try_role_of(&self, key: &PeerKey) -> Option<Role> {
        if key.as_bytes() == self.hello_a.key().as_bytes() {
            Some(Role::A)
        } else if key.as_bytes() == self.hello_b.key().as_bytes() {
            Some(Role::B)
        } else {
            None
        }
    }

    pub fn role_of(&self, key: &PeerKey) -> Role {
        self.try_role_of(key)
            .expect("key must belong to this bootstrap")
    }

    pub fn peer_key_for(&self, key: &PeerKey) -> Option<&PeerKey> {
        if key.as_bytes() == self.hello_a.key().as_bytes() {
            Some(self.hello_b.key())
        } else if key.as_bytes() == self.hello_b.key().as_bytes() {
            Some(self.hello_a.key())
        } else {
            None
        }
    }

    /// 12-digit out-of-band short authentication string (`XXXX-XXXX-XXXX`)
    /// bound to `params_id` and both identity keys.
    pub fn safety_code(&self) -> String {
        let mut h = Sha512_256::new();
        h.update(SAFETY_CODE_DOMAIN);
        h.update(self.params_id());
        h.update(self.hello_a.key().as_bytes());
        h.update(self.hello_b.key().as_bytes());
        let digest: [u8; 32] = h.finalize().into();
        let mut buf = [0u8; 8];
        buf[..6].copy_from_slice(&digest[..6]);
        let num = u64::from_le_bytes(buf) % 1_000_000_000_000;
        format!(
            "{:04}-{:04}-{:04}",
            num / 100_000_000,
            (num / 10_000) % 10_000,
            num % 10_000
        )
    }

    pub fn hello_a(&self) -> &Hello {
        &self.hello_a
    }

    pub fn hello_b(&self) -> &Hello {
        &self.hello_b
    }
}

/// A = lower identity key, B = higher; the same key pair always gets the same roles, so A
/// always keeps the last-reveal abort option (accepted). Roles are deliberately NOT taken
/// from a sid bit: a party seeing the other Hello first could grind its nonce.
///
/// ```text
/// sid          = SHA-512/256(SID_DOMAIN || params_id || pk_A || nonce_A || pk_B || nonce_B)
/// genesis_hash = SHA-512/256(GENESIS_DOMAIN || signed_hello_A || signed_hello_B)
/// ```
pub fn complete_bootstrap(
    first: CheckedHello,
    second: CheckedHello,
) -> Result<SessionBootstrap, HelloError> {
    if first.hello.params_id() != second.hello.params_id() {
        return Err(HelloError::ParamsIdMismatch);
    }
    if first.hello.key().as_bytes() == second.hello.key().as_bytes() {
        return Err(HelloError::EqualIdentityKeys);
    }
    let (hello_a, hello_b) = if first.hello.key() < second.hello.key() {
        (first.hello, second.hello)
    } else {
        (second.hello, first.hello)
    };

    let mut sid_hasher = Sha512_256::new();
    sid_hasher.update(SID_DOMAIN);
    sid_hasher.update(hello_a.params_id());
    sid_hasher.update(hello_a.key().as_bytes());
    sid_hasher.update(hello_a.nonce());
    sid_hasher.update(hello_b.key().as_bytes());
    sid_hasher.update(hello_b.nonce());
    let sid: [u8; 32] = sid_hasher.finalize().into();

    let mut genesis_hasher = Sha512_256::new();
    genesis_hasher.update(GENESIS_DOMAIN);
    genesis_hasher.update(hello_a.encode());
    genesis_hasher.update(hello_b.encode());
    let genesis_hash: [u8; 32] = genesis_hasher.finalize().into();

    Ok(SessionBootstrap {
        hello_a,
        hello_b,
        sid,
        genesis_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ExpectedKey;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use zkb_core::params::Parameters;

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn params_id() -> [u8; 32] {
        *Parameters::standard().params_id()
    }

    fn make_hello(seed: u8, nonce: u8) -> (IdentityKeypair, Hello) {
        let keypair = IdentityKeypair::from_seed(&[seed; 32]);
        let mut rng = rng(nonce);
        let hello = Hello::create(&keypair, params_id(), &mut rng);
        (keypair, hello)
    }

    fn check(hello: Hello, keypair: &IdentityKeypair) -> CheckedHello {
        check_hello(hello, &params_id(), &ExpectedKey::new(keypair.peer_key())).unwrap()
    }

    #[test]
    fn hello_roundtrip_and_check() {
        let (keypair, hello) = make_hello(1, 2);
        let decoded = Hello::decode(&hello.encode()).unwrap();
        assert_eq!(decoded.key(), &keypair.peer_key());
        let checked = check(decoded, &keypair);
        assert_eq!(checked.authenticated_peer().key(), &keypair.peer_key());
    }

    #[test]
    fn policy_cannot_substitute_a_different_key() {
        // A policy that authenticates a key other than the announced one must be rejected.
        struct Substitute(PeerKey);
        impl PeerAuthPolicy for Substitute {
            fn authenticate(&self, _announced: &PeerKey) -> Option<AuthenticatedPeer> {
                ExpectedKey::new(self.0).authenticate(&self.0)
            }
        }
        let (_, hello) = make_hello(1, 2);
        let other = IdentityKeypair::from_seed(&[8; 32]).peer_key();
        assert_eq!(
            check_hello(hello, &params_id(), &Substitute(other)),
            Err(HelloError::PeerNotAuthenticated)
        );
    }

    #[test]
    fn hello_rejects_tampering() {
        let (keypair, hello) = make_hello(1, 2);
        let bytes = hello.encode();

        assert!(matches!(
            Hello::decode(&bytes[..Hello::LEN - 1]),
            Err(HelloError::WrongLength { .. })
        ));

        let mut bad = hello.clone();
        bad.version = 2;
        assert_eq!(
            check_hello(bad, &params_id(), &ExpectedKey::new(keypair.peer_key())),
            Err(HelloError::WrongVersion {
                expected: 1,
                actual: 2
            })
        );

        let mut bad = hello.clone();
        bad.params_id = [0xEE; 32];
        assert_eq!(
            check_hello(bad, &params_id(), &ExpectedKey::new(keypair.peer_key())),
            Err(HelloError::ParamsIdMismatch)
        );

        let mut bad = hello.clone();
        bad.nonce[0] ^= 1;
        assert_eq!(
            check_hello(bad, &params_id(), &ExpectedKey::new(keypair.peer_key())),
            Err(HelloError::InvalidSignature)
        );

        let stranger = IdentityKeypair::from_seed(&[9; 32]);
        assert_eq!(
            check_hello(hello, &params_id(), &ExpectedKey::new(stranger.peer_key())),
            Err(HelloError::PeerNotAuthenticated)
        );
    }

    #[test]
    fn bootstrap_rejects_equal_keys() {
        let (keypair, hello) = make_hello(1, 2);
        let first = check(hello.clone(), &keypair);
        let second = check(hello, &keypair);
        assert_eq!(
            complete_bootstrap(first, second),
            Err(HelloError::EqualIdentityKeys)
        );
    }

    #[test]
    fn bootstrap_vectors_are_pinned() {
        let (ka, ha) = make_hello(0x11, 0x33);
        let (kb, hb) = make_hello(0x22, 0x44);
        let bootstrap = complete_bootstrap(check(ha, &ka), check(hb, &kb)).unwrap();

        let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex(bootstrap.sid()),
            "05a70f538f64c136278b7ad0a60f6153d4b133e1df24c93fdbd00d47b49d5a19"
        );
        assert_eq!(
            hex(bootstrap.genesis_hash()),
            "181859589b76e3638fb28b540705bb7661a5b80cb59b66f5c38bd31a8015b1ea"
        );

        let (lo, hi) = if ka.peer_key() < kb.peer_key() {
            (&ka, &kb)
        } else {
            (&kb, &ka)
        };
        assert_eq!(bootstrap.role_of(&lo.peer_key()), Role::A);
        assert_eq!(bootstrap.role_of(&hi.peer_key()), Role::B);
        assert_eq!(bootstrap.peer_key_for(&lo.peer_key()), Some(&hi.peer_key()));
        assert_eq!(bootstrap.peer_key_for(&hi.peer_key()), Some(&lo.peer_key()));
        let third = IdentityKeypair::from_seed(&[0x77; 32]).peer_key();
        assert_eq!(bootstrap.try_role_of(&third), None);
        assert_eq!(bootstrap.peer_key_for(&third), None);
        assert_eq!(bootstrap.safety_code().len(), 14);
        assert_eq!(bootstrap.hello_a().key(), &lo.peer_key());
        assert_eq!(bootstrap.hello_b().key(), &hi.peer_key());
    }

    #[test]
    fn bootstrap_rejects_mismatched_params_id() {
        let ka = IdentityKeypair::from_seed(&[0x11; 32]);
        let kb = IdentityKeypair::from_seed(&[0x22; 32]);
        let ha = Hello::create(&ka, *Parameters::standard().params_id(), &mut rng(1));
        let hb = Hello::create(&kb, *Parameters::no_touch().params_id(), &mut rng(2));
        let ca = check_hello(
            ha,
            Parameters::standard().params_id(),
            &ExpectedKey::new(ka.peer_key()),
        )
        .unwrap();
        let cb = check_hello(
            hb,
            Parameters::no_touch().params_id(),
            &ExpectedKey::new(kb.peer_key()),
        )
        .unwrap();
        assert_eq!(
            complete_bootstrap(ca, cb),
            Err(HelloError::ParamsIdMismatch)
        );
    }
}
