//! Replays `vectors/game_transcript_v1.txt` byte-for-byte (both proofs included; slow in debug).

use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;
use zkb_core::fleet::{Fleet, SHIP_BITS};
use zkb_core::game::Role;
use zkb_core::params::{CellIndex, Parameters, Rules, N, T};
use zkb_core::setup::{self, SetupMessage};
use zkb_session::hello::{self, Hello};
use zkb_session::identity::{ExpectedKey, IdentityKeypair, PeerAuthPolicy};
use zkb_session::state::{AcceptOutcome, Session};
use zkb_session::verify::{self, TranscriptVerdict};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digit"))
        .collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32 bytes")
}

fn parse_vector(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| {
            let (key, value) = line.split_once(" = ").expect("`key = value` line");
            (key.to_string(), value.to_string())
        })
        .collect()
}

fn fleet(field: &str) -> Fleet {
    let bytes: [u8; 15] = unhex(field).try_into().expect("15 fleet bytes");
    Fleet::from_bytes(&bytes, Rules::Standard).expect("legal fleet")
}

fn rng_seed(field: &str) -> [u8; 32] {
    let seed = field
        .strip_prefix("chacha20rng(seed=")
        .and_then(|s| s.strip_suffix(')'))
        .expect("chacha20rng(seed=...) field");
    unhex32(seed)
}

fn blinders(field: &str) -> Vec<Scalar> {
    let mut rng = ChaCha20Rng::from_seed(rng_seed(field));
    (0..SHIP_BITS).map(|_| Scalar::random(&mut rng)).collect()
}

#[test]
fn game_transcript_vector_replays_byte_for_byte() {
    let params = Parameters::standard();
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors/game_transcript_v1.txt");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}; regenerate with `cargo run -p zkb-session --example generate_game_transcript`", path.display()));
    let v = parse_vector(&text);

    assert_eq!(v["profile"], "zkbattleship/paper/v1");
    assert_eq!(v["params_id"], hex(params.params_id()));

    let ka = IdentityKeypair::from_seed(&unhex32(&v["key_seed_role_a"]));
    let kb = IdentityKeypair::from_seed(&unhex32(&v["key_seed_role_b"]));
    let hello_a = Hello::decode(&unhex(&v["hello_role_a"])).unwrap();
    let hello_b = Hello::decode(&unhex(&v["hello_role_b"])).unwrap();
    assert_eq!(hello_a.key(), &ka.peer_key());
    assert_eq!(hello_b.key(), &kb.peer_key());
    let checked_a = hello::check_hello(
        hello_a,
        params.params_id(),
        &ExpectedKey::new(ka.peer_key()),
    )
    .unwrap();
    let checked_b = hello::check_hello(
        hello_b,
        params.params_id(),
        &ExpectedKey::new(kb.peer_key()),
    )
    .unwrap();
    let bootstrap = hello::complete_bootstrap(checked_a, checked_b).unwrap();
    assert_eq!(bootstrap.role_of(&ka.peer_key()), Role::A);
    assert_eq!(bootstrap.role_of(&kb.peer_key()), Role::B);
    assert_eq!(hex(bootstrap.sid()), v["sid"]);
    assert_eq!(hex(bootstrap.genesis_hash()), v["genesis_hash"]);

    let auth = |kp: &IdentityKeypair| {
        ExpectedKey::new(kp.peer_key())
            .authenticate(&kp.peer_key())
            .unwrap()
    };
    let mut sa = Session::new(
        params,
        &ka,
        Role::A,
        auth(&kb),
        *bootstrap.sid(),
        *bootstrap.genesis_hash(),
        fleet(&v["fleet_role_a"]),
        blinders(&v["blinders_seed_role_a"]),
    )
    .unwrap();
    let mut sb = Session::new(
        params,
        &kb,
        Role::B,
        auth(&ka),
        *bootstrap.sid(),
        *bootstrap.genesis_hash(),
        fleet(&v["fleet_role_b"]),
        blinders(&v["blinders_seed_role_b"]),
    )
    .unwrap();

    let frames: Vec<Vec<u8>> = v
        .iter()
        .filter(|(key, _)| key.starts_with("frame["))
        .map(|(_, value)| unhex(value))
        .collect();
    assert_eq!(frames.len(), v["frame_count"].parse::<usize>().unwrap());

    let proof_seed_a = rng_seed(&v["proof_finalize_rng_role_a"]);
    let proof_seed_b = rng_seed(&v["proof_finalize_rng_role_b"]);
    let mut coin_rng_a = ChaCha20Rng::from_seed(rng_seed(&v["coin_rng_role_a"]));
    let mut coin_rng_b = ChaCha20Rng::from_seed(rng_seed(&v["coin_rng_role_b"]));

    let mut idx = 0usize;
    let mut first_mover_seen: Option<Role> = None;
    for _ in 0..16 {
        while let Some(f) = sa
            .produce_with_rng(&mut coin_rng_a, ChaCha20Rng::from_seed(proof_seed_a))
            .unwrap()
        {
            assert_eq!(f.bytes(), frames[idx].as_slice(), "frame {idx}");
            idx += 1;
            if let AcceptOutcome::GameReady { first_mover } = sb.accept(f.bytes()).unwrap() {
                first_mover_seen = Some(first_mover);
            }
        }
        while let Some(f) = sb
            .produce_with_rng(&mut coin_rng_b, ChaCha20Rng::from_seed(proof_seed_b))
            .unwrap()
        {
            assert_eq!(f.bytes(), frames[idx].as_slice(), "frame {idx}");
            idx += 1;
            if let AcceptOutcome::GameReady { first_mover } = sa.accept(f.bytes()).unwrap() {
                first_mover_seen = Some(first_mover);
            }
        }
        if first_mover_seen.is_some() && sa.game().is_some() && sb.game().is_some() {
            break;
        }
    }
    let first_mover = first_mover_seen.expect("coin flip resolved");
    assert_eq!(format!("{first_mover:?}"), v["first_mover"]);

    let mut current = first_mover;
    let winner = loop {
        let defender = current.other();
        let (attacker, attacked) = match current {
            Role::A => (&mut sa, &mut sb),
            Role::B => (&mut sb, &mut sa),
        };
        let cell = (0..N as u8)
            .map(|i| CellIndex::from_index(i).unwrap())
            .find(|c| {
                !attacker
                    .game()
                    .unwrap()
                    .shots_on_board(defender)
                    .is_shot(*c)
            })
            .expect("unshot cells remain");
        let shot = attacker.fire_shot(cell).unwrap();
        assert_eq!(shot.bytes(), frames[idx].as_slice(), "frame {idx}");
        idx += 1;
        let (answer, conceded) = match attacked.accept(shot.bytes()).unwrap() {
            AcceptOutcome::ShotReceived {
                answer,
                cell: shot_cell,
                winner,
                ..
            } => {
                assert_eq!(shot_cell, cell);
                (answer, winner)
            }
            other => panic!("expected ShotReceived, got {other:?}"),
        };
        assert_eq!(answer.bytes(), frames[idx].as_slice(), "frame {idx}");
        idx += 1;
        match attacker.accept(answer.bytes()).unwrap() {
            AcceptOutcome::GameFinished { winner } => {
                // Both sides finish at the same chain position.
                assert_eq!(conceded, Some(winner));
                break winner;
            }
            AcceptOutcome::Answer(_) => {
                assert_eq!(conceded, None);
                current = defender;
            }
            other => panic!("expected Answer/GameFinished, got {other:?}"),
        }
    };

    assert_eq!(idx, frames.len());
    assert_eq!(format!("{winner:?}"), v["winner"]);
    assert_eq!(v["winner_hits"].parse::<u8>().unwrap(), T as u8);
    assert_eq!(v["winner_sunk_total"].parse::<u8>().unwrap(), 5);

    assert_eq!(sa.transcript(), frames.as_slice());
    assert_eq!(sb.transcript(), frames.as_slice());
    assert_eq!(sa.head_sequence(), sb.head_sequence());
    assert_eq!(sa.head_hash(), sb.head_hash());
    assert_eq!(sa.winner(), Some(winner));
    assert_eq!(sb.winner(), Some(winner));
    assert_eq!(sa.expected_sender(), None);
    assert_eq!(sb.expected_sender(), None);

    let loser = match winner {
        Role::A => &sb,
        Role::B => &sa,
    };
    assert_eq!(
        loser.game().unwrap().verified_hits(),
        v["loser_hits"].parse::<u8>().unwrap()
    );
    assert_eq!(loser.game().unwrap().hits_conceded(), T as u8);

    // Confirm the zero-secret public verifier accepts the exact pinned transcript.
    let report = verify::verify_transcript(
        &unhex(&v["hello_role_a"]),
        &unhex(&v["hello_role_b"]),
        &frames,
    )
    .unwrap();
    assert!(matches!(
        report.verdict,
        TranscriptVerdict::Completed { winner: w } if w == winner
    ));
    assert_eq!(report.frames_verified, frames.len());
    assert_eq!(
        report.hits_by_a + report.hits_by_b,
        T as u8 + v["loser_hits"].parse::<u8>().unwrap()
    );
}

/// Decodes, re-encodes and verifies the pinned setup message.
#[test]
fn setup_message_vector_verifies() {
    let params = Parameters::standard();
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors/setup_message_v1.txt");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let v = parse_vector(&text);

    assert_eq!(v["profile"], "zkbattleship/paper/v1");
    assert_eq!(v["params_id"], hex(params.params_id()));

    let bytes = unhex(&v["setup_hex"]);
    assert_eq!(bytes.len(), v["setup_len"].parse::<usize>().unwrap());
    let sha512_256 = |bytes: &[u8]| {
        use sha2::{Digest, Sha512_256};
        hex(&Sha512_256::digest(bytes))
    };
    assert_eq!(sha512_256(&bytes), v["setup_sha512_256"]);

    let msg = SetupMessage::decode(&bytes, Rules::Standard).unwrap();
    assert_eq!(msg.encode(), bytes);
    setup::verify(params, &unhex32(&v["prover_id"]), &unhex32(&v["sid"]), &msg).unwrap();
}

/// Decodes, re-encodes and verifies the pinned no-touch setup message.
#[test]
fn notouch_setup_message_vector_verifies() {
    let params = Parameters::no_touch();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vectors/setup_message_notouch_v1.txt");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let v = parse_vector(&text);

    assert_eq!(v["profile"], "zkbattleship/paper/v1/no-touch");
    assert_eq!(v["params_id"], hex(params.params_id()));

    let bytes = unhex(&v["setup_hex"]);
    assert_eq!(bytes.len(), v["setup_len"].parse::<usize>().unwrap());
    let sha512_256 = |bytes: &[u8]| {
        use sha2::{Digest, Sha512_256};
        hex(&Sha512_256::digest(bytes))
    };
    assert_eq!(sha512_256(&bytes), v["setup_sha512_256"]);

    let msg = SetupMessage::decode(&bytes, Rules::NoTouch).unwrap();
    assert_eq!(msg.encode(), bytes);
    setup::verify(params, &unhex32(&v["prover_id"]), &unhex32(&v["sid"]), &msg).unwrap();
}
