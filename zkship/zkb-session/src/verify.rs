//! Public, zero-secret third-party transcript verifier and violation auditor
//! (paper Section 7 and Section 10).
//!
//! Takes two `Hello` messages (in either order) and the linear sequence of
//! signed frames, checks every signature, setup proof, coin flip, shot, answer,
//! not-sunk range proof, and sink opening, and returns either a verified final
//! outcome, an incomplete prefix report, or the exact attributable frame
//! proving which peer cheated.

use crate::codec::MessageType;
use crate::coin;
use crate::frame::{self, ChainExpectation, SignedFrame};
use crate::hello::{self, Hello, HelloError};
use crate::identity::{ExpectedKey, PeerAuthPolicy, PeerKey};
use crate::state::{ClassBReason, Violation};
use std::fmt;
use zkb_core::answers::{
    self, AnswerContext, AnswerOutcome, AnswerRejection, BoardShots, ShotAnswer,
};
use zkb_core::game::{GameError, Role};
use zkb_core::params::{CellIndex, Parameters, Rules, K, T};
use zkb_core::setup::{self, SetupMessage, VerifiedSetup};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoinStep {
    Commit,
    Nonce,
    Reveal,
}

#[derive(Debug)]
pub enum TranscriptVerdict {
    Completed {
        winner: Role,
    },
    Resigned {
        winner: Role,
        resigned: Role,
    },
    AttributableViolation {
        guilty: Role,
        sequence: u64,
        frame_hash: [u8; 32],
        violation: Violation,
    },
    Incomplete {
        expected_next: Role,
    },
}

#[derive(Debug)]
pub enum TranscriptError {
    InvalidHello(HelloError),
    UnknownParamsId([u8; 32]),
    InvalidFrame { index: usize, reason: ClassBReason },
}

impl fmt::Display for TranscriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TranscriptError::InvalidHello(e) => write!(f, "invalid hello: {e}"),
            TranscriptError::UnknownParamsId(id) => {
                write!(f, "unknown params_id {}", hex_prefix(id))
            }
            TranscriptError::InvalidFrame { index, reason } => {
                write!(f, "class-B invalid frame at index {index}: {reason}")
            }
        }
    }
}

impl std::error::Error for TranscriptError {}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug)]
pub struct TranscriptReport {
    pub rules: Rules,
    pub params_id: [u8; 32],
    pub sid: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub role_a_key: PeerKey,
    pub role_b_key: PeerKey,
    pub first_mover: Option<Role>,
    pub frames_verified: usize,
    pub shots_by_a: u8,
    pub shots_by_b: u8,
    pub hits_by_a: u8,
    pub hits_by_b: u8,
    pub sunk_on_a: [bool; K],
    pub sunk_on_b: [bool; K],
    pub sunk_cells_on_a: [Option<Vec<CellIndex>>; K],
    pub sunk_cells_on_b: [Option<Vec<CellIndex>>; K],
    pub verdict: TranscriptVerdict,
}

enum VerifyPhase {
    Commit,
    Coin {
        step: CoinStep,
        coin_commit: Option<[u8; 32]>,
        r_b: Option<[u8; 32]>,
    },
    Playing {
        expected_next: Role,
        pending_shot: Option<(Role, CellIndex)>,
        a_board: Box<BoardShots>,
        b_board: Box<BoardShots>,
    },
    Finished {
        winner: Role,
        resigned: Option<Role>,
        a_board: Box<BoardShots>,
        b_board: Box<BoardShots>,
    },
}

impl VerifyPhase {
    fn expected_sender(&self, a_done: bool) -> Option<Role> {
        match self {
            VerifyPhase::Commit => Some(if a_done { Role::B } else { Role::A }),
            VerifyPhase::Coin { step, .. } => Some(match step {
                CoinStep::Commit => Role::A,
                CoinStep::Nonce => Role::B,
                CoinStep::Reveal => Role::A,
            }),
            VerifyPhase::Playing { expected_next, .. } => Some(*expected_next),
            VerifyPhase::Finished { .. } => None,
        }
    }

    fn boards(&self) -> Option<(&BoardShots, &BoardShots)> {
        match self {
            VerifyPhase::Playing {
                a_board, b_board, ..
            }
            | VerifyPhase::Finished {
                a_board, b_board, ..
            } => Some((a_board, b_board)),
            VerifyPhase::Commit | VerifyPhase::Coin { .. } => None,
        }
    }
}

fn params_for_id(params_id: &[u8; 32]) -> Result<&'static Parameters, TranscriptError> {
    let std_params = Parameters::standard();
    if std_params.params_id() == params_id {
        return Ok(std_params);
    }
    let nt_params = Parameters::no_touch();
    if nt_params.params_id() == params_id {
        return Ok(nt_params);
    }
    Err(TranscriptError::UnknownParamsId(*params_id))
}

/// Verifies a full or partial public transcript from both `Hello` messages
/// (accepted in either order) and the sequential signed frames.
pub fn verify_transcript(
    hello_one: &[u8],
    hello_two: &[u8],
    frames: &[impl AsRef<[u8]>],
) -> Result<TranscriptReport, TranscriptError> {
    let h1 = Hello::decode(hello_one).map_err(TranscriptError::InvalidHello)?;
    let h2 = Hello::decode(hello_two).map_err(TranscriptError::InvalidHello)?;
    let params = params_for_id(h1.params_id())?;
    verify_with_hellos(h1, h2, params, frames)
}

fn verify_with_hellos(
    h1: Hello,
    h2: Hello,
    params: &'static Parameters,
    frames: &[impl AsRef<[u8]>],
) -> Result<TranscriptReport, TranscriptError> {
    let p1 = ExpectedKey::new(*h1.key());
    let c1 =
        hello::check_hello(h1, params.params_id(), &p1).map_err(TranscriptError::InvalidHello)?;
    let p2 = ExpectedKey::new(*h2.key());
    let c2 =
        hello::check_hello(h2, params.params_id(), &p2).map_err(TranscriptError::InvalidHello)?;
    let bootstrap = hello::complete_bootstrap(c1, c2).map_err(TranscriptError::InvalidHello)?;

    let role_a_key = *bootstrap.hello_a().key();
    let role_b_key = *bootstrap.hello_b().key();
    let auth_a = ExpectedKey::new(role_a_key)
        .authenticate(&role_a_key)
        .expect("verified hello key");
    let auth_b = ExpectedKey::new(role_b_key)
        .authenticate(&role_b_key)
        .expect("verified hello key");
    let sid = *bootstrap.sid();
    let genesis_hash = *bootstrap.genesis_hash();

    let mut head_seq = 0u64;
    let mut head_hash = genesis_hash;
    let mut a_setup: Option<VerifiedSetup> = None;
    let mut b_setup: Option<VerifiedSetup> = None;
    let mut phase = VerifyPhase::Commit;
    let mut first_mover: Option<Role> = None;
    let mut shots_by_a = 0u8;
    let mut shots_by_b = 0u8;
    let mut hits_by_a = 0u8;
    let mut hits_by_b = 0u8;
    let mut frames_verified = 0usize;
    let mut violation_found: Option<(Role, u64, [u8; 32], Violation)> = None;

    for (index, raw_ref) in frames.iter().enumerate() {
        let raw = raw_ref.as_ref();
        let frame = SignedFrame::decode(raw).map_err(|e| TranscriptError::InvalidFrame {
            index,
            reason: ClassBReason::Malformed(e),
        })?;
        let expected_seq = head_seq + 1;
        let expectation = ChainExpectation {
            sid,
            sequence: expected_seq,
            prev_hash: head_hash,
        };
        let (signer, auth_frame) = match frame.clone().authenticate(&expectation, &auth_a) {
            Ok(auth) => (Role::A, auth),
            Err(crate::frame::ChainError::BadSignature) => {
                match frame.authenticate(&expectation, &auth_b) {
                    Ok(auth) => (Role::B, auth),
                    Err(e) => {
                        return Err(TranscriptError::InvalidFrame {
                            index,
                            reason: map_chain_err(e),
                        });
                    }
                }
            }
            Err(e) => {
                return Err(TranscriptError::InvalidFrame {
                    index,
                    reason: map_chain_err(e),
                });
            }
        };

        let frame_hash = auth_frame.frame().frame_hash();
        let claimed = auth_frame.frame().header().sender_role;
        if claimed != frame::role_to_byte(signer) {
            violation_found = Some((
                signer,
                expected_seq,
                frame_hash,
                Violation::SenderRoleMismatch { claimed },
            ));
            break;
        }

        let message_type = auth_frame.frame().header().message_type;
        if message_type == MessageType::Resign {
            if phase.expected_sender(a_setup.is_some()) == Some(signer) {
                let (a_board, b_board) = phase
                    .boards()
                    .map(|(a, b)| (Box::new(a.clone()), Box::new(b.clone())))
                    .unwrap_or_default();
                phase = VerifyPhase::Finished {
                    winner: signer.other(),
                    resigned: Some(signer),
                    a_board,
                    b_board,
                };
                head_seq = expected_seq;
                head_hash = frame_hash;
                frames_verified += 1;
                continue;
            }
            violation_found = Some((signer, expected_seq, frame_hash, Violation::OutOfTurnResign));
            break;
        }

        let signer_key = match signer {
            Role::A => &role_a_key,
            Role::B => &role_b_key,
        };
        let payload = auth_frame.frame().payload();
        let mut step_violation: Option<Violation> = None;

        match &mut phase {
            VerifyPhase::Commit => {
                let expected = if a_setup.is_some() { Role::B } else { Role::A };
                if message_type != MessageType::Commit || signer != expected {
                    step_violation = Some(Violation::UnexpectedMessage { message_type });
                } else {
                    let verified = SetupMessage::decode(payload, params.rules())
                        .and_then(|msg| setup::verify(params, signer_key.as_bytes(), &sid, &msg));
                    match verified {
                        Ok(v) => {
                            match signer {
                                Role::A => a_setup = Some(v),
                                Role::B => b_setup = Some(v),
                            }
                            if a_setup.is_some() && b_setup.is_some() {
                                phase = VerifyPhase::Coin {
                                    step: CoinStep::Commit,
                                    coin_commit: None,
                                    r_b: None,
                                };
                            }
                        }
                        Err(e) => step_violation = Some(Violation::InvalidCommit(e)),
                    }
                }
            }
            VerifyPhase::Coin {
                step,
                coin_commit,
                r_b,
            } => match (*step, message_type, signer) {
                (CoinStep::Commit, MessageType::CoinCommit, Role::A) => {
                    let c: [u8; 32] = payload.try_into().expect("32-byte CoinCommit");
                    *coin_commit = Some(c);
                    *step = CoinStep::Nonce;
                }
                (CoinStep::Nonce, MessageType::CoinNonce, Role::B) => {
                    let rb: [u8; 32] = payload.try_into().expect("32-byte CoinNonce");
                    *r_b = Some(rb);
                    *step = CoinStep::Reveal;
                }
                (CoinStep::Reveal, MessageType::CoinReveal, Role::A) => {
                    let ra: [u8; 32] = payload.try_into().expect("32-byte CoinReveal");
                    let commit = coin_commit.as_ref().expect("CoinCommit seen");
                    if !coin::verify_reveal(&sid, commit, &ra) {
                        step_violation = Some(Violation::BadCoinReveal);
                    } else {
                        let rb = r_b.as_ref().expect("CoinNonce seen");
                        let fm = coin::first_mover(&sid, &ra, rb);
                        first_mover = Some(fm);
                        phase = VerifyPhase::Playing {
                            expected_next: fm,
                            pending_shot: None,
                            a_board: Box::new(BoardShots::default()),
                            b_board: Box::new(BoardShots::default()),
                        };
                    }
                }
                _ => step_violation = Some(Violation::UnexpectedMessage { message_type }),
            },
            VerifyPhase::Playing {
                expected_next,
                pending_shot,
                a_board,
                b_board,
            } => {
                let a_setup_ref = a_setup.as_ref().expect("A setup verified");
                let b_setup_ref = b_setup.as_ref().expect("B setup verified");
                match (message_type, *pending_shot) {
                    (MessageType::Shot, None) if signer == *expected_next => {
                        let cell_byte = payload[0];
                        let target_board = match signer {
                            Role::A => &mut **b_board,
                            Role::B => &mut **a_board,
                        };
                        let target_setup = match signer {
                            Role::A => b_setup_ref,
                            Role::B => a_setup_ref,
                        };
                        match CellIndex::from_index(cell_byte) {
                            None => {
                                step_violation =
                                    Some(Violation::InvalidShot(GameError::OutOfRangeShot {
                                        cell: cell_byte,
                                    }));
                            }
                            Some(cell) if target_board.is_shot(cell) => {
                                step_violation =
                                    Some(Violation::InvalidShot(GameError::RepeatedShot {
                                        cell: cell_byte,
                                    }));
                            }
                            Some(cell) => {
                                target_board.register(target_setup.ship_cells(), cell);
                                match signer {
                                    Role::A => shots_by_a += 1,
                                    Role::B => shots_by_b += 1,
                                }
                                *pending_shot = Some((signer, cell));
                                *expected_next = signer.other();
                            }
                        }
                    }
                    (MessageType::Answer, Some((shooter, cell))) if signer == shooter.other() => {
                        let (defender_board, defender_setup, shooter_hits) = match shooter {
                            Role::A => (&mut **b_board, b_setup_ref, &mut hits_by_a),
                            Role::B => (&mut **a_board, a_setup_ref, &mut hits_by_b),
                        };
                        match ShotAnswer::decode(payload, defender_board.unsunk_count()) {
                            Err(e) => step_violation = Some(Violation::InvalidAnswerEncoding(e)),
                            Ok(answer) => {
                                let ctx = AnswerContext {
                                    defender_id: signer_key.as_bytes(),
                                    sid: &sid,
                                };
                                match answers::verify_answer(
                                    params,
                                    &ctx,
                                    defender_setup.ship_cells(),
                                    defender_setup.cell_commitments(),
                                    defender_board,
                                    cell,
                                    &answer,
                                ) {
                                    Err(r) => step_violation = Some(Violation::InvalidAnswer(r)),
                                    Ok(outcome) => {
                                        match outcome {
                                            AnswerOutcome::Miss => {}
                                            AnswerOutcome::Hit => *shooter_hits += 1,
                                            AnswerOutcome::Sunk { ship, cells } => {
                                                defender_board.mark_sunk_with_cells(ship, cells);
                                                *shooter_hits += 1;
                                            }
                                        }
                                        *pending_shot = None;
                                        if *shooter_hits == T as u8 {
                                            if defender_board.unsunk_count() != 0 {
                                                step_violation = Some(Violation::InvalidAnswer(
                                                    AnswerRejection::MalformedSunkAnnouncement,
                                                ));
                                            } else {
                                                phase = VerifyPhase::Finished {
                                                    winner: shooter,
                                                    resigned: None,
                                                    a_board: a_board.clone(),
                                                    b_board: b_board.clone(),
                                                };
                                            }
                                        } else if defender_board.unsunk_count() == 0 {
                                            step_violation = Some(Violation::InvalidAnswer(
                                                AnswerRejection::MalformedSunkAnnouncement,
                                            ));
                                        } else {
                                            *expected_next = shooter.other();
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => step_violation = Some(Violation::UnexpectedMessage { message_type }),
                }
            }
            VerifyPhase::Finished { .. } => {
                step_violation = Some(Violation::UnexpectedMessage { message_type });
            }
        }

        if let Some(violation) = step_violation {
            violation_found = Some((signer, expected_seq, frame_hash, violation));
            break;
        }
        head_seq = expected_seq;
        head_hash = frame_hash;
        frames_verified += 1;
    }

    let (sunk_on_a, sunk_on_b, sunk_cells_on_a, sunk_cells_on_b) = match phase.boards() {
        Some((a_board, b_board)) => (
            *a_board.sunk(),
            *b_board.sunk(),
            std::array::from_fn(|j| a_board.sunk_cells(j).map(|c| c.to_vec())),
            std::array::from_fn(|j| b_board.sunk_cells(j).map(|c| c.to_vec())),
        ),
        None => (
            [false; K],
            [false; K],
            std::array::from_fn(|_| None),
            std::array::from_fn(|_| None),
        ),
    };

    let verdict = if let Some((guilty, sequence, frame_hash, violation)) = violation_found {
        TranscriptVerdict::AttributableViolation {
            guilty,
            sequence,
            frame_hash,
            violation,
        }
    } else {
        match phase {
            VerifyPhase::Finished {
                winner,
                resigned: Some(resigned),
                ..
            } => TranscriptVerdict::Resigned { winner, resigned },
            VerifyPhase::Finished {
                winner,
                resigned: None,
                ..
            } => TranscriptVerdict::Completed { winner },
            other => TranscriptVerdict::Incomplete {
                expected_next: other
                    .expected_sender(a_setup.is_some())
                    .expect("nonterminal has sender"),
            },
        }
    };

    Ok(TranscriptReport {
        rules: params.rules(),
        params_id: *params.params_id(),
        sid,
        genesis_hash,
        role_a_key,
        role_b_key,
        first_mover,
        frames_verified,
        shots_by_a,
        shots_by_b,
        hits_by_a,
        hits_by_b,
        sunk_on_a,
        sunk_on_b,
        sunk_cells_on_a,
        sunk_cells_on_b,
        verdict,
    })
}

fn map_chain_err(err: crate::frame::ChainError) -> ClassBReason {
    match err {
        crate::frame::ChainError::WrongSession => ClassBReason::WrongSession,
        crate::frame::ChainError::WrongSequence { expected, actual } => {
            ClassBReason::WrongSequence { expected, actual }
        }
        crate::frame::ChainError::WrongPrevHash => ClassBReason::WrongPrevHash,
        crate::frame::ChainError::BadSignature => ClassBReason::BadSignature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeypair;
    use crate::state::{AcceptOutcome, Session};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use zkb_core::fleet::{Fleet, SHIP_BITS};

    fn auth(kp: &IdentityKeypair) -> crate::identity::AuthenticatedPeer {
        ExpectedKey::new(kp.peer_key())
            .authenticate(&kp.peer_key())
            .unwrap()
    }

    fn fleet_a(rules: Rules) -> Fleet {
        Fleet::from_bytes(&[0, 0, 0, 2, 0, 0, 4, 0, 0, 6, 0, 0, 8, 0, 0], rules).unwrap()
    }

    fn fleet_b(rules: Rules) -> Fleet {
        Fleet::from_bytes(&[0, 9, 1, 0, 7, 1, 0, 5, 1, 0, 3, 1, 0, 1, 1], rules).unwrap()
    }

    fn blinders(seed: u8) -> Vec<curve25519_dalek::scalar::Scalar> {
        let mut r = ChaCha20Rng::from_seed([seed; 32]);
        (0..SHIP_BITS)
            .map(|_| curve25519_dalek::scalar::Scalar::random(&mut r))
            .collect()
    }

    struct TranscriptFixture {
        hello_a: Vec<u8>,
        hello_b: Vec<u8>,
        sid: [u8; 32],
        ka: IdentityKeypair,
        kb: IdentityKeypair,
        frames: Vec<Vec<u8>>,
        winner: Role,
    }

    fn play_full_game(rules: Rules) -> TranscriptFixture {
        let params = Parameters::for_rules(rules);
        let params_id = *params.params_id();
        let k0 = IdentityKeypair::from_seed(&[0x11; 32]);
        let k1 = IdentityKeypair::from_seed(&[0x22; 32]);
        let mut r = ChaCha20Rng::from_seed([0x99; 32]);
        let h0 = Hello::create(&k0, params_id, &mut r);
        let h1 = Hello::create(&k1, params_id, &mut r);
        let c0 =
            hello::check_hello(h0.clone(), &params_id, &ExpectedKey::new(k0.peer_key())).unwrap();
        let c1 =
            hello::check_hello(h1.clone(), &params_id, &ExpectedKey::new(k1.peer_key())).unwrap();
        let bootstrap = hello::complete_bootstrap(c0, c1).unwrap();
        let (ka, kb, hello_a, hello_b) = if bootstrap.role_of(&k0.peer_key()) == Role::A {
            (k0, k1, h0.encode(), h1.encode())
        } else {
            (k1, k0, h1.encode(), h0.encode())
        };
        let mut sa = Session::from_bootstrap(
            params,
            &ka,
            &bootstrap,
            auth(&kb),
            fleet_a(rules),
            blinders(0xA0),
        )
        .unwrap();
        let mut sb = Session::from_bootstrap(
            params,
            &kb,
            &bootstrap,
            auth(&ka),
            fleet_b(rules),
            blinders(0xB0),
        )
        .unwrap();

        let mut first_mover = None;
        for _ in 0..10 {
            while let Some(f) = sa.produce(&mut r).unwrap() {
                if let AcceptOutcome::GameReady { first_mover: fm } = sb.accept(f.bytes()).unwrap()
                {
                    first_mover = Some(fm);
                }
            }
            while let Some(f) = sb.produce(&mut r).unwrap() {
                if let AcceptOutcome::GameReady { first_mover: fm } = sa.accept(f.bytes()).unwrap()
                {
                    first_mover = Some(fm);
                }
            }
            if sa.phase_kind() == crate::state::PhaseKind::Playing
                && sb.phase_kind() == crate::state::PhaseKind::Playing
            {
                break;
            }
        }
        let mut current = first_mover.unwrap();
        let winner = loop {
            let (att, def) = if current == Role::A {
                (&mut sa, &mut sb)
            } else {
                (&mut sb, &mut sa)
            };
            let cell = (0..100u8)
                .map(|i| CellIndex::from_index(i).unwrap())
                .find(|c| {
                    !att.game()
                        .unwrap()
                        .shots_on_board(current.other())
                        .is_shot(*c)
                })
                .unwrap();
            let shot = att.fire_shot(cell).unwrap();
            let AcceptOutcome::ShotReceived { answer, .. } = def.accept(shot.bytes()).unwrap()
            else {
                panic!();
            };
            match att.accept(answer.bytes()).unwrap() {
                AcceptOutcome::GameFinished { winner } => break winner,
                AcceptOutcome::Answer(_) => current = current.other(),
                other => panic!("unexpected {other:?}"),
            }
        };
        let frames = sa.transcript().to_vec();
        drop((sa, sb));
        TranscriptFixture {
            hello_a,
            hello_b,
            sid: *bootstrap.sid(),
            ka,
            kb,
            frames,
            winner,
        }
    }

    #[test]
    fn verifies_completed_games_and_prefixes() {
        for rules in [Rules::Standard, Rules::NoTouch] {
            let fix = play_full_game(rules);
            // Accepts Hellos in either order.
            let report = verify_transcript(&fix.hello_b, &fix.hello_a, &fix.frames).unwrap();
            assert_eq!(report.rules, rules);
            assert!(matches!(
                report.verdict,
                TranscriptVerdict::Completed { winner } if winner == fix.winner
            ));
            assert_eq!(report.frames_verified, fix.frames.len());
            assert_eq!(report.hits_by_a, T as u8);
            assert_eq!(report.sunk_on_b, [true; K]);

            // Empty transcript is Incomplete awaiting Role A.
            let empty: [&[u8]; 0] = [];
            let r0 = verify_transcript(&fix.hello_a, &fix.hello_b, &empty).unwrap();
            assert!(matches!(
                r0.verdict,
                TranscriptVerdict::Incomplete {
                    expected_next: Role::A
                }
            ));

            // Prefix ending mid-shot is Incomplete awaiting defender.
            let r_mid = verify_transcript(&fix.hello_a, &fix.hello_b, &fix.frames[..6]).unwrap();
            assert!(matches!(
                r_mid.verdict,
                TranscriptVerdict::Incomplete { .. }
            ));
        }
    }

    #[test]
    fn verifies_resignation_and_attributes_violations() {
        let fix = play_full_game(Rules::Standard);

        // In-turn resignation on frame 0 (Commit owed by A).
        let genesis = hello::complete_bootstrap(
            hello::check_hello(
                Hello::decode(&fix.hello_a).unwrap(),
                Parameters::standard().params_id(),
                &ExpectedKey::new(fix.ka.peer_key()),
            )
            .unwrap(),
            hello::check_hello(
                Hello::decode(&fix.hello_b).unwrap(),
                Parameters::standard().params_id(),
                &ExpectedKey::new(fix.kb.peer_key()),
            )
            .unwrap(),
        )
        .unwrap()
        .genesis_hash()
        .to_owned();
        let resign = SignedFrame::craft(
            &fix.ka,
            &fix.sid,
            Role::A,
            1,
            MessageType::Resign,
            &genesis,
            vec![],
        );
        let r = verify_transcript(&fix.hello_a, &fix.hello_b, &[resign.bytes()]).unwrap();
        assert!(matches!(
            r.verdict,
            TranscriptVerdict::Resigned {
                winner: Role::B,
                resigned: Role::A
            }
        ));

        // Out-of-turn resign by B at seq 1 is attributable to B.
        let bad_resign = SignedFrame::craft(
            &fix.kb,
            &fix.sid,
            Role::B,
            1,
            MessageType::Resign,
            &genesis,
            vec![],
        );
        let r = verify_transcript(&fix.hello_a, &fix.hello_b, &[bad_resign.bytes()]).unwrap();
        assert!(matches!(
            r.verdict,
            TranscriptVerdict::AttributableViolation {
                guilty: Role::B,
                sequence: 1,
                violation: Violation::OutOfTurnResign,
                ..
            }
        ));

        // Sender-role mismatch: A signs with Role::B byte.
        let bad_role = SignedFrame::craft(
            &fix.ka,
            &fix.sid,
            Role::B,
            1,
            MessageType::Commit,
            &genesis,
            vec![0; crate::codec::COMMIT_PAYLOAD_LEN],
        );
        let r = verify_transcript(&fix.hello_a, &fix.hello_b, &[bad_role.bytes()]).unwrap();
        assert!(matches!(
            r.verdict,
            TranscriptVerdict::AttributableViolation {
                guilty: Role::A,
                sequence: 1,
                violation: Violation::SenderRoleMismatch { claimed: 1 },
                ..
            }
        ));

        // Post-finish frame attributed to its signer.
        let last_frame = SignedFrame::decode(fix.frames.last().unwrap()).unwrap();
        let post = SignedFrame::craft(
            &fix.kb,
            &fix.sid,
            Role::B,
            last_frame.header().sequence + 1,
            MessageType::Shot,
            &last_frame.frame_hash(),
            vec![0],
        );
        let mut extended = fix.frames.clone();
        extended.push(post.bytes().to_vec());
        let r = verify_transcript(&fix.hello_a, &fix.hello_b, &extended).unwrap();
        assert!(matches!(
            r.verdict,
            TranscriptVerdict::AttributableViolation {
                guilty: Role::B,
                violation: Violation::UnexpectedMessage {
                    message_type: MessageType::Shot
                },
                ..
            }
        ));

        // Class-B forged signature returns Err(InvalidFrame).
        let mut forged = fix.frames[0].clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(matches!(
            verify_transcript(&fix.hello_a, &fix.hello_b, &[forged]),
            Err(TranscriptError::InvalidFrame {
                index: 0,
                reason: ClassBReason::BadSignature
            })
        ));
    }
}
