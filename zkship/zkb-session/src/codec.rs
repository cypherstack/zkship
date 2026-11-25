//! Canonical wire codec. Every structural check runs before any allocation or group
//! arithmetic; no input may panic.

use std::fmt;
use zkb_core::answers::ShotAnswer;

/// Bounds all allocations; the largest legitimate frame is a no-touch `Commit`:
/// 78 + 20,544 + 64 = 20,686.
pub const MAX_FRAME_SIZE: usize = 32 * 1024;

/// Five setup/coin frames plus at most `2*N - 1` shots and one answer per shot.
/// In the worst legal game, both players miss every non-ship cell before the
/// first mover lands the final hit on shot 199.
pub const MAX_TRANSCRIPT_FRAMES: usize = 5 + 2 * (2 * zkb_core::params::N - 1);

/// `sid[32] || sender_role u8 || sequence u64 LE || message_type u8 || prev_hash[32] || payload_len u32 LE`.
pub const HEADER_LEN: usize = 32 + 1 + 8 + 1 + 32 + 4;

pub const SIGNATURE_LEN: usize = 64;

/// Setup message, standard rules: 559 points and 50 scalars = 19,488.
pub const COMMIT_PAYLOAD_LEN: usize = 19_488;

/// Setup message with the no-touch proof: 20,544.
pub const COMMIT_NO_TOUCH_PAYLOAD_LEN: usize = 20_544;

pub const COIN_PAYLOAD_LEN: usize = 32;

pub const SHOT_PAYLOAD_LEN: usize = 1;

pub const ANSWER_MISS_LEN: usize = zkb_core::answers::MISS_LEN;

/// Wire discriminants. Payload sizes: Commit 19,488 (20,544 with the no-touch rule; the
/// session checks the exact length for its profile); coin messages 32; Shot 1 (cell index);
/// Answer by tag: miss 33, hit 449/513/577 (by unsunk ships), sunk 100/133/166/199 (by
/// ship length); Resign 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    Commit = 1,
    CoinCommit = 2,
    CoinNonce = 3,
    CoinReveal = 4,
    Shot = 5,
    Answer = 6,
    Resign = 7,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<MessageType> {
        match v {
            1 => Some(MessageType::Commit),
            2 => Some(MessageType::CoinCommit),
            3 => Some(MessageType::CoinNonce),
            4 => Some(MessageType::CoinReveal),
            5 => Some(MessageType::Shot),
            6 => Some(MessageType::Answer),
            7 => Some(MessageType::Resign),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// For `Answer`, header length, actual length, and a length the tag allows must all
    /// agree before any group arithmetic; the game then checks the exact length.
    pub fn check_payload(self, payload: &[u8]) -> Result<(), CodecError> {
        let expected = match self {
            MessageType::Commit if payload.len() == COMMIT_NO_TOUCH_PAYLOAD_LEN => {
                COMMIT_NO_TOUCH_PAYLOAD_LEN
            }
            MessageType::Commit => COMMIT_PAYLOAD_LEN,
            MessageType::CoinCommit | MessageType::CoinNonce | MessageType::CoinReveal => {
                COIN_PAYLOAD_LEN
            }
            MessageType::Shot => SHOT_PAYLOAD_LEN,
            MessageType::Resign => 0,
            MessageType::Answer => match payload.first() {
                Some(&tag @ 0..=2) => {
                    if ShotAnswer::is_possible_length(tag, payload.len()) {
                        payload.len()
                    } else {
                        return Err(CodecError::WrongAnswerLength {
                            tag,
                            actual: payload.len(),
                        });
                    }
                }
                Some(&b) => return Err(CodecError::InvalidAnswerFlag(b)),
                None => ANSWER_MISS_LEN,
            },
        };
        if payload.len() != expected {
            return Err(CodecError::WrongPayloadLength {
                message_type: self,
                expected,
                actual: payload.len(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    FrameTooSmall {
        actual: usize,
    },
    FrameTooLarge {
        actual: usize,
    },
    LengthMismatch {
        declared: u32,
        actual: usize,
    },
    UnknownMessageType(u8),
    WrongPayloadLength {
        message_type: MessageType,
        expected: usize,
        actual: usize,
    },
    InvalidAnswerFlag(u8),
    WrongAnswerLength {
        tag: u8,
        actual: usize,
    },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::FrameTooSmall { actual } => {
                write!(
                    f,
                    "frame is {actual} bytes, smaller than header + signature"
                )
            }
            CodecError::FrameTooLarge { actual } => {
                write!(
                    f,
                    "frame is {actual} bytes, exceeding the {MAX_FRAME_SIZE}-byte maximum"
                )
            }
            CodecError::LengthMismatch { declared, actual } => {
                write!(
                    f,
                    "header declares {declared} payload bytes but {actual} are present"
                )
            }
            CodecError::UnknownMessageType(v) => write!(f, "unknown message type {v}"),
            CodecError::WrongPayloadLength {
                message_type,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{message_type:?} payload is {actual} bytes, expected {expected}"
                )
            }
            CodecError::InvalidAnswerFlag(b) => {
                write!(f, "answer payload starts with tag {b}, expected 0, 1 or 2")
            }
            CodecError::WrongAnswerLength { tag, actual } => {
                write!(f, "no answer with tag {tag} is {actual} bytes long")
            }
        }
    }
}

impl std::error::Error for CodecError {}

#[cfg(test)]
mod tests {
    use super::*;
    use zkb_core::params::Rules;
    use zkb_core::setup;

    #[test]
    fn commit_payload_len_matches_spec() {
        const _: () =
            assert!(HEADER_LEN + COMMIT_NO_TOUCH_PAYLOAD_LEN + SIGNATURE_LEN <= MAX_FRAME_SIZE);
        assert_eq!(COMMIT_PAYLOAD_LEN, setup::encoded_len(Rules::Standard));
        assert_eq!(
            COMMIT_NO_TOUCH_PAYLOAD_LEN,
            setup::encoded_len(Rules::NoTouch)
        );
        assert_eq!(HEADER_LEN, 78);
        assert_eq!(MAX_TRANSCRIPT_FRAMES, 403);
    }

    #[test]
    fn message_type_roundtrip() {
        for v in 1..=7u8 {
            let mt = MessageType::from_u8(v).unwrap();
            assert_eq!(mt.to_u8(), v);
        }
        assert_eq!(MessageType::from_u8(0), None);
        assert_eq!(MessageType::from_u8(8), None);
    }

    #[test]
    fn payload_size_rules() {
        assert!(MessageType::Commit
            .check_payload(&vec![0u8; COMMIT_PAYLOAD_LEN])
            .is_ok());
        assert!(matches!(
            MessageType::Commit.check_payload(&[0u8; 32]),
            Err(CodecError::WrongPayloadLength { .. })
        ));
        assert!(MessageType::CoinCommit.check_payload(&[0u8; 32]).is_ok());
        assert!(MessageType::Shot.check_payload(&[7]).is_ok());
        assert!(MessageType::Resign.check_payload(&[]).is_ok());
        assert!(matches!(
            MessageType::Resign.check_payload(&[0]),
            Err(CodecError::WrongPayloadLength { .. })
        ));

        assert!(MessageType::Commit
            .check_payload(&vec![0u8; COMMIT_NO_TOUCH_PAYLOAD_LEN])
            .is_ok());
        assert!(MessageType::Answer
            .check_payload(&[0u8; ANSWER_MISS_LEN])
            .is_ok());
        for len in [449, 513, 577] {
            let mut hit = vec![0u8; len];
            hit[0] = 1;
            assert!(MessageType::Answer.check_payload(&hit).is_ok());
        }
        for len in [100, 133, 166, 199] {
            let mut sunk = vec![0u8; len];
            sunk[0] = 2;
            assert!(MessageType::Answer.check_payload(&sunk).is_ok());
        }
        let mut hit = vec![0u8; 577];
        hit[0] = 1;
        assert_eq!(
            MessageType::Answer.check_payload(&hit[..ANSWER_MISS_LEN]),
            Err(CodecError::WrongAnswerLength { tag: 1, actual: 33 })
        );
        let mut bad = vec![0u8; ANSWER_MISS_LEN];
        bad[0] = 3;
        assert_eq!(
            MessageType::Answer.check_payload(&bad),
            Err(CodecError::InvalidAnswerFlag(3))
        );
        assert!(matches!(
            MessageType::Answer.check_payload(&[]),
            Err(CodecError::WrongPayloadLength { .. })
        ));
    }
}
