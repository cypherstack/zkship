//! Fleet placements and the paper's encoding (Section 3.2): the fleet is the
//! binary string `s in {0,1}^{m n^2}`, one indicator vector over the board
//! per ship (ship-major, `s[j*N + i]`), plus one orientation bit per ship.
//! The board itself is never committed; its cells are `b_i = sum_j s[j*N + i]`.
//!
//! Legality: every ship lies on the board as a straight segment of its
//! length, no cell holds two ships, and under [`Rules::NoTouch`] no two ships
//! are adjacent, diagonals included.

use crate::params::{CellIndex, Rules, BOARD_N, FLEET_LENGTHS, K, N};
use rand_core::{CryptoRng, RngCore};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Ship bits across the whole fleet: `K * N`.
pub const SHIP_BITS: usize = K * N;

/// A ship's first (top or left) cell and its direction. `vertical` is the
/// orientation bit `o_j` of the paper (Section 3.1): `o_j = 1` when the rows
/// vary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct ShipPlacement {
    pub row: u8,
    pub col: u8,
    pub vertical: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlacementError {
    OutOfBounds { ship: usize },
    Overlap { cell: u8 },
    Touching { cell: u8 },
}

impl fmt::Display for PlacementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlacementError::OutOfBounds { ship } => write!(f, "ship {ship} leaves the board"),
            PlacementError::Overlap { cell } => write!(f, "two ships occupy cell {cell}"),
            PlacementError::Touching { cell } => {
                write!(f, "ships touch at cell {cell} (no-touch rule)")
            }
        }
    }
}

impl std::error::Error for PlacementError {}

/// A legal fleet under the rules it was validated for. Secret: zeroized on
/// drop, `Debug` redacts.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Fleet {
    ships: [ShipPlacement; K],
}

impl fmt::Debug for Fleet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Fleet(<secret>)")
    }
}

fn ship_cells(ship: &ShipPlacement, length: u8) -> Option<Vec<CellIndex>> {
    (0..length)
        .map(|t| {
            let (row, col) = if ship.vertical {
                (ship.row.checked_add(t)?, ship.col)
            } else {
                (ship.row, ship.col.checked_add(t)?)
            };
            CellIndex::from_row_col(row, col)
        })
        .collect()
}

/// The eight neighbours of a cell that lie on the board.
pub fn neighbours(cell: CellIndex) -> impl Iterator<Item = CellIndex> {
    let (row, col) = (cell.row() as i16, cell.col() as i16);
    (-1i16..=1)
        .flat_map(move |dr| (-1i16..=1).map(move |dc| (dr, dc)))
        .filter(|&(dr, dc)| (dr, dc) != (0, 0))
        .filter_map(move |(dr, dc)| {
            let (r, c) = (row + dr, col + dc);
            if (0..BOARD_N as i16).contains(&r) && (0..BOARD_N as i16).contains(&c) {
                CellIndex::from_row_col(r as u8, c as u8)
            } else {
                None
            }
        })
}

fn sample_below<R: RngCore + CryptoRng>(rng: &mut R, bound: u8) -> u8 {
    debug_assert!(bound > 0);
    let limit = 256u16 - (256u16 % u16::from(bound));
    let mut buf = [0u8; 1];
    loop {
        rng.fill_bytes(&mut buf);
        let v = u16::from(buf[0]);
        if v < limit {
            return (v % u16::from(bound)) as u8;
        }
    }
}

impl Fleet {
    pub fn new(ships: [ShipPlacement; K], rules: Rules) -> Result<Fleet, PlacementError> {
        let fleet = Fleet { ships };
        let mut owner = [None::<usize>; N];
        for (j, &length) in FLEET_LENGTHS.iter().enumerate() {
            let cells = ship_cells(&fleet.ships[j], length)
                .ok_or(PlacementError::OutOfBounds { ship: j })?;
            for cell in cells {
                let slot = &mut owner[cell.index() as usize];
                if slot.is_some() {
                    return Err(PlacementError::Overlap { cell: cell.index() });
                }
                *slot = Some(j);
            }
        }
        if rules == Rules::NoTouch {
            for i in 0..N {
                let Some(j) = owner[i] else { continue };
                let cell = CellIndex::from_index(i as u8).expect("i < N");
                for other in neighbours(cell) {
                    if matches!(owner[other.index() as usize], Some(k) if k != j) {
                        return Err(PlacementError::Touching { cell: cell.index() });
                    }
                }
            }
        }
        Ok(fleet)
    }

    /// Rejection-sampled uniformly over valid per-ship placements until legal.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R, rules: Rules) -> Fleet {
        loop {
            let ships = std::array::from_fn(|j| {
                let vertical = sample_below(rng, 2) == 1;
                let max_start = BOARD_N as u8 - FLEET_LENGTHS[j] + 1;
                let along = sample_below(rng, max_start);
                let across = sample_below(rng, BOARD_N as u8);
                let (row, col) = if vertical {
                    (along, across)
                } else {
                    (across, along)
                };
                ShipPlacement { row, col, vertical }
            });
            if let Ok(fleet) = Fleet::new(ships, rules) {
                return fleet;
            }
        }
    }

    pub fn ships(&self) -> &[ShipPlacement; K] {
        &self.ships
    }

    /// Cells of ship `j`, in increasing order.
    pub fn cells(&self, j: usize) -> Vec<CellIndex> {
        ship_cells(&self.ships[j], FLEET_LENGTHS[j]).expect("validated fleet")
    }

    /// `s`, ship-major: `s[j*N + i] = 1` iff ship `j` covers cell `i`.
    pub fn ship_bits(&self) -> Zeroizing<Vec<u8>> {
        let mut bits = Zeroizing::new(vec![0u8; SHIP_BITS]);
        for j in 0..K {
            for cell in self.cells(j) {
                bits[j * N + cell.index() as usize] = 1;
            }
        }
        bits
    }

    /// Orientation bits `o_j`.
    pub fn orientation_bits(&self) -> [u8; K] {
        std::array::from_fn(|j| u8::from(self.ships[j].vertical))
    }

    /// Board occupancy `b_i`.
    pub fn occupied(&self) -> [bool; N] {
        let mut out = [false; N];
        for j in 0..K {
            for cell in self.cells(j) {
                out[cell.index() as usize] = true;
            }
        }
        out
    }

    /// `row || col || vertical` per ship, 15 bytes; used for test vectors and
    /// to rekey the prover's nonce RNG with the witness.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 3 * K]> {
        let mut out = Zeroizing::new([0u8; 3 * K]);
        for (j, ship) in self.ships.iter().enumerate() {
            out[3 * j] = ship.row;
            out[3 * j + 1] = ship.col;
            out[3 * j + 2] = u8::from(ship.vertical);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8; 3 * K], rules: Rules) -> Result<Fleet, PlacementError> {
        let ships = std::array::from_fn(|j| ShipPlacement {
            row: bytes[3 * j],
            col: bytes[3 * j + 1],
            vertical: bytes[3 * j + 2] != 0,
        });
        Fleet::new(ships, rules)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    pub(crate) fn ship(row: u8, col: u8, vertical: bool) -> ShipPlacement {
        ShipPlacement { row, col, vertical }
    }

    /// Rows 0, 2, 4, 6, 8 from the left; legal under both rule sets.
    pub(crate) fn fleet_a() -> Fleet {
        Fleet::new(
            [
                ship(0, 0, false),
                ship(2, 0, false),
                ship(4, 0, false),
                ship(6, 0, false),
                ship(8, 0, false),
            ],
            Rules::NoTouch,
        )
        .unwrap()
    }

    /// Columns 9, 7, 5, 3 and 1 from the top.
    pub(crate) fn fleet_b() -> Fleet {
        Fleet::new(
            [
                ship(0, 9, true),
                ship(0, 7, true),
                ship(0, 5, true),
                ship(0, 3, true),
                ship(0, 1, true),
            ],
            Rules::NoTouch,
        )
        .unwrap()
    }

    #[test]
    fn encoding_counts() {
        let fleet = fleet_a();
        let bits = fleet.ship_bits();
        assert_eq!(bits.iter().map(|&b| b as usize).sum::<usize>(), 17);
        for j in 0..K {
            let row_sum: u8 = bits[j * N..(j + 1) * N].iter().sum();
            assert_eq!(row_sum, FLEET_LENGTHS[j]);
        }
        assert_eq!(fleet.occupied().iter().filter(|&&b| b).count(), 17);
        assert_eq!(fleet_b().orientation_bits(), [1; K]);
        assert_eq!(
            fleet.cells(0).iter().map(|c| c.index()).collect::<Vec<_>>(),
            [0, 1, 2, 3, 4]
        );
        assert_eq!(
            fleet_b()
                .cells(4)
                .iter()
                .map(|c| c.index())
                .collect::<Vec<_>>(),
            [1, 11]
        );
    }

    #[test]
    fn illegal_fleets_are_rejected() {
        let base = *fleet_a().ships();
        let mut out = base;
        out[0] = ship(0, 6, false);
        assert_eq!(
            Fleet::new(out, Rules::Standard),
            Err(PlacementError::OutOfBounds { ship: 0 })
        );
        let mut out = base;
        out[1] = ship(7, 9, true);
        assert_eq!(
            Fleet::new(out, Rules::Standard),
            Err(PlacementError::OutOfBounds { ship: 1 })
        );
        let mut out = base;
        out[4] = ship(0, 3, true);
        assert_eq!(
            Fleet::new(out, Rules::Standard),
            Err(PlacementError::Overlap { cell: 3 })
        );

        // Adjacent rows: legal in the standard game, touching otherwise.
        let mut out = base;
        out[1] = ship(1, 0, false);
        assert!(Fleet::new(out, Rules::Standard).is_ok());
        assert!(matches!(
            Fleet::new(out, Rules::NoTouch),
            Err(PlacementError::Touching { .. })
        ));
        // Diagonal contact only.
        let mut out = base;
        out[4] = ship(1, 5, false);
        assert!(Fleet::new(out, Rules::Standard).is_ok());
        assert!(matches!(
            Fleet::new(out, Rules::NoTouch),
            Err(PlacementError::Touching { .. })
        ));
    }

    #[test]
    fn neighbour_counts() {
        let count = |r, c| neighbours(CellIndex::from_row_col(r, c).unwrap()).count();
        assert_eq!(count(0, 0), 3);
        assert_eq!(count(0, 5), 5);
        assert_eq!(count(5, 5), 8);
        assert_eq!(count(9, 9), 3);
    }

    #[test]
    fn random_fleets_are_legal_and_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([3; 32]);
        for rules in [Rules::Standard, Rules::NoTouch] {
            let mut saw_vertical = false;
            let mut saw_horizontal = false;
            for _ in 0..50 {
                let fleet = Fleet::random(&mut rng, rules);
                saw_vertical |= fleet.ships().iter().any(|s| s.vertical);
                saw_horizontal |= fleet.ships().iter().any(|s| !s.vertical);
                let again = Fleet::from_bytes(&fleet.to_bytes(), rules).unwrap();
                assert_eq!(again, fleet);
            }
            assert!(saw_vertical && saw_horizontal);
        }
    }
}
