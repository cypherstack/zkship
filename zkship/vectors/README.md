# Interoperability vectors (standard rules)

Format: `key = value` per line, `#` comments, lowercase hex, decimal integers;
multi-byte integers inside protocol encodings are little-endian. Fleets are
15 bytes, `row || col || vertical` per ship in fleet order (5, 4, 3, 3, 2),
the anchor being the top or left cell.

## setup_message_v1.txt

- `profile`, `params_id`; `prover_id`, `sid` (proof context); `fleet`.
- `blinders_rng`, `proof_finalize_rng`: seeded RNGs for the 500 ship-cell blinders and the prover's hedged nonces.
- `setup_len` (19,488), `setup_sha512_256`, `setup_hex`: the setup message.

Regenerate: `cargo run -p zkb-core --example generate_setup_vector` (checks the digest pinned in `setup.rs`).
Conformance: `zkb-session/tests/conformance.rs::setup_message_vector_verifies`.

## setup_message_notouch_v1.txt

- No-touch setup vector (`setup_len` 20,544 bytes).
- Regenerate: `cargo run -p zkb-core --example generate_notouch_setup_vector`.
- Conformance: `zkb-session/tests/conformance.rs::notouch_setup_message_vector_verifies`.

## game_transcript_v1.txt

- `key_seed_role_a/b`, `hello_role_a/b` (162 bytes each); `fleet_role_a/b`.
- `blinders_seed_*`, `proof_finalize_rng_*`, `coin_rng_*`: seeded RNGs. The coin RNG also supplies each player's not-sunk proof seed, drawn right after its Commit.
- `sid`, `genesis_hash`, `first_mover`, `winner`, `winner_hits`, `winner_sunk_total`, `loser_hits`.
- `frame_count`, `frame[0000]`..: every signed frame in chain order (sequence 1..).

Regenerate: `cargo run -p zkb-session --example generate_game_transcript` (byte-for-byte).
Conformance: `zkb-session/tests/conformance.rs::game_transcript_vector_replays_byte_for_byte`.
