# zkship: Zero-Knowledge Battleship implementation (Rust)

Authority: `../docs/zk-battleship.pdf` (source `../docs/zk-battleship.tex`),
the long version of the BBCON 2026 extended abstract
(`../docs/BBCON2026_ZK_Battleship_Extended_Abstract.pdf`).
Wire formats, domain strings, and transcript order are specified by the code
and pinned by `vectors/`.

Not independently audited. Do not use for meaningful stakes.

- `zkb-core/`: parameters (`standard` and `no-touch` profiles), fleets, Bulletproofs (inner-product argument, arbitrary-width range proofs), squaring Σ-protocol, setup proof, shot answers, game state machine. No I/O.
- `zkb-session/`: codec, Ed25519 identity and peer-auth policy hook, Hello/roles/sid, signed frame chain, coin flip, session driver, snapshot persistence, and zero-secret third-party `verify` transcript auditor.
- `zkb-wasm/`: stateful client engine (`ClientEngine`) and `wasm-bindgen` bindings (`ZkShipClient`) for Web Workers, browsers, and Node.js.
- `zkb-relay/`: untrusted HTTP + WebSocket room relay, reconnect catch-up, origin/rate/room limits, and `POST /api/v1/verify-transcript` endpoint.
- `zkb-cli/`: two-process TCP demo (`listen`, `connect`, `--fleet`, `--transcript-out`) and offline transcript auditor (`verify-transcript`).
- `zkb-bench/`: Criterion benchmark suite.
- `fuzz/`: `cargo-fuzz` targets (nightly, outside the workspace).
- `vectors/`: pinned standard & no-touch setup vectors and full-game transcript vector.

```text
cargo build --workspace --locked
cargo test --workspace --release --locked   # debug is minutes; proofs are slow
cargo +nightly fuzz run <target>            # from fuzz/
cargo build -p zkb-core -p zkb-session -p zkb-wasm --target wasm32-unknown-unknown --locked
wasm-pack build zkb-wasm --target web --release
cargo run -p zkb-core --example generate_setup_vector
cargo run -p zkb-core --example generate_notouch_setup_vector
cargo run -p zkb-session --example generate_game_transcript
zkb-cli listen  --addr 127.0.0.1:7878 --name alice [--rules standard|no-touch] [--transcript-out tr.txt]
zkb-cli connect --addr 127.0.0.1:7878 --name bob   [--rules standard|no-touch] [--transcript-out tr.txt]
zkb-cli verify-transcript vectors/game_transcript_v1.txt
docker compose up --build                   # from repo root; see ../deploy/WEB_CLIENT_INTEGRATION.md
```

Rust 1.85+. `ZKB_CLI_AUTO=1` auto-confirms fingerprints and fires scripted shots (test aid only).

Sizes (standard game, Ristretto255): setup 559 points and 50 scalars
(19,488 bytes; 20,544 with the no-touch proof); a miss is one scalar; a hit
is one scalar plus a 416-544-byte range proof; a sink announcement is one
scalar plus one scalar per cell of the sunk ship. Each answer has a 1-byte
tag on the wire, a sink also one index byte for the ship and each cell, and
frames add a 78-byte header and a 64-byte signature.

Not provided: peer authentication (the CLI fingerprint prompt / `ZkShipClient` pinning hook and `safety_code` require out-of-band verification for MITM protection), transport confidentiality (transcripts are public; run WSS/HTTPS in production), attributable timeouts, abort fairness, UC or concurrent security, post-quantum soundness. Commitments and openings are perfectly hiding; the proofs' zero knowledge is computational in practice, since prover nonces come from a Merlin RNG rekeyed with the witness. Besides `G` and `H`, the Bulletproofs vector generators (1,024, or 4,096 with no-touch) are hashed to the group from a fixed domain, so there is still no trusted setup.

Security-relevant changes (need review plus new vectors): G/H and vector
generator derivation, point/scalar decoding, canonical parameter bytes,
Fiat-Shamir fields/order, challenge reduction, proof algebra, RNG rekeying,
secret-side variable-time calls, sid derivation, frame encoding, role/sequence
rules, crypto dependency majors.
