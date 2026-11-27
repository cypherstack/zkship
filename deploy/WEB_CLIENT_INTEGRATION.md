# Web Client & Hosted Relay Integration Guide

This guide documents how browser clients, Web Workers, and operators should integrate `zkb-wasm` and `zkb-relay`.

## 1. Architecture & Browser Pitfalls

1. **Run `zkb-wasm` in a dedicated Web Worker (not the UI thread)**
   - Bulletproofs generator derivation (`BpGens::derive` for 1,024 / 4,096 points) and board setup / range proving take noticeable CPU time in WASM.
   - Call `warmup("standard")` or `warmup("no-touch")` once during worker startup (`LazyLock` caches `Parameters` globally inside the WASM instance) before asking the player to confirm a match.

2. **Secret durability across browser refresh / tab sleep (`export_secret_snapshot`)**
   - A reload wipes WASM memory, losing fleet witnesses (`fleet`, `rho`, `answer_seed`).
   - Save `{ roomId, seatToken }` and the opaque bytes from `client.export_secret_snapshot()` after `accept_peer_hello`, `fire_shot*`, and `accept_frame`.
   - Treat `export_secret_snapshot()` output as secret (it contains your Ed25519 seed, fleet placement, and blinding scalars; avoid uploading it anywhere and clear it from storage as soon as `state.phase` becomes `"finished"` or `"aborted"`).
   - On reload, restore with `ZkShipClient.restore_secret_snapshot(bytes)` and send `attach` with `after_seq: client.state().head_sequence`. Read `attached.head_seq` before processing any following binary replay messages.
   - If `attached.head_seq < client.state().head_sequence`, the snapshot normally contains a locally signed frame that disconnected before its relay acknowledgement. Resend each frame in `client.export_public_transcript().frames.slice(attached.head_seq)` as `0x02 || frame`; the relay accepts exact retries idempotently. Do not feed those frames back into the local engine. A Class-B rejection during this suffix replay means relay state has regressed or the wrong room was attached, so stop recovery.
   - If `attached.head_seq > client.state().head_sequence`, accept the following replay frames normally. If the heads are equal, no frame recovery is needed.

3. **Duplicate tabs, reconnects, and missed frames**
   - `zkb-relay` replaces an older WebSocket for the same `(room_id, seat_token)` with close code `4000` (`replaced_by_new_connection`) and replays peer-authored frames past `after_seq`.
   - Never treat close `4000` with reason `replaced_by_new_connection` as an automatic reconnect loop trigger (another tab/worker took over the seat).
   - Catch-up only includes peer-authored frames past `after_seq`; the relay never echoes your own committed frames back to you. The relay queues the `attached` event, peer Hello, and catch-up prefix atomically ahead of new live frames.

4. **Peer authentication & MITM defense (`zkb-relay` is untrusted)**
   - A compromised or MITM relay can try to substitute public keys during `Hello` exchange.
   - **Preferred (known opponent / invite):** obtain your peer's 64-hex Ed25519 key (`own_public_key()`) over a trusted channel and pass `expected_peer_key_hex` into `new ZkShipClient(rules, ships, seed, expected_peer_key_hex)`. Any key mismatch fails immediately with `error.kind === "peer_auth"`.
   - **Out-of-band (quick-match):** pass `null` for `expected_peer_key_hex`, then ask players to compare the `XXXX-XXXX-XXXX` `safety_code` returned by `accept_peer_hello()` / `state().safety_code` out-of-band.
   - Also pin TLS (`wss://` / `https://`) in production so the relay link itself is encrypted.

5. **Error classes: A vs. B vs. C**
   - **Class A (`error.kind === "attributable"`):** a validly signed, chain-extending frame failed cryptographic verification or game rules. `ZkShipClient` automatically aborts, zeroizes board secrets, and preserves `evidence_frame` + `evidence_frame_hash` in both the error and `state()`. Present `export_public_transcript()` (or call `POST /api/v1/verify-transcript`) for third-party proof.
   - **Class B (`error.kind === "class_b"`):** malformed, replayed, wrong-sequence, or unauthenticated frame. **Not** evidence of peer cheating (anyone on the wire could corrupt packets). Discard and continue waiting cleanly.
   - **Class C (silence / timeout):** indistinguishable from network partition on a two-party transcript. `zkb-relay` reaps abandoned waiting rooms (`ZKB_WAITING_TTL_SECS`), disconnected seats past `ZKB_RECONNECT_GRACE_SECS`, and stalled active turns past `ZKB_TURN_TIMEOUT_SECS` without falsely attributing blame.

6. **A's automatic `CoinReveal` turn**
   - In `zkb-session`, Role A emits `CoinReveal` immediately after accepting Role B's `CoinNonce`. `ZkShipClient::accept_peer_hello` and `ZkShipClient::accept_frame` already drain all due `Session::produce` outputs into `result.outgoing_frames` (`0`..N bytes arrays) so callers just send every buffer in `outgoing_frames` in order as binary `0x02 || frame`.

7. **Browser CORS & WebSocket `Origin` checks**
   - Set `ZKB_ALLOWED_ORIGINS` to your exact frontend origin(s) (comma-separated, e.g. `https://play.example.com`) in production. The relay checks HTTP CORS via `tower-http` AND enforces the `Origin` header on `/ws` upgrades (`403` on mismatch). When `ZKB_ALLOWED_ORIGINS` is restricted (not `*`), non-browser clients without `Origin` are also rejected on `/ws`.

---

## 2. `zkb-wasm` JS API Summary

Top-level helpers:
- `warmup(rules: "standard" | "no-touch") -> params_id_hex`
- `protocol_info() -> { board_n, cells, ship_lengths, total_ship_cells, standard_params_id, no_touch_params_id, hello_len, max_frame_size }`
- `validate_fleet(ships, rules) -> true | throws ClientErrorDto` (`ShipDto`: `{ row: 0..9, col: 0..9, vertical: bool }`)
- `random_fleet(rules) -> ShipDto[]`
- `generate_identity_seed() -> Uint8Array (32 bytes)`
- `identity_public_key(seed: Uint8Array) -> 64-hex string`
- `verify_transcript(hello_a: Uint8Array, hello_b: Uint8Array, frames: Uint8Array[]) -> VerifyReportDto`

Stateful client (`ZkShipClient`):
- `new ZkShipClient(rules, ships, identity_seed?: Uint8Array, expected_peer_key_hex?: string)`
- `client.hello_bytes() -> Uint8Array` (send on `/ws` prefixed with byte `0x01`)
- `client.accept_peer_hello(bytes) -> BootstrapResultDto` (send each frame in `outgoing_frames` prefixed with `0x02`)
- `client.accept_frame(bytes) -> StepResultDto` (send each frame in `outgoing_frames` prefixed with `0x02`)
- `client.fire_shot(row, col)` / `client.fire_shot_index(index) -> StepResultDto`
- `client.resign() -> StepResultDto` (honorable mid-game forfeit)
- `client.abort(reason?) -> ClientStateDto` (zeroizes secrets pre- or mid-game)
- `client.state() -> ClientStateDto` (`phase`: `"awaiting_peer_hello" | "commit" | "coin" | "playing" | "finished" | "aborted"`)
- `client.export_public_transcript() -> { rules, params_id, hello_a, hello_b, sid, genesis_hash, frames, evidence_frame }`
- `client.export_secret_snapshot() -> Uint8Array` / `ZkShipClient.restore_secret_snapshot(bytes) -> ZkShipClient`

All protocol byte buffers (`hello_bytes()`, `outgoing_frames`, `evidence_frame`, `export_public_transcript().{hello_a, hello_b, frames, evidence_frame}`, and `export_secret_snapshot()`) are JS `Uint8Array`s, so `verify_transcript(tr.hello_a, tr.hello_b, tr.frames)` works directly without manual conversion.

All `Result` errors reject/throw structured `ClientErrorDto`: `{ kind, message, evidence_frame?, evidence_frame_hash? }`.

---

## 3. `zkb-relay` HTTP & WebSocket Protocol

### HTTP Endpoints
- `GET /healthz` -> `200 { status: "ok", rooms, quick_match_queued }`
- `GET /api/v1/params` -> protocol constants & profile `params_id`s
- `POST /api/v1/rooms` (`{ "rules"?: "standard" | "no-touch" }`, empty body accepted) -> `201 { room_id, seat_token, seat, rules, params_id }`
- `POST /api/v1/rooms/{room_id}/join` -> `200 { room_id, seat_token, seat, rules, params_id, peer_present }`
- `GET /api/v1/rooms/{room_id}` -> public room metadata & finish verdict
- `GET /api/v1/rooms/{room_id}/transcript` -> public hex `{ room_id, rules, params_id, hello_a, hello_b, sid, genesis_hash, frames }`
- `POST /api/v1/verify-transcript` (`{ hello_one, hello_two, frames }` hex; 1 MiB body limit) -> `VerifyTranscriptResp`

### WebSocket `/ws`
**Text (JSON) Client -> Server messages:**
- `{"type":"create_room","rules":"standard"|"no-touch"}`
- `{"type":"join_room","room_id":"..."}`
- `{"type":"quick_match","rules":"standard"|"no-touch"}`
- `{"type":"attach","room_id":"...","seat_token":"...","after_seq":0}`
- `{"type":"claim_finished"}` (triggers `zkb-session::verify` over the room transcript and broadcasts `room_finished`)
- `{"type":"ping"}`

**Binary Client <-> Server frames:**
- `0x01 || hello_bytes`: submit/deliver peer `Hello` (`Hello::LEN == 162` bytes; also exposed via `protocol_info().hello_len`)
- `0x02 || frame_bytes`: submit/deliver signed protocol `SignedFrame`; relay verifies `sid`, `sequence`, `prev_hash`, and seat Ed25519 signature before forwarding `0x02 || frame_bytes` to peer and replying `{"type":"frame_ack","seq":...,"frame_hash":...}` to sender. (Application/ZK validity stays intentionally client-verified so Class-A cheating frames still reach the victim as signed evidence.)

**Text (JSON) Server -> Client events:**
`room_created`, `room_joined`, `queued`, `matched`, `attached`, `peer_joined`, `peer_hello_accepted`, `bootstrap_ready`, `frame_ack`, `peer_disconnected`, `peer_reconnected`, `room_finished`, `room_closed`, `error`, `pong`.

---

## 4. Environment Configuration & Reverse Proxy Notes

- `ZKB_BIND_ADDR` (default `0.0.0.0:8080`)
- `ZKB_ALLOWED_ORIGINS` (default `*`; set exact origin list in production)
- `ZKB_TRUST_PROXY` (`0` default; set `1` ONLY when running strictly behind Caddy/Nginx)
  - Reads `X-Real-IP` first, otherwise the **rightmost** entry in `X-Forwarded-For` appended by the trusted proxy.
- Limits & TTLs: `ZKB_MAX_ROOMS` (`4096`), `ZKB_MAX_TRANSCRIPT_BYTES` (`134217728`, global stored transcript budget; each room is additionally capped at the 213432-byte v1 protocol maximum), `ZKB_MAX_CONNS_PER_IP` (`32`), `ZKB_ROOM_CREATE_PER_MIN` (`60`), `ZKB_VERIFY_PER_MIN` (`30`), `ZKB_MAX_CONCURRENT_VERIFICATIONS` (`2`, global CPU-heavy verifier jobs), `ZKB_WAITING_TTL_SECS` (`600`), `ZKB_RECONNECT_GRACE_SECS` (`120`), `ZKB_TURN_TIMEOUT_SECS` (`300`), `ZKB_FINISHED_TTL_SECS` (`1800`).

See [../docker-compose.yml](../docker-compose.yml), [../docker-compose.tls.yml](../docker-compose.tls.yml), and [Caddyfile.example](Caddyfile.example) for container deployment.
