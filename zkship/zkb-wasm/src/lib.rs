//! WebAssembly / JS bindings over [`engine::ClientEngine`]. Zero DOM/window
//! assumptions, so the module runs identically on main thread, Web Workers, and Node.

#![forbid(unsafe_code)]

pub mod engine;

use engine::{ClientEngine, ClientErrorDto, ShipDto};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;
use zkb_core::fleet::Fleet;
use zkb_session::identity::IdentityKeypair;

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(|e| {
        let err = ClientErrorDto {
            kind: "internal".to_string(),
            message: format!("serialize error: {e}"),
            evidence_frame: None,
            evidence_frame_hash: None,
        };
        serde_wasm_bindgen::to_value(&err).unwrap_or(JsValue::from_str(&err.message))
    })
}

fn err_to_js(err: ClientErrorDto) -> JsValue {
    serde_wasm_bindgen::to_value(&err).unwrap_or_else(|_| JsValue::from_str(&err.message))
}

fn decode_frames_arg(frames_js: JsValue) -> Result<Vec<Vec<u8>>, JsValue> {
    let arr: js_sys::Array = frames_js.dyn_into().map_err(|_| {
        err_to_js(ClientErrorDto {
            kind: "invalid_input".to_string(),
            message: "frames must be an Array of Uint8Array".to_string(),
            evidence_frame: None,
            evidence_frame_hash: None,
        })
    })?;
    let mut frames = Vec::with_capacity(arr.length() as usize);
    for val in arr.iter() {
        let u8arr: js_sys::Uint8Array = val.dyn_into().map_err(|_| {
            err_to_js(ClientErrorDto {
                kind: "invalid_input".to_string(),
                message: "each frame must be a Uint8Array".to_string(),
                evidence_frame: None,
                evidence_frame_hash: None,
            })
        })?;
        frames.push(u8arr.to_vec());
    }
    Ok(frames)
}

#[wasm_bindgen]
pub fn warmup(rules: &str) -> Result<String, JsValue> {
    engine::warmup(rules).map_err(err_to_js)
}

#[wasm_bindgen]
pub fn protocol_info() -> Result<JsValue, JsValue> {
    to_js(&engine::protocol_info())
}

#[wasm_bindgen]
pub fn validate_fleet(ships: JsValue, rules: &str) -> Result<bool, JsValue> {
    let rules = engine::parse_rules(rules).map_err(err_to_js)?;
    let ships: Vec<ShipDto> = serde_wasm_bindgen::from_value(ships).map_err(|e| {
        err_to_js(ClientErrorDto {
            kind: "invalid_input".to_string(),
            message: format!("invalid ships array: {e}"),
            evidence_frame: None,
            evidence_frame_hash: None,
        })
    })?;
    match engine::parse_fleet(&ships, rules) {
        Ok(_) => Ok(true),
        Err(e) => Err(err_to_js(e)),
    }
}

#[wasm_bindgen]
pub fn random_fleet(rules: &str) -> Result<JsValue, JsValue> {
    let rules = engine::parse_rules(rules).map_err(err_to_js)?;
    let fleet = Fleet::random(&mut OsRng, rules);
    to_js(&engine::fleet_to_dtos(&fleet))
}

#[wasm_bindgen]
pub fn generate_identity_seed() -> Vec<u8> {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(seed.as_mut());
    seed.to_vec()
}

#[wasm_bindgen]
pub fn identity_public_key(seed: &[u8]) -> Result<String, JsValue> {
    if seed.len() != 32 {
        return Err(err_to_js(ClientErrorDto {
            kind: "invalid_input".to_string(),
            message: format!("identity seed must be 32 bytes, got {}", seed.len()),
            evidence_frame: None,
            evidence_frame_hash: None,
        }));
    }
    let mut wrapped = Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(seed);
    Ok(IdentityKeypair::from_seed(&wrapped)
        .peer_key()
        .fingerprint_hex())
}

#[wasm_bindgen]
pub fn verify_transcript(
    hello_a: &[u8],
    hello_b: &[u8],
    frames: JsValue,
) -> Result<JsValue, JsValue> {
    let frames = decode_frames_arg(frames)?;
    let report = engine::verify_transcript_dto(hello_a, hello_b, &frames).map_err(err_to_js)?;
    to_js(&report)
}

#[wasm_bindgen]
pub struct ZkShipClient {
    inner: ClientEngine,
}

#[wasm_bindgen]
impl ZkShipClient {
    #[wasm_bindgen(constructor)]
    pub fn new(
        rules: &str,
        ships: JsValue,
        identity_seed: Option<Vec<u8>>,
        expected_peer_key_hex: Option<String>,
    ) -> Result<ZkShipClient, JsValue> {
        let ships: Vec<ShipDto> = serde_wasm_bindgen::from_value(ships).map_err(|e| {
            err_to_js(ClientErrorDto {
                kind: "invalid_input".to_string(),
                message: format!("invalid ships array: {e}"),
                evidence_frame: None,
                evidence_frame_hash: None,
            })
        })?;
        let seed_wrap = identity_seed.map(Zeroizing::new);
        let engine = ClientEngine::new(
            rules,
            &ships,
            seed_wrap.as_deref().map(Vec::as_slice),
            expected_peer_key_hex.as_deref(),
        )
        .map_err(err_to_js)?;
        Ok(ZkShipClient { inner: engine })
    }

    pub fn hello_bytes(&self) -> Vec<u8> {
        self.inner.hello_bytes()
    }

    pub fn own_public_key(&self) -> String {
        self.inner.own_public_key_hex()
    }

    pub fn own_fingerprint(&self) -> String {
        self.inner.own_fingerprint()
    }

    pub fn accept_peer_hello(&mut self, bytes: &[u8]) -> Result<JsValue, JsValue> {
        let out = self.inner.accept_peer_hello(bytes).map_err(err_to_js)?;
        to_js(&out)
    }

    pub fn accept_frame(&mut self, bytes: &[u8]) -> Result<JsValue, JsValue> {
        let out = self.inner.accept_frame(bytes).map_err(err_to_js)?;
        to_js(&out)
    }

    pub fn fire_shot(&mut self, row: u8, col: u8) -> Result<JsValue, JsValue> {
        let out = self.inner.fire_shot(row, col).map_err(err_to_js)?;
        to_js(&out)
    }

    pub fn fire_shot_index(&mut self, index: u8) -> Result<JsValue, JsValue> {
        let out = self.inner.fire_shot_index(index).map_err(err_to_js)?;
        to_js(&out)
    }

    pub fn resign(&mut self) -> Result<JsValue, JsValue> {
        let out = self.inner.resign().map_err(err_to_js)?;
        to_js(&out)
    }

    pub fn abort(&mut self, reason: Option<String>) -> Result<JsValue, JsValue> {
        let st = self.inner.abort(reason.as_deref());
        to_js(&st)
    }

    pub fn state(&self) -> Result<JsValue, JsValue> {
        to_js(&self.inner.state())
    }

    pub fn export_public_transcript(&self) -> Result<JsValue, JsValue> {
        to_js(&self.inner.export_public_transcript())
    }

    pub fn export_secret_snapshot(&self) -> Result<Vec<u8>, JsValue> {
        self.inner
            .export_secret_snapshot()
            .map(|z| z.to_vec())
            .map_err(err_to_js)
    }

    pub fn restore_secret_snapshot(snapshot: &[u8]) -> Result<ZkShipClient, JsValue> {
        let engine = ClientEngine::restore_secret_snapshot(snapshot).map_err(err_to_js)?;
        Ok(ZkShipClient { inner: engine })
    }
}
