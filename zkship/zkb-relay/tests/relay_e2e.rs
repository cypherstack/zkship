use axum::http::{HeaderValue, Request};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as WsMsg;
use zkb_core::game::Role;
use zkb_core::params::Parameters;
use zkb_relay::config::RelayConfig;
use zkb_relay::{build_router, AppState};
use zkb_session::codec::MessageType;
use zkb_session::frame::SignedFrame;
use zkb_session::hello::Hello;
use zkb_session::identity::IdentityKeypair;

async fn spawn_relay(config: RelayConfig) -> SocketAddr {
    let state = AppState::new(config);
    let _reaper = state.rooms.spawn_reaper();
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    addr
}

async fn http_req(addr: SocketAddr, method: &str, path: &str, body: Option<&str>) -> (u16, Value) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let body_bytes = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body_bytes.len(),
        body_bytes
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8(raw).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status: u16 = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let json: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    (status, json)
}

async fn ws_connect(
    addr: SocketAddr,
    origin: Option<&str>,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>> {
    let url = format!("ws://{addr}/ws");
    let mut req: Request<()> = url.into_client_request().unwrap();
    if let Some(o) = origin {
        req.headers_mut()
            .insert("Origin", HeaderValue::from_str(o).unwrap());
    }
    let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    ws
}

async fn recv_text_event(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
) -> Value {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("ws text timeout")
            .expect("ws open")
            .expect("ws ok");
        match msg {
            WsMsg::Text(t) => return serde_json::from_str(&t).unwrap(),
            WsMsg::Ping(_) | WsMsg::Pong(_) => continue,
            other => panic!("expected text event, got {other:?}"),
        }
    }
}

async fn next_ws_msg(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
) -> Result<(Option<Value>, Option<(u8, Vec<u8>)>), &'static str> {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .map_err(|_| "timeout")?
            .ok_or("eof")?
            .map_err(|_| "ws_err")?;
        match msg {
            WsMsg::Text(t) => return Ok((Some(serde_json::from_str(&t).unwrap()), None)),
            WsMsg::Binary(b) => {
                let (&tag, rest) = b.split_first().unwrap();
                return Ok((None, Some((tag, rest.to_vec()))));
            }
            WsMsg::Ping(_) | WsMsg::Pong(_) => continue,
            WsMsg::Close(_) => return Err("closed"),
            _ => continue,
        }
    }
}

fn ships_a() -> Vec<zkb_wasm::engine::ShipDto> {
    use zkb_wasm::engine::ShipDto;
    vec![
        ShipDto {
            row: 0,
            col: 0,
            vertical: false,
        },
        ShipDto {
            row: 2,
            col: 0,
            vertical: false,
        },
        ShipDto {
            row: 4,
            col: 0,
            vertical: false,
        },
        ShipDto {
            row: 6,
            col: 0,
            vertical: false,
        },
        ShipDto {
            row: 8,
            col: 0,
            vertical: false,
        },
    ]
}

fn ships_b() -> Vec<zkb_wasm::engine::ShipDto> {
    use zkb_wasm::engine::ShipDto;
    vec![
        ShipDto {
            row: 0,
            col: 9,
            vertical: true,
        },
        ShipDto {
            row: 0,
            col: 7,
            vertical: true,
        },
        ShipDto {
            row: 0,
            col: 5,
            vertical: true,
        },
        ShipDto {
            row: 0,
            col: 3,
            vertical: true,
        },
        ShipDto {
            row: 0,
            col: 1,
            vertical: true,
        },
    ]
}

#[tokio::test]
async fn full_game_with_reconnect_and_verify_transcript() {
    let addr = spawn_relay(RelayConfig::default()).await;

    let (st, params_json) = http_req(addr, "GET", "/api/v1/params", None).await;
    assert_eq!(st, 200);
    assert_eq!(params_json["board_n"], 10);

    let (st, created) = http_req(
        addr,
        "POST",
        "/api/v1/rooms",
        Some(r#"{"rules":"standard"}"#),
    )
    .await;
    assert_eq!(st, 201);
    let room_id = created["room_id"].as_str().unwrap().to_string();
    let tok0 = created["seat_token"].as_str().unwrap().to_string();

    let (st, joined) = http_req(addr, "POST", &format!("/api/v1/rooms/{room_id}/join"), None).await;
    assert_eq!(st, 200);
    let tok1 = joined["seat_token"].as_str().unwrap().to_string();

    let mut ws0 = ws_connect(addr, None).await;
    let mut ws1 = ws_connect(addr, None).await;

    ws0.send(WsMsg::Text(
        serde_json::json!({"type": "attach", "room_id": room_id, "seat_token": tok0, "after_seq": 0})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    assert_eq!(recv_text_event(&mut ws0).await["type"], "attached");

    ws1.send(WsMsg::Text(
        serde_json::json!({"type": "attach", "room_id": room_id, "seat_token": tok1, "after_seq": 0})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    assert_eq!(recv_text_event(&mut ws1).await["type"], "attached");

    let mut c0 = zkb_wasm::engine::ClientEngine::new("standard", &ships_a(), None, None).unwrap();
    let mut c1 = zkb_wasm::engine::ClientEngine::new("standard", &ships_b(), None, None).unwrap();

    let mut bin0 = vec![0x01];
    bin0.extend_from_slice(&c0.hello_bytes());
    ws0.send(WsMsg::Binary(bin0.into())).await.unwrap();

    let mut bin1 = vec![0x01];
    bin1.extend_from_slice(&c1.hello_bytes());
    ws1.send(WsMsg::Binary(bin1.into())).await.unwrap();

    let mut reconnected = false;
    let mut seq_seen_by_1 = 0u64;

    loop {
        if c0.state().phase == "finished" && c1.state().phase == "finished" {
            break;
        }
        // Pump any shots due if in playing phase.
        for (idx, (client, ws)) in [(&mut c0, &mut ws0), (&mut c1, &mut ws1)]
            .into_iter()
            .enumerate()
        {
            if client.state().can_fire_shot {
                let st = client.state();
                let cell = st
                    .opponent_board
                    .iter()
                    .position(|s| s == "unknown")
                    .unwrap() as u8;
                let step = client.fire_shot_index(cell).unwrap();
                if idx == 1 {
                    seq_seen_by_1 = step.state.head_sequence;
                }
                for f in step.outgoing_frames {
                    let mut msg = vec![0x02];
                    msg.extend_from_slice(&f);
                    ws.send(WsMsg::Binary(msg.into())).await.unwrap();
                }
            }
        }

        // Mid-game forced disconnect & reconnect takeover test once seq_seen_by_1 >= 10.
        if !reconnected && seq_seen_by_1 >= 10 {
            reconnected = true;
            // Open a new ws1 BEFORE closing old ws1 to also test stale-socket replacement!
            let mut new_ws1 = ws_connect(addr, None).await;
            new_ws1
                .send(WsMsg::Text(
                    serde_json::json!({
                        "type": "attach",
                        "room_id": room_id,
                        "seat_token": tok1,
                        "after_seq": seq_seen_by_1
                    })
                    .to_string()
                    .into(),
                ))
                .await
                .unwrap();
            let ev = recv_text_event(&mut new_ws1).await;
            assert_eq!(ev["type"], "attached");
            // Drain replayed peer hello on attach (since attach sends peer_hello if present).
            let mut old_ws1 = std::mem::replace(&mut ws1, new_ws1);
            let _ = old_ws1.close(None).await;
        }

        tokio::select! {
            res = next_ws_msg(&mut ws0) => {
                if let Ok((_ev, Some((tag, payload)))) = res {
                    let outgoing = match tag {
                        0x01 if c0.state().phase == "awaiting_peer_hello" => {
                            c0.accept_peer_hello(&payload).unwrap().outgoing_frames
                        }
                        0x01 => Vec::new(),
                        0x02 => {
                            let step = c0.accept_frame(&payload).unwrap();
                            step.outgoing_frames
                        }
                        _ => unreachable!(),
                    };
                    for f in outgoing {
                        let mut msg = vec![0x02];
                        msg.extend_from_slice(&f);
                        ws0.send(WsMsg::Binary(msg.into())).await.unwrap();
                    }
                }
            }
            res = next_ws_msg(&mut ws1) => {
                if let Ok((_ev, Some((tag, payload)))) = res {
                    let outgoing = match tag {
                        0x01 if c1.state().phase == "awaiting_peer_hello" => {
                            c1.accept_peer_hello(&payload).unwrap().outgoing_frames
                        }
                        0x01 => Vec::new(),
                        0x02 => {
                            let step = c1.accept_frame(&payload).unwrap();
                            seq_seen_by_1 = step.state.head_sequence;
                            step.outgoing_frames
                        }
                        _ => unreachable!(),
                    };
                    for f in outgoing {
                        let mut msg = vec![0x02];
                        msg.extend_from_slice(&f);
                        ws1.send(WsMsg::Binary(msg.into())).await.unwrap();
                    }
                }
            }
        }
    }

    assert!(reconnected);
    assert_eq!(c0.state().winner, c1.state().winner);

    // Fetch public transcript from HTTP and verify via POST /api/v1/verify-transcript.
    let (st, transcript) = http_req(
        addr,
        "GET",
        &format!("/api/v1/rooms/{room_id}/transcript"),
        None,
    )
    .await;
    assert_eq!(st, 200);
    let verify_body = serde_json::json!({
        "hello_one": transcript["hello_a"],
        "hello_two": transcript["hello_b"],
        "frames": transcript["frames"],
    })
    .to_string();
    let (st, verified) = http_req(
        addr,
        "POST",
        "/api/v1/verify-transcript",
        Some(&verify_body),
    )
    .await;
    assert_eq!(st, 200);
    assert_eq!(verified["verdict"], "completed");
    assert_eq!(verified["winner"].as_str(), c0.state().winner.as_deref());
}

#[tokio::test]
async fn quick_match_edge_class_b_and_attributable_class_a_relay() {
    let addr = spawn_relay(RelayConfig::default()).await;
    let mut ws0 = ws_connect(addr, None).await;
    let mut ws1 = ws_connect(addr, None).await;

    ws0.send(WsMsg::Text(
        r#"{"type":"quick_match","rules":"standard"}"#.into(),
    ))
    .await
    .unwrap();
    let ev0 = recv_text_event(&mut ws0).await;
    assert_eq!(ev0["type"], "queued");
    assert_eq!(recv_text_event(&mut ws0).await["type"], "attached");

    ws1.send(WsMsg::Text(
        r#"{"type":"quick_match","rules":"standard"}"#.into(),
    ))
    .await
    .unwrap();
    let ev1 = recv_text_event(&mut ws1).await;
    assert_eq!(ev1["type"], "matched");
    assert_eq!(ev1["room_id"], ev0["room_id"]);
    assert_eq!(recv_text_event(&mut ws1).await["type"], "attached");
    assert_eq!(recv_text_event(&mut ws0).await["type"], "peer_joined");

    let k0 = IdentityKeypair::from_seed(&[0x11; 32]);
    let k1 = IdentityKeypair::from_seed(&[0x22; 32]);
    let params_id = *Parameters::standard().params_id();
    let mut chacha: rand_chacha::ChaCha20Rng = rand::SeedableRng::seed_from_u64(99);
    let h0 = Hello::create(&k0, params_id, &mut chacha);
    let h1 = Hello::create(&k1, params_id, &mut chacha);

    let mut b0 = vec![0x01];
    b0.extend_from_slice(&h0.encode());
    ws0.send(WsMsg::Binary(b0.into())).await.unwrap();
    let mut b1 = vec![0x01];
    b1.extend_from_slice(&h1.encode());
    ws1.send(WsMsg::Binary(b1.into())).await.unwrap();

    let mut sid_hex = String::new();
    let mut gen_hex = String::new();
    let mut role0 = Role::A;
    for _ in 0..8 {
        if let Ok((Some(ev), _)) = next_ws_msg(&mut ws0).await {
            if ev["type"] == "bootstrap_ready" {
                sid_hex = ev["sid"].as_str().unwrap().to_string();
                gen_hex = ev["genesis_hash"].as_str().unwrap().to_string();
                role0 = if ev["your_role"] == "A" {
                    Role::A
                } else {
                    Role::B
                };
                break;
            }
        }
    }
    let sid: [u8; 32] = zkb_relay::room::decode_hex_32(&sid_hex).unwrap();
    let genesis: [u8; 32] = zkb_relay::room::decode_hex_32(&gen_hex).unwrap();

    // 1. Class-B forged signature must be dropped by relay and NOT forwarded.
    let stranger = IdentityKeypair::from_seed(&[0x99; 32]);
    let forged = SignedFrame::craft(
        &stranger,
        &sid,
        role0,
        1,
        MessageType::Shot,
        &genesis,
        vec![0],
    );
    let mut msg = vec![0x02];
    msg.extend_from_slice(forged.bytes());
    ws0.send(WsMsg::Binary(msg.into())).await.unwrap();
    let err_ev = recv_text_event(&mut ws0).await;
    assert_eq!(err_ev["type"], "error");
    assert_eq!(err_ev["code"], "class_b");

    // 2. Class-A validly signed cheating frame (Shot at seq 1!) MUST be relayed as evidence!
    let cheater_shot =
        SignedFrame::craft(&k0, &sid, role0, 1, MessageType::Shot, &genesis, vec![0]);
    let mut msg = vec![0x02];
    msg.extend_from_slice(cheater_shot.bytes());
    ws0.send(WsMsg::Binary(msg.into())).await.unwrap();
    let ack = recv_text_event(&mut ws0).await;
    assert_eq!(ack["type"], "frame_ack");

    // Peer (ws1) must receive the relayed 0x02 frame.
    let mut got_frame = false;
    for _ in 0..6 {
        if let Ok((_, Some((0x02, bytes)))) = next_ws_msg(&mut ws1).await {
            assert_eq!(bytes, cheater_shot.bytes());
            got_frame = true;
            break;
        }
    }
    assert!(got_frame);

    // 3. Conflicting frame at already-committed seq 1 must be rejected!
    let equiv = SignedFrame::craft(&k0, &sid, role0, 1, MessageType::Resign, &genesis, vec![]);
    let mut msg = vec![0x02];
    msg.extend_from_slice(equiv.bytes());
    ws0.send(WsMsg::Binary(msg.into())).await.unwrap();
    let err_ev = recv_text_event(&mut ws0).await;
    assert_eq!(err_ev["type"], "error");
    assert_eq!(err_ev["code"], "bad_request");

    // 4. Transcript verification reports attributable violation by seat 0's role.
    let room_id = ev0["room_id"].as_str().unwrap();
    let (st, tr) = http_req(
        addr,
        "GET",
        &format!("/api/v1/rooms/{room_id}/transcript"),
        None,
    )
    .await;
    assert_eq!(st, 200);
    let body = serde_json::json!({
        "hello_one": tr["hello_a"],
        "hello_two": tr["hello_b"],
        "frames": tr["frames"],
    })
    .to_string();
    let (st, ver) = http_req(addr, "POST", "/api/v1/verify-transcript", Some(&body)).await;
    assert_eq!(st, 200);
    assert_eq!(ver["verdict"], "attributable_violation");
    assert_eq!(ver["guilty"], if role0 == Role::A { "A" } else { "B" });
}

#[tokio::test]
async fn origin_check_and_limits_are_enforced() {
    let cfg = RelayConfig {
        allowed_origins: vec!["https://play.zkship.example".to_string()],
        max_rooms: 1,
        verify_per_min: 1,
        ..Default::default()
    };
    let addr = spawn_relay(cfg).await;

    // Disallowed origin gets 403 on WS upgrade.
    let url = format!("ws://{addr}/ws");
    let mut req: Request<()> = url.into_client_request().unwrap();
    req.headers_mut()
        .insert("Origin", HeaderValue::from_static("https://evil.example"));
    let err = tokio_tungstenite::connect_async(req).await.unwrap_err();
    let err_str = err.to_string();
    assert!(err_str.contains("403"), "expected 403, got {err_str}");

    // Room capacity limit enforced.
    let (st, _) = http_req(addr, "POST", "/api/v1/rooms", None).await;
    assert_eq!(st, 201);
    let (st, _) = http_req(addr, "POST", "/api/v1/rooms", None).await;
    assert_eq!(st, 503);

    // Rate limit on verify-transcript enforced.
    let bad = r#"{"hello_one":"00","hello_two":"00","frames":[]}"#;
    let (st1, _) = http_req(addr, "POST", "/api/v1/verify-transcript", Some(bad)).await;
    assert_eq!(st1, 400);
    let (st2, _) = http_req(addr, "POST", "/api/v1/verify-transcript", Some(bad)).await;
    assert_eq!(st2, 429);
}
