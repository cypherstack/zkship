//! Two-process TCP demo and offline transcript verifier. Transport (length-prefixed frames)
//! lives here, outside the crypto/game core. The transcript is public by design; use an
//! encrypted transport if confidentiality matters.
//!
//! ```text
//! zkb-cli listen  --addr 127.0.0.1:PORT [--name NAME] [--key-file PATH] [--rules RULES] [--fleet HEX] [--transcript-out PATH]
//! zkb-cli connect --addr 127.0.0.1:PORT [--name NAME] [--key-file PATH] [--rules RULES] [--fleet HEX] [--transcript-out PATH]
//! zkb-cli verify-transcript PATH
//! ```
//!
//! The fingerprint prompt is the application peer-auth hook; it is not MITM
//! protection unless the fingerprint is compared out of band.
//! `RULES` is `standard` (default) or `no-touch`; both peers must agree, which the
//! Hello exchange checks through `params_id`.
//! `ZKB_CLI_AUTO=1` is a scripted test mode (auto-confirm, deterministic shots).

#![forbid(unsafe_code)]

use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use std::env;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;
use zeroize::Zeroizing;
use zkb_core::fleet::{Fleet, SHIP_BITS};
use zkb_core::game::Role;
use zkb_core::game::ShotOutcome;
use zkb_core::params::{CellIndex, Parameters, Rules, FLEET_LENGTHS, K, N, T};
use zkb_session::codec::MAX_FRAME_SIZE;
use zkb_session::frame::{self, SignedFrame};
use zkb_session::hello::{self, Hello};
use zkb_session::identity::{
    AuthenticatedPeer, ExpectedKey, IdentityKeypair, PeerAuthPolicy, PeerKey,
};
use zkb_session::state::{AcceptOutcome, Session, SessionError};
use zkb_session::verify::{self, TranscriptVerdict};

const AUTO_ENV: &str = "ZKB_CLI_AUTO";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

enum CliAction {
    Play(Options),
    VerifyTranscript(String),
}

struct Options {
    listen: bool,
    addr: String,
    name: String,
    key_file: Option<String>,
    rules: Rules,
    fleet: Option<Zeroizing<[u8; 3 * K]>>,
    transcript_out: Option<String>,
    auto: bool,
}

fn parse_action(args: &[String]) -> Result<CliAction, String> {
    let auto = env::var(AUTO_ENV).ok().as_deref() == Some("1");
    let mut iter = args.iter();
    let Some(command) = iter.next() else {
        return Err(usage());
    };
    if command == "verify-transcript" {
        let Some(path) = iter.next() else {
            return Err(usage());
        };
        if iter.next().is_some() {
            return Err(usage());
        }
        return Ok(CliAction::VerifyTranscript(path.clone()));
    }
    let listen = match command.as_str() {
        "listen" => true,
        "connect" => false,
        _ => return Err(usage()),
    };
    let mut addr = None;
    let mut name = None;
    let mut key_file = None;
    let mut rules = Rules::Standard;
    let mut fleet_hex = None;
    let mut fleet_file = None;
    let mut transcript_out = None;
    while let Some(flag) = iter.next() {
        let Some(value) = iter.next() else {
            return Err(usage());
        };
        match flag.as_str() {
            "--addr" => addr = Some(value.clone()),
            "--name" => name = Some(value.clone()),
            "--key-file" => key_file = Some(value.clone()),
            "--rules" => {
                rules = match value.as_str() {
                    "standard" => Rules::Standard,
                    "no-touch" => Rules::NoTouch,
                    _ => return Err(usage()),
                }
            }
            "--fleet" => fleet_hex = Some(value.clone()),
            "--fleet-file" => fleet_file = Some(value.clone()),
            "--transcript-out" => transcript_out = Some(value.clone()),
            _ => return Err(usage()),
        }
    }
    if fleet_hex.is_some() && fleet_file.is_some() {
        return Err("use only one of --fleet or --fleet-file".to_string());
    }
    let fleet = match (fleet_hex, fleet_file) {
        (Some(raw), None) => {
            eprintln!(
                "warning: --fleet exposes the secret placement via argv; prefer --fleet-file"
            );
            Some(parse_fleet_hex(&raw, rules)?)
        }
        (None, Some(path)) => Some(parse_fleet_file(&path, rules)?),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("checked above"),
    };
    Ok(CliAction::Play(Options {
        listen,
        addr: addr.ok_or_else(usage)?,
        name: name.unwrap_or_else(|| "player".to_string()),
        key_file,
        rules,
        fleet,
        transcript_out,
        auto,
    }))
}

fn usage() -> String {
    "usage:\n  \
     zkb-cli <listen|connect> --addr HOST:PORT [--name NAME] [--key-file PATH] \
     [--rules standard|no-touch] [--fleet-file PATH] [--transcript-out PATH]\n  \
     zkb-cli verify-transcript PATH"
        .to_string()
}

fn run(args: &[String]) -> Result<(), String> {
    let options = match parse_action(args)? {
        CliAction::VerifyTranscript(path) => return verify_transcript_file(&path),
        CliAction::Play(opts) => opts,
    };
    let params = Parameters::for_rules(options.rules);
    let keypair = load_or_create_identity(options.key_file.as_deref())?;
    println!(
        "[{}] identity fingerprint: {}",
        options.name,
        fingerprint(keypair.peer_key().as_bytes())
    );

    let mut stream = if options.listen {
        let listener = TcpListener::bind(&options.addr).map_err(|e| format!("bind: {e}"))?;
        println!("[{}] listening on {} ...", options.name, options.addr);
        let (stream, peer_addr) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        println!("[{}] peer connected from {peer_addr}", options.name);
        stream
    } else {
        TcpStream::connect(&options.addr).map_err(|e| format!("connect: {e}"))?
    };
    let _ = stream.set_nodelay(true);

    let mut demo = Demo::new(params, &keypair, &options);
    let outcome = (|| -> Result<(), String> {
        demo.bootstrap(&mut stream)?;
        let Some(first_mover) = demo.commit_and_coin(&mut stream)? else {
            return Ok(());
        };
        demo.play(&mut stream, first_mover)
    })();

    if let Some(path) = options.transcript_out.as_deref() {
        if let Err(e) = demo.write_public_transcript(path) {
            eprintln!("warning: failed to write transcript {path}: {e}");
        }
    }
    outcome
}

/// Application auth hook: interactive fingerprint confirmation (auto in scripted mode).
struct ConfirmPolicy {
    auto: bool,
}

impl PeerAuthPolicy for ConfirmPolicy {
    fn authenticate(&self, announced: &PeerKey) -> Option<AuthenticatedPeer> {
        let mark = fingerprint(announced.as_bytes());
        if self.auto {
            println!("[auto] peer fingerprint {mark} auto-confirmed (demo mode)");
            return Some(AuthenticatedPeer::from_policy_decision(*announced));
        }
        println!("peer identity fingerprint: {mark}");
        println!("compare it with your peer out of band, then confirm.");
        let confirmed = prompt_line("confirm peer identity? [y/N] ")
            .is_some_and(|s| matches!(s.trim().to_ascii_lowercase().as_str(), "y" | "yes"));
        if confirmed {
            Some(AuthenticatedPeer::from_policy_decision(*announced))
        } else {
            None
        }
    }
}

struct Demo<'a> {
    params: &'a Parameters,
    keypair: &'a IdentityKeypair,
    name: String,
    auto: bool,
    fleet_bytes: Option<Zeroizing<[u8; 3 * K]>>,
    session: Option<Session<'a>>,
    hello_pair: Option<(Vec<u8>, Vec<u8>)>,
    evidence_frame: Option<Vec<u8>>,
    placement: Zeroizing<Vec<bool>>,
    shots_against: Vec<bool>,
    // None = unshot, Some(false) = miss, Some(true) = hit.
    tracking: Vec<Option<bool>>,
}

impl<'a> Demo<'a> {
    fn new(params: &'a Parameters, keypair: &'a IdentityKeypair, options: &Options) -> Demo<'a> {
        Demo {
            params,
            keypair,
            name: options.name.clone(),
            auto: options.auto,
            fleet_bytes: options.fleet.clone(),
            session: None,
            hello_pair: None,
            evidence_frame: None,
            placement: Zeroizing::new(vec![false; N]),
            shots_against: vec![false; N],
            tracking: vec![None; N],
        }
    }

    fn session(&mut self) -> &mut Session<'a> {
        self.session
            .as_mut()
            .expect("session exists after bootstrap")
    }

    fn bootstrap(&mut self, stream: &mut TcpStream) -> Result<(), String> {
        let params_id = *self.params.params_id();
        let hello = Hello::create(self.keypair, params_id, &mut OsRng);
        let own_hello_bytes = hello.encode();
        send_bytes(stream, &own_hello_bytes)?;
        let peer_bytes = recv_bytes(stream, Hello::LEN)?;
        let peer_hello = Hello::decode(&peer_bytes).map_err(|e| format!("peer hello: {e}"))?;

        let policy = ConfirmPolicy { auto: self.auto };
        let checked_peer = hello::check_hello(peer_hello, &params_id, &policy)
            .map_err(|e| format!("peer hello rejected: {e}"))?;
        let peer = *checked_peer.authenticated_peer();
        let checked_own = hello::check_hello(
            hello,
            &params_id,
            &ExpectedKey::new(self.keypair.peer_key()),
        )
        .map_err(|e| format!("own hello: {e}"))?;
        let bootstrap = hello::complete_bootstrap(checked_own, checked_peer)
            .map_err(|e| format!("bootstrap: {e}"))?;
        let local_role = bootstrap.role_of(&self.keypair.peer_key());
        self.hello_pair = Some(match local_role {
            Role::A => (own_hello_bytes, peer_bytes),
            Role::B => (peer_bytes, own_hello_bytes),
        });

        let fleet = match self.fleet_bytes.take() {
            Some(bytes) => {
                Fleet::from_bytes(&bytes, self.params.rules()).map_err(|e| format!("fleet: {e}"))?
            }
            None => Fleet::random(&mut OsRng, self.params.rules()),
        };
        self.placement = Zeroizing::new(fleet.occupied().to_vec());
        let blinders: Vec<Scalar> = (0..SHIP_BITS).map(|_| Scalar::random(&mut OsRng)).collect();
        let session = Session::new(
            self.params,
            self.keypair,
            local_role,
            peer,
            *bootstrap.sid(),
            *bootstrap.genesis_hash(),
            fleet,
            blinders,
        )
        .map_err(|e| format!("session: {e}"))?;
        println!(
            "[{}] session established; role {local_role:?}; sid {}",
            self.name,
            fingerprint(session.sid())
        );
        self.session = Some(session);
        Ok(())
    }

    fn commit_and_coin(&mut self, stream: &mut TcpStream) -> Result<Option<Role>, String> {
        println!(
            "[{}] committing board and proving legality (this takes a moment)...",
            self.name
        );
        loop {
            while let Some(frame) = self
                .session()
                .produce(&mut OsRng)
                .map_err(|e| format!("produce: {e}"))?
            {
                send_frame(stream, &frame)?;
            }
            let bytes = recv_frame(stream)?;
            match self.accept(&bytes)? {
                Some(AcceptOutcome::GameReady { first_mover }) => {
                    // A still owes CoinReveal after GameReady.
                    while let Some(frame) = self
                        .session()
                        .produce(&mut OsRng)
                        .map_err(|e| format!("produce: {e}"))?
                    {
                        send_frame(stream, &frame)?;
                    }
                    println!(
                        "[{}] coin flip resolved: {first_mover:?} shoots first",
                        self.name
                    );
                    return Ok(Some(first_mover));
                }
                Some(AcceptOutcome::PeerResigned) => {
                    println!("*** GAME OVER: peer resigned; you win by forfeit ***");
                    return Ok(None);
                }
                Some(AcceptOutcome::CommitVerified) => {
                    println!("[{}] peer board verified", self.name);
                }
                _ => {}
            }
        }
    }

    fn play(&mut self, stream: &mut TcpStream, first_mover: Role) -> Result<(), String> {
        let mut current = first_mover;
        self.render();
        loop {
            if current == self.session().local_role() {
                match self.read_command()? {
                    Command::Fire(cell) => {
                        let frame = self
                            .session()
                            .fire_shot(cell)
                            .map_err(|e| format!("fire: {e}"))?;
                        send_frame(stream, &frame)?;
                        let bytes = recv_frame(stream)?;
                        match self.accept(&bytes)? {
                            Some(AcceptOutcome::Answer(outcome)) => {
                                self.record_answer(cell, outcome);
                                self.render();
                            }
                            Some(AcceptOutcome::GameFinished { winner }) => {
                                self.record_answer(cell, ShotOutcome::Win);
                                self.render();
                                println!("*** GAME OVER: {winner:?} wins (all {T} cells hit) ***");
                                return Ok(());
                            }
                            Some(AcceptOutcome::PeerResigned) => {
                                println!("*** GAME OVER: peer resigned; you win by forfeit ***");
                                return Ok(());
                            }
                            other => return Err(format!("unexpected outcome {other:?}")),
                        }
                    }
                    Command::Resign => {
                        let frame = self
                            .session()
                            .resign()
                            .map_err(|e| format!("resign: {e}"))?;
                        send_frame(stream, &frame)?;
                        println!("[{}] you resigned; peer wins by forfeit", self.name);
                        return Ok(());
                    }
                    Command::Quit => {
                        self.session().abort();
                        println!(
                            "[{}] quitting mid-session: this is class-C disconnection, \
                             not attributable evidence",
                            self.name
                        );
                        return Ok(());
                    }
                }
            } else {
                println!("[{}] waiting for peer's shot...", self.name);
                let bytes = recv_frame(stream)?;
                match self.accept(&bytes)? {
                    Some(AcceptOutcome::ShotReceived {
                        cell,
                        hit,
                        answer,
                        winner,
                    }) => {
                        send_frame(stream, &answer)?;
                        self.shots_against[cell.index() as usize] = true;
                        println!(
                            "[{}] peer fired at {}: {}",
                            self.name,
                            cell_name(cell),
                            if hit { "hit" } else { "miss" }
                        );
                        self.render();
                        if let Some(winner) = winner {
                            println!(
                                "*** GAME OVER: {winner:?} wins (your fleet is fully sunk) ***"
                            );
                            return Ok(());
                        }
                    }
                    Some(AcceptOutcome::PeerResigned) => {
                        println!("*** GAME OVER: peer resigned; you win by forfeit ***");
                        return Ok(());
                    }
                    other => return Err(format!("unexpected outcome {other:?}")),
                }
            }
            current = current.other();
        }
    }

    fn accept(&mut self, bytes: &[u8]) -> Result<Option<AcceptOutcome>, String> {
        match self.session().accept(bytes) {
            Ok(outcome) => Ok(Some(outcome)),
            Err(SessionError::ClassB(reason)) => Err(format!(
                "class-B input (non-extending/replayed/unauthenticated/corrupt; \
                 not evidence of peer cheating): {reason}"
            )),
            Err(SessionError::Attributable(violation)) => {
                self.evidence_frame = Some(violation.frame.bytes().to_vec());
                Err(format!(
                    "ATTRIBUTABLE peer violation: {}; evidence frame hash {}",
                    violation.violation,
                    hex(&frame::frame_hash(violation.frame.bytes()))
                ))
            }
            Err(SessionError::InternalInvariant(what)) => {
                Err(format!("class-D internal invariant failure: {what}"))
            }
            Err(e) => Err(format!("session error: {e}")),
        }
    }

    fn write_public_transcript(&self, path: &str) -> Result<(), String> {
        let Some((hello_a, hello_b)) = &self.hello_pair else {
            return Ok(());
        };
        let Some(session) = &self.session else {
            return Ok(());
        };
        let mut out = String::new();
        let rules_str = match self.params.rules() {
            Rules::Standard => "standard",
            Rules::NoTouch => "no-touch",
        };
        out.push_str("# zkbattleship public transcript\n");
        out.push_str(&format!("rules = {rules_str}\n"));
        out.push_str(&format!("params_id = {}\n", hex(self.params.params_id())));
        out.push_str(&format!("hello_a = {}\n", hex(hello_a)));
        out.push_str(&format!("hello_b = {}\n", hex(hello_b)));
        out.push_str(&format!("sid = {}\n", hex(session.sid())));
        out.push_str(&format!("genesis_hash = {}\n", hex(session.genesis_hash())));
        for (i, frame) in session.transcript().iter().enumerate() {
            out.push_str(&format!("frame[{i:04}] = {}\n", hex(frame)));
        }
        if let Some(evidence) = &self.evidence_frame {
            out.push_str(&format!("evidence_frame = {}\n", hex(evidence)));
        }
        std::fs::write(path, out).map_err(|e| format!("write {path}: {e}"))?;
        println!("[{}] wrote public transcript to {path}", self.name);
        Ok(())
    }

    fn record_answer(&mut self, cell: CellIndex, outcome: ShotOutcome) {
        match outcome {
            ShotOutcome::Miss => {
                self.tracking[cell.index() as usize] = Some(false);
                println!("[{}] miss", self.name);
            }
            ShotOutcome::Hit => {
                self.tracking[cell.index() as usize] = Some(true);
                println!("[{}] hit!", self.name);
            }
            ShotOutcome::Sunk { ship } => {
                self.tracking[cell.index() as usize] = Some(true);
                println!(
                    "[{}] hit! ship {ship} (length {}) sunk",
                    self.name, FLEET_LENGTHS[ship as usize]
                );
            }
            ShotOutcome::Win => {
                self.tracking[cell.index() as usize] = Some(true);
                println!("[{}] hit! last ship sunk", self.name);
            }
        }
    }

    fn render(&self) {
        println!("--- your fleet (X = hit, o = miss against you) ---");
        print_grid(|i| {
            let shot = self.shots_against[i];
            match (self.placement[i], shot) {
                (true, true) => 'X',
                (true, false) => 'S',
                (false, true) => 'o',
                (false, false) => '~',
            }
        });
        println!("--- your shots (X = hit, o = miss) ---");
        let tracking = &self.tracking;
        print_grid(|i| match tracking[i] {
            Some(true) => 'X',
            Some(false) => 'o',
            None => '.',
        });
    }

    fn read_command(&self) -> Result<Command, String> {
        loop {
            if self.auto {
                let session = self.session.as_ref().expect("session");
                let game = session.game().expect("game");
                let peer = session.local_role().other();
                let cell = (0..N as u8)
                    .map(|i| CellIndex::from_index(i).unwrap())
                    .find(|c| !game.shots_on_board(peer).is_shot(*c))
                    .expect("unshot cells remain");
                println!("[auto] firing at {}", cell_name(cell));
                return Ok(Command::Fire(cell));
            }
            let Some(line) = prompt_line("your shot (e.g. B5), 'resign', or 'quit': ") else {
                return Ok(Command::Quit);
            };
            match line.as_str() {
                "resign" => return Ok(Command::Resign),
                "quit" => return Ok(Command::Quit),
                _ => match parse_cell(&line) {
                    Some(cell) => {
                        let session = self.session.as_ref().expect("session");
                        let game = session.game().expect("game");
                        let peer = session.local_role().other();
                        if game.shots_on_board(peer).is_shot(cell) {
                            println!("cell {} was already shot; pick another", cell_name(cell));
                        } else {
                            return Ok(Command::Fire(cell));
                        }
                    }
                    None => println!("invalid cell; use a letter A-J and a column 0-9, e.g. B5"),
                },
            }
        }
    }
}

enum Command {
    Fire(CellIndex),
    Resign,
    Quit,
}

/// u32 LE length prefix, then frame bytes; MAX_FRAME_SIZE enforced before allocating.
fn send_bytes(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), String> {
    let len = u32::try_from(bytes.len()).map_err(|_| "frame too large".to_string())?;
    stream
        .write_all(&len.to_le_bytes())
        .and_then(|()| stream.write_all(bytes))
        .map_err(|e| format!("send: {e}"))
}

fn send_frame(stream: &mut TcpStream, frame: &SignedFrame) -> Result<(), String> {
    send_bytes(stream, frame.bytes())
}

fn recv_bytes(stream: &mut TcpStream, max: usize) -> Result<Vec<u8>, String> {
    let mut len_bytes = [0u8; 4];
    stream
        .read_exact(&mut len_bytes)
        .map_err(|e| format!("receive length: {e}"))?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > max {
        return Err(format!(
            "peer announced {len} bytes, over the {max}-byte bound"
        ));
    }
    let mut bytes = vec![0u8; len];
    stream
        .read_exact(&mut bytes)
        .map_err(|e| format!("receive body: {e}"))?;
    Ok(bytes)
}

fn recv_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    recv_bytes(stream, MAX_FRAME_SIZE)
}

fn load_or_create_identity(key_file: Option<&str>) -> Result<IdentityKeypair, String> {
    let Some(path) = key_file else {
        return Ok(IdentityKeypair::generate(&mut OsRng));
    };
    match std::fs::File::open(path) {
        Ok(mut file) => {
            // Bounded read: 32-byte seed plus one trailing byte.
            let mut seed = Zeroizing::new([0u8; 32]);
            file.read_exact(seed.as_mut())
                .map_err(|e| format!("read key file {path} (expected 32-byte seed): {e}"))?;
            let mut trailing = Zeroizing::new([0u8; 1]);
            if file
                .read(trailing.as_mut())
                .map_err(|e| format!("read key file: {e}"))?
                != 0
            {
                return Err(format!("key file {path} must contain a raw 32-byte seed"));
            }
            Ok(IdentityKeypair::from_seed(&seed))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let mut seed = Zeroizing::new([0u8; 32]);
            rand_core::RngCore::fill_bytes(&mut OsRng, seed.as_mut());
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            // Create only on NotFound, exclusively (also rejects a racing creator or
            // dangling symlink), mode 0600 on Unix. Other read errors never overwrite.
            let mut file = options
                .open(path)
                .map_err(|e| format!("create key file: {e}"))?;
            file.write_all(seed.as_ref())
                .map_err(|e| format!("write key file: {e}"))?;
            file.sync_all().map_err(|e| format!("sync key file: {e}"))?;
            println!("generated new identity; seed stored in {path}");
            Ok(IdentityKeypair::from_seed(&seed))
        }
        Err(e) => Err(format!("read key file {path}: {e}")),
    }
}

/// "B5": row letter A-J (A = 0), column digit 0-9.
fn parse_cell(input: &str) -> Option<CellIndex> {
    let bytes = input.trim().as_bytes();
    if bytes.len() != 2 {
        return None;
    }
    let row = bytes[0].to_ascii_uppercase();
    if !(b'A'..=b'J').contains(&row) || !bytes[1].is_ascii_digit() {
        return None;
    }
    CellIndex::from_row_col(row - b'A', bytes[1] - b'0')
}

fn decode_hex(raw: &str) -> Option<Vec<u8>> {
    let s = raw.trim();
    if (s.len() & 1) != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn parse_fleet_hex(raw: &str, rules: Rules) -> Result<Zeroizing<[u8; 3 * K]>, String> {
    let bytes = Zeroizing::new(
        decode_hex(raw).ok_or_else(|| "invalid hex in fleet placement".to_string())?,
    );
    let arr = Zeroizing::new(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("fleet placement must be exactly {} hex chars", 6 * K))?,
    );
    Fleet::from_bytes(&arr, rules).map_err(|e| format!("invalid fleet placement: {e}"))?;
    Ok(arr)
}

fn parse_fleet_file(path: &str, rules: Rules) -> Result<Zeroizing<[u8; 3 * K]>, String> {
    const MAX_FLEET_FILE_BYTES: u64 = 128;
    let file = std::fs::File::open(path).map_err(|e| format!("open fleet file {path}: {e}"))?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_FLEET_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read fleet file {path}: {e}"))?;
    if bytes.len() as u64 > MAX_FLEET_FILE_BYTES {
        return Err(format!(
            "fleet file {path} exceeds {MAX_FLEET_FILE_BYTES}-byte limit"
        ));
    }
    if bytes.len() == 3 * K {
        let arr = Zeroizing::new(bytes.as_slice().try_into().expect("length checked"));
        Fleet::from_bytes(&arr, rules)
            .map_err(|e| format!("invalid fleet placement in {path}: {e}"))?;
        return Ok(arr);
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| format!("fleet file {path} must contain 15 raw bytes or 30 hex digits"))?;
    parse_fleet_hex(text.trim(), rules)
}

struct ParsedTranscript {
    hello_a: Vec<u8>,
    hello_b: Vec<u8>,
    frames: Vec<Vec<u8>>,
}

fn parse_transcript_text(text: &str) -> Result<ParsedTranscript, String> {
    if text.trim_start().starts_with('{') {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|e| format!("invalid JSON transcript: {e}"))?;
        let object = value
            .as_object()
            .ok_or_else(|| "JSON transcript must be an object".to_string())?;
        let hex_field = |keys: &[&str]| -> Result<Option<Vec<u8>>, String> {
            for key in keys {
                match object.get(*key) {
                    None | Some(serde_json::Value::Null) => continue,
                    Some(serde_json::Value::String(raw)) => {
                        return decode_hex(raw)
                            .map(Some)
                            .ok_or_else(|| format!("invalid hex in JSON field '{key}'"));
                    }
                    Some(_) => return Err(format!("JSON field '{key}' must be a hex string")),
                }
            }
            Ok(None)
        };
        let hello_a = hex_field(&["hello_a", "hello_one"])?
            .ok_or_else(|| "missing hello_a / hello_one in JSON transcript".to_string())?;
        let hello_b = hex_field(&["hello_b", "hello_two"])?
            .ok_or_else(|| "missing hello_b / hello_two in JSON transcript".to_string())?;
        let frame_values = object
            .get("frames")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "JSON field 'frames' must be an array".to_string())?;
        let mut frames = Vec::with_capacity(frame_values.len() + 1);
        for (i, item) in frame_values.iter().enumerate() {
            let raw = item
                .as_str()
                .ok_or_else(|| format!("frames[{i}] must be a hex string"))?;
            frames.push(decode_hex(raw).ok_or_else(|| format!("invalid hex at frames[{i}]"))?);
        }
        if let Some(ev) = hex_field(&["evidence_frame"])? {
            if frames.last().is_none_or(|f| f.as_slice() != ev.as_slice()) {
                frames.push(ev);
            }
        }
        return Ok(ParsedTranscript {
            hello_a,
            hello_b,
            frames,
        });
    }

    let mut hello_a = None;
    let mut hello_b = None;
    let mut indexed_frames: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut evidence = None;

    for (line_no, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("line {}: expected key = value", line_no + 1));
        };
        let key = k.trim();
        let val = v.trim();
        match key {
            "hello_a" | "hello_role_a" | "hello_one" => {
                hello_a = Some(
                    decode_hex(val)
                        .ok_or_else(|| format!("line {}: invalid hex for {key}", line_no + 1))?,
                );
            }
            "hello_b" | "hello_role_b" | "hello_two" => {
                hello_b = Some(
                    decode_hex(val)
                        .ok_or_else(|| format!("line {}: invalid hex for {key}", line_no + 1))?,
                );
            }
            "evidence_frame" => {
                evidence = Some(decode_hex(val).ok_or_else(|| {
                    format!("line {}: invalid hex for evidence_frame", line_no + 1)
                })?);
            }
            _ if key.starts_with("frame[") && key.ends_with(']') => {
                let idx_str = &key[6..key.len() - 1];
                let idx: usize = idx_str
                    .parse()
                    .map_err(|_| format!("line {}: invalid frame index '{key}'", line_no + 1))?;
                let bytes = decode_hex(val)
                    .ok_or_else(|| format!("line {}: invalid hex in {key}", line_no + 1))?;
                indexed_frames.push((idx, bytes));
            }
            _ => {}
        }
    }

    let hello_a = hello_a.ok_or_else(|| "missing hello_a / hello_role_a".to_string())?;
    let hello_b = hello_b.ok_or_else(|| "missing hello_b / hello_role_b".to_string())?;
    indexed_frames.sort_by_key(|(idx, _)| *idx);
    let mut frames = Vec::with_capacity(indexed_frames.len() + usize::from(evidence.is_some()));
    for (expected, (idx, bytes)) in indexed_frames.into_iter().enumerate() {
        if idx != expected {
            return Err(format!(
                "non-contiguous frame indices: expected {expected}, found {idx}"
            ));
        }
        frames.push(bytes);
    }
    if let Some(ev) = evidence {
        if frames.last().is_none_or(|f| f.as_slice() != ev.as_slice()) {
            frames.push(ev);
        }
    }
    Ok(ParsedTranscript {
        hello_a,
        hello_b,
        frames,
    })
}

fn verify_transcript_file(path: &str) -> Result<(), String> {
    const MAX_TRANSCRIPT_BYTES: u64 = 2 * 1024 * 1024;
    let meta = std::fs::metadata(path).map_err(|e| format!("stat {path}: {e}"))?;
    if meta.len() > MAX_TRANSCRIPT_BYTES {
        return Err(format!(
            "{path} exceeds {MAX_TRANSCRIPT_BYTES}-byte transcript limit"
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let parsed = parse_transcript_text(&text)?;
    let report = verify::verify_transcript(&parsed.hello_a, &parsed.hello_b, &parsed.frames)
        .map_err(|e| format!("transcript invalid: {e}"))?;

    let rules_str = match report.rules {
        Rules::Standard => "standard",
        Rules::NoTouch => "no-touch",
    };
    println!("rules: {rules_str}");
    println!("params_id: {}", hex(&report.params_id));
    println!("sid: {}", hex(&report.sid));
    println!("genesis_hash: {}", hex(&report.genesis_hash));
    println!("role_a: {}", report.role_a_key.fingerprint_hex());
    println!("role_b: {}", report.role_b_key.fingerprint_hex());
    if let Some(first) = report.first_mover {
        println!("first_mover: {first:?}");
    }
    println!("frames_verified: {}", report.frames_verified);
    println!(
        "tallies: A shots={} hits={}; B shots={} hits={}",
        report.shots_by_a, report.hits_by_a, report.shots_by_b, report.hits_by_b
    );
    match report.verdict {
        TranscriptVerdict::Completed { winner } => {
            println!("verdict: COMPLETED winner={winner:?}");
        }
        TranscriptVerdict::Resigned { winner, resigned } => {
            println!("verdict: RESIGNED winner={winner:?} resigned={resigned:?}");
        }
        TranscriptVerdict::AttributableViolation {
            guilty,
            sequence,
            frame_hash,
            violation,
        } => {
            println!(
                "verdict: ATTRIBUTABLE_VIOLATION guilty={guilty:?} seq={sequence} hash={} reason={violation}",
                hex(&frame_hash)
            );
        }
        TranscriptVerdict::Incomplete { expected_next } => {
            println!("verdict: INCOMPLETE expected_next={expected_next:?}");
        }
    }
    Ok(())
}

fn cell_name(cell: CellIndex) -> String {
    format!("{}{}", (b'A' + cell.row()) as char, cell.col())
}

fn print_grid(mark: impl Fn(usize) -> char) {
    println!(
        "   {}",
        (0..10).map(|c| c.to_string()).collect::<Vec<_>>().join(" ")
    );
    for row in 0..10 {
        let cells: Vec<String> = (0..10)
            .map(|col| mark(row * 10 + col).to_string())
            .collect();
        println!("{}  {}", (b'A' + row as u8) as char, cells.join(" "));
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fingerprint(bytes: &[u8; 32]) -> String {
    hex(bytes)
}

fn prompt_line(prompt: &str) -> Option<String> {
    print!("{prompt}");
    std::io::stdout().flush().ok()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok()?;
    if line.is_empty() {
        return None;
    }
    Some(line.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    struct KeyDir(std::path::PathBuf);
    impl KeyDir {
        fn new() -> Self {
            let path = env::temp_dir().join(format!("zkb-key-test-{:032x}", OsRng.gen::<u128>()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn key(&self) -> String {
            self.0.join("identity").to_str().unwrap().to_owned()
        }
    }
    impl Drop for KeyDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn identity_roundtrip_and_private_creation() {
        let dir = KeyDir::new();
        let path = dir.key();
        let first = load_or_create_identity(Some(&path)).unwrap();
        let second = load_or_create_identity(Some(&path)).unwrap();
        assert_eq!(first.peer_key(), second.peer_key());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn invalid_existing_identity_is_never_overwritten() {
        let dir = KeyDir::new();
        let path = dir.key();
        for len in [0, 31, 33, 4096] {
            let original = vec![0x71; len];
            std::fs::write(&path, &original).unwrap();
            assert!(load_or_create_identity(Some(&path)).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }
        assert!(load_or_create_identity(Some(dir.0.to_str().unwrap())).is_err());
        assert!(dir.0.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_does_not_create_or_replace_identity() {
        let dir = KeyDir::new();
        let path = dir.key();
        let target = dir.0.join("missing");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(load_or_create_identity(Some(&path)).is_err());
        assert!(!target.exists());
        assert!(std::fs::symlink_metadata(path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn fingerprint_covers_the_entire_identity() {
        let first = [7; 32];
        let mut second = first;
        second[31] ^= 1;
        assert_ne!(fingerprint(&first), fingerprint(&second));
        assert_eq!(fingerprint(&first).len(), 64);
    }

    #[test]
    fn fleet_file_accepts_raw_or_hex_and_rejects_unsafe_inputs() {
        let dir = KeyDir::new();
        let raw = [0, 0, 0, 2, 0, 0, 4, 0, 0, 5, 0, 0, 7, 0, 0];
        let raw_path = dir.0.join("fleet.raw");
        std::fs::write(&raw_path, raw).unwrap();
        assert_eq!(
            parse_fleet_file(raw_path.to_str().unwrap(), Rules::Standard)
                .unwrap()
                .as_ref(),
            &raw
        );

        let hex_path = dir.0.join("fleet.hex");
        std::fs::write(&hex_path, format!("  {}\n", hex(&raw))).unwrap();
        assert_eq!(
            parse_fleet_file(hex_path.to_str().unwrap(), Rules::Standard)
                .unwrap()
                .as_ref(),
            &raw
        );

        let oversized_path = dir.0.join("oversized");
        std::fs::write(&oversized_path, vec![b'0'; 129]).unwrap();
        assert!(parse_fleet_file(oversized_path.to_str().unwrap(), Rules::Standard).is_err());
    }

    #[test]
    fn fleet_sources_are_mutually_exclusive() {
        let args = vec![
            "listen".to_string(),
            "--fleet".to_string(),
            "000000020000040000050000070000".to_string(),
            "--fleet-file".to_string(),
            "private-fleet".to_string(),
        ];
        assert!(matches!(
            parse_action(&args),
            Err(message) if message == "use only one of --fleet or --fleet-file"
        ));
    }

    fn test_session<'a>(
        key: &'a IdentityKeypair,
        role: Role,
        peer: &IdentityKeypair,
    ) -> Session<'a> {
        let fleet = Fleet::from_bytes(
            &[0, 0, 0, 2, 0, 0, 4, 0, 0, 5, 0, 0, 7, 0, 0],
            Rules::Standard,
        )
        .unwrap();
        Session::new(
            Parameters::standard(),
            key,
            role,
            AuthenticatedPeer::from_policy_decision(peer.peer_key()),
            [3; 32],
            [4; 32],
            fleet,
            vec![Scalar::ONE; SHIP_BITS],
        )
        .unwrap()
    }

    fn test_demo<'a>(key: &'a IdentityKeypair, session: Session<'a>) -> Demo<'a> {
        let opts = Options {
            listen: false,
            addr: String::new(),
            name: "test".into(),
            key_file: None,
            rules: Rules::Standard,
            fleet: None,
            transcript_out: None,
            auto: true,
        };
        let mut demo = Demo::new(Parameters::standard(), key, &opts);
        demo.session = Some(session);
        demo
    }

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        for stream in [&client, &server] {
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
        }
        (client, server)
    }

    #[test]
    fn peer_resignation_during_commit_ends_demo() {
        let a = IdentityKeypair::from_seed(&[1; 32]);
        let b = IdentityKeypair::from_seed(&[2; 32]);
        let mut peer = test_session(&a, Role::A, &b);
        let mut demo = test_demo(&b, test_session(&b, Role::B, &a));
        let (mut local_stream, mut peer_stream) = tcp_pair();
        send_frame(&mut peer_stream, &peer.resign().unwrap()).unwrap();
        assert_eq!(demo.commit_and_coin(&mut local_stream).unwrap(), None);
    }

    #[test]
    fn peer_resignation_instead_of_answer_ends_demo() {
        let a = IdentityKeypair::from_seed(&[1; 32]);
        let b = IdentityKeypair::from_seed(&[2; 32]);
        let mut sa = test_session(&a, Role::A, &b);
        let mut sb = test_session(&b, Role::B, &a);
        for _ in 0..8 {
            while let Some(f) = sa.produce(&mut OsRng).unwrap() {
                sb.accept(f.bytes()).unwrap();
            }
            while let Some(f) = sb.produce(&mut OsRng).unwrap() {
                sa.accept(f.bytes()).unwrap();
            }
            if sa.game().is_some() && sb.game().is_some() && sa.head_sequence() == 5 {
                break;
            }
        }
        let first = sa.expected_sender().unwrap();
        let (session, key, peer_key) = match first {
            Role::A => (sa, &a, &b),
            Role::B => (sb, &b, &a),
        };
        let mut demo = test_demo(key, session);
        let (mut local_stream, mut peer_stream) = tcp_pair();
        std::thread::scope(|scope| {
            let peer = scope.spawn(|| {
                let shot = SignedFrame::decode(&recv_frame(&mut peer_stream).unwrap()).unwrap();
                let resign = SignedFrame::craft(
                    peer_key,
                    &shot.header().sid,
                    first.other(),
                    shot.header().sequence + 1,
                    zkb_session::codec::MessageType::Resign,
                    &shot.frame_hash(),
                    vec![],
                );
                send_frame(&mut peer_stream, &resign).unwrap();
            });
            demo.play(&mut local_stream, first).unwrap();
            peer.join().unwrap();
        });
        assert_eq!(demo.session().winner(), Some(first));
    }

    #[test]
    fn parse_cell_accepts_valid_and_rejects_malformed() {
        assert_eq!(parse_cell("A0"), CellIndex::from_row_col(0, 0));
        assert_eq!(parse_cell("j9"), CellIndex::from_row_col(9, 9));
        assert_eq!(parse_cell(" B5 "), CellIndex::from_row_col(1, 5));
        for bad in ["B05", "B+5", "K0", "A10", "", "5B", "A\u{0660}"] {
            assert_eq!(parse_cell(bad), None, "expected None for '{bad}'");
        }
    }

    #[test]
    fn parse_action_supports_fleet_transcript_and_verify() {
        let valid_notouch_fleet = "000000020000040000060000080000";
        let args: Vec<String> = vec![
            "listen",
            "--addr",
            "127.0.0.1:7878",
            "--rules",
            "no-touch",
            "--fleet",
            valid_notouch_fleet,
            "--transcript-out",
            "/tmp/out.txt",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        match parse_action(&args).unwrap() {
            CliAction::Play(opts) => {
                assert!(opts.listen);
                assert_eq!(opts.rules, Rules::NoTouch);
                assert!(opts.fleet.is_some());
                assert_eq!(opts.transcript_out.as_deref(), Some("/tmp/out.txt"));
            }
            CliAction::VerifyTranscript(_) => panic!("expected Play"),
        }

        // Standard-valid touching fleet (rows 4 & 5 touch) must fail under --rules no-touch.
        let touching_fleet: Vec<String> = vec![
            "listen",
            "--addr",
            "127.0.0.1:7878",
            "--rules",
            "no-touch",
            "--fleet",
            "000000020000040000050000070000",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert!(parse_action(&touching_fleet).is_err());

        // Overlapping ships must fail --fleet validation.
        let bad_fleet: Vec<String> = vec![
            "connect",
            "--addr",
            "127.0.0.1:7878",
            "--fleet",
            "000000000000000000000000000000",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert!(parse_action(&bad_fleet).is_err());

        let ver: Vec<String> = vec!["verify-transcript", "vectors/game_transcript_v1.txt"]
            .into_iter()
            .map(String::from)
            .collect();
        match parse_action(&ver).unwrap() {
            CliAction::VerifyTranscript(p) => assert_eq!(p, "vectors/game_transcript_v1.txt"),
            CliAction::Play(_) => panic!("expected VerifyTranscript"),
        }
    }

    #[test]
    fn verify_transcript_file_verifies_pinned_v1_vector() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../vectors/game_transcript_v1.txt"
        );
        verify_transcript_file(path).unwrap();

        let text = std::fs::read_to_string(path).unwrap();
        let p = parse_transcript_text(&text).unwrap();
        let json = format!(
            "{{\n  \"hello_a\": \"{}\",\n  \"hello_b\": \"{}\",\n  \"frames\": [{}]\n}}",
            hex(&p.hello_a),
            hex(&p.hello_b),
            p.frames
                .iter()
                .map(|f| format!("\"{}\"", hex(f)))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let jp = parse_transcript_text(&json).unwrap();
        assert_eq!(jp.hello_a, p.hello_a);
        assert_eq!(jp.hello_b, p.hello_b);
        assert_eq!(jp.frames, p.frames);

        assert!(parse_transcript_text(
            r#"{"hello_a":"00","hello_b":"00","frames":"not-an-array"}"#
        )
        .is_err());
        assert!(parse_transcript_text(
            r#"{"note":"\"hello_a\":\"00\"","hello_b":"00","frames":[]}"#
        )
        .is_err());
        assert!(
            parse_transcript_text(r#"{"hello_a":"00","hello_b":"00","frames":[]} trailing"#)
                .is_err()
        );
    }
}
