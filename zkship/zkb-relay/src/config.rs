use std::env;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub bind_addr: SocketAddr,
    pub allowed_origins: Vec<String>,
    pub trust_proxy: bool,
    pub max_rooms: usize,
    pub max_conns_per_ip: usize,
    pub room_create_per_min: u32,
    pub verify_per_min: u32,
    pub max_concurrent_verifications: usize,
    pub waiting_ttl: Duration,
    pub reconnect_grace: Duration,
    pub turn_timeout: Duration,
    pub finished_ttl: Duration,
    pub ping_interval: Duration,
    pub pong_timeout: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 8080)),
            allowed_origins: vec!["*".to_string()],
            trust_proxy: false,
            max_rooms: 4096,
            max_conns_per_ip: 32,
            room_create_per_min: 60,
            verify_per_min: 30,
            max_concurrent_verifications: 2,
            waiting_ttl: Duration::from_secs(600),
            reconnect_grace: Duration::from_secs(120),
            turn_timeout: Duration::from_secs(300),
            finished_ttl: Duration::from_secs(1800),
            ping_interval: Duration::from_secs(20),
            pong_timeout: Duration::from_secs(45),
        }
    }
}

impl RelayConfig {
    pub fn from_env() -> Result<Self, String> {
        let mut cfg = Self::default();
        if let Ok(v) = env::var("ZKB_BIND_ADDR") {
            cfg.bind_addr = v
                .parse()
                .map_err(|e| format!("invalid ZKB_BIND_ADDR '{v}': {e}"))?;
        }
        if let Ok(v) = env::var("ZKB_ALLOWED_ORIGINS") {
            let origins: Vec<String> = v
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect();
            if origins.is_empty() {
                return Err("ZKB_ALLOWED_ORIGINS must not be empty when set".to_string());
            }
            cfg.allowed_origins = origins;
        }
        if let Ok(v) = env::var("ZKB_TRUST_PROXY") {
            cfg.trust_proxy = matches!(v.as_str(), "1" | "true" | "TRUE" | "yes");
        }
        if let Some(v) = parse_usize_env("ZKB_MAX_ROOMS")? {
            cfg.max_rooms = v;
        }
        if let Some(v) = parse_usize_env("ZKB_MAX_CONNS_PER_IP")? {
            cfg.max_conns_per_ip = v;
        }
        if let Some(v) = parse_u32_env("ZKB_ROOM_CREATE_PER_MIN")? {
            cfg.room_create_per_min = v;
        }
        if let Some(v) = parse_u32_env("ZKB_VERIFY_PER_MIN")? {
            cfg.verify_per_min = v;
        }
        if let Some(v) = parse_usize_env("ZKB_MAX_CONCURRENT_VERIFICATIONS")? {
            if v == 0 {
                return Err("ZKB_MAX_CONCURRENT_VERIFICATIONS must be at least 1".to_string());
            }
            cfg.max_concurrent_verifications = v;
        }
        if let Some(v) = parse_secs_env("ZKB_WAITING_TTL_SECS")? {
            cfg.waiting_ttl = v;
        }
        if let Some(v) = parse_secs_env("ZKB_RECONNECT_GRACE_SECS")? {
            cfg.reconnect_grace = v;
        }
        if let Some(v) = parse_secs_env("ZKB_TURN_TIMEOUT_SECS")? {
            cfg.turn_timeout = v;
        }
        if let Some(v) = parse_secs_env("ZKB_FINISHED_TTL_SECS")? {
            cfg.finished_ttl = v;
        }
        Ok(cfg)
    }

    pub fn allow_all_origins(&self) -> bool {
        self.allowed_origins.iter().any(|o| o == "*")
    }

    pub fn origin_allowed(&self, origin: Option<&str>) -> bool {
        if self.allow_all_origins() {
            return true;
        }
        let Some(origin) = origin else {
            return false;
        };
        self.allowed_origins
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(origin))
    }
}

fn parse_usize_env(name: &str) -> Result<Option<usize>, String> {
    match env::var(name) {
        Ok(v) => v
            .parse::<usize>()
            .map(Some)
            .map_err(|e| format!("invalid {name} '{v}': {e}")),
        Err(_) => Ok(None),
    }
}

fn parse_u32_env(name: &str) -> Result<Option<u32>, String> {
    match env::var(name) {
        Ok(v) => v
            .parse::<u32>()
            .map(Some)
            .map_err(|e| format!("invalid {name} '{v}': {e}")),
        Err(_) => Ok(None),
    }
}

fn parse_secs_env(name: &str) -> Result<Option<Duration>, String> {
    match env::var(name) {
        Ok(v) => v
            .parse::<u64>()
            .map(Duration::from_secs)
            .map(Some)
            .map_err(|e| format!("invalid {name} '{v}': {e}")),
        Err(_) => Ok(None),
    }
}
