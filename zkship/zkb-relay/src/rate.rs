use axum::http::HeaderMap;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);

#[derive(Default)]
struct Inner {
    conns: HashMap<IpAddr, usize>,
    create_windows: HashMap<IpAddr, VecDeque<Instant>>,
    verify_windows: HashMap<IpAddr, VecDeque<Instant>>,
}

#[derive(Clone, Default)]
pub struct IpTracker {
    inner: Arc<Mutex<Inner>>,
}

pub struct ConnGuard {
    ip: IpAddr,
    inner: Arc<Mutex<Inner>>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut guard = self.inner.lock().expect("tracker mutex");
        if let Some(count) = guard.conns.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                guard.conns.remove(&self.ip);
            }
        }
    }
}

impl IpTracker {
    pub fn acquire_conn(&self, ip: IpAddr, max_per_ip: usize) -> Option<ConnGuard> {
        let mut guard = self.inner.lock().expect("tracker mutex");
        let count = guard.conns.entry(ip).or_insert(0);
        if *count >= max_per_ip {
            return None;
        }
        *count += 1;
        Some(ConnGuard {
            ip,
            inner: Arc::clone(&self.inner),
        })
    }

    pub fn allow_room_create(&self, ip: IpAddr, limit_per_min: u32) -> bool {
        let mut guard = self.inner.lock().expect("tracker mutex");
        check_window(&mut guard.create_windows, ip, limit_per_min)
    }

    pub fn allow_verify(&self, ip: IpAddr, limit_per_min: u32) -> bool {
        let mut guard = self.inner.lock().expect("tracker mutex");
        check_window(&mut guard.verify_windows, ip, limit_per_min)
    }
}

fn check_window(map: &mut HashMap<IpAddr, VecDeque<Instant>>, ip: IpAddr, limit: u32) -> bool {
    if limit == 0 {
        return false;
    }
    let now = Instant::now();
    if map.len() > 2048 {
        map.retain(|_, q| {
            while let Some(&front) = q.front() {
                if now.duration_since(front) >= WINDOW {
                    q.pop_front();
                } else {
                    break;
                }
            }
            !q.is_empty()
        });
    }
    let q = map.entry(ip).or_default();
    while let Some(&front) = q.front() {
        if now.duration_since(front) >= WINDOW {
            q.pop_front();
        } else {
            break;
        }
    }
    if q.len() >= limit as usize {
        return false;
    }
    q.push_back(now);
    true
}

pub fn extract_client_ip(headers: &HeaderMap, peer: SocketAddr, trust_proxy: bool) -> IpAddr {
    if trust_proxy {
        if let Some(real_ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return real_ip;
        }
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            // Take the rightmost proxy-appended entry so clients cannot spoof a leftmost header.
            if let Some(last) = xff
                .rsplit(',')
                .next()
                .and_then(|s| s.trim().parse::<IpAddr>().ok())
            {
                return last;
            }
        }
    }
    peer.ip()
}
