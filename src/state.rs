use crate::{config::Config, crypto};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

pub fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub const BUCKETS: [f64; 11] = [
    0.1,
    0.5,
    1.,
    2.,
    5.,
    15.,
    60.,
    300.,
    600.,
    1800.,
    f64::INFINITY,
];
#[derive(Default)]
pub struct UserStats {
    pub connects: AtomicU64,
    pub current: AtomicUsize,
    pub bytes_from: AtomicU64,
    pub bytes_to: AtomicU64,
    pub msgs_from: AtomicU64,
    pub msgs_to: AtomicU64,
}
impl UserStats {
    pub fn transfer(&self, len: usize, upstream: bool) {
        let (bytes, msgs) = if upstream {
            (&self.bytes_from, &self.msgs_from)
        } else {
            (&self.bytes_to, &self.msgs_to)
        };
        bytes.fetch_add(len as u64, Ordering::Relaxed);
        msgs.fetch_add(1, Ordering::Relaxed);
    }
}
pub struct BoundedSet<T> {
    set: HashSet<T>,
    order: VecDeque<T>,
}
impl<T> Default for BoundedSet<T> {
    fn default() -> Self {
        Self {
            set: HashSet::new(),
            order: VecDeque::new(),
        }
    }
}
impl<T: std::hash::Hash + Eq + Clone> BoundedSet<T> {
    pub fn contains<Q: std::hash::Hash + Eq + ?Sized>(&self, key: &Q) -> bool
    where
        T: std::borrow::Borrow<Q>,
    {
        self.set.contains(key)
    }
    pub fn set_limit(&mut self, limit: usize) {
        if limit == 0 {
            self.set.clear();
            self.order.clear();
            return;
        }
        while self.order.len() > limit {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
    }
    pub fn insert(&mut self, key: T, limit: usize) -> bool {
        self.set_limit(limit);
        if limit == 0 {
            return true;
        }
        if self.set.contains(&key) {
            return false;
        }
        while self.order.len() >= limit {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        self.set.insert(key.clone());
        self.order.push_back(key);
        true
    }
}
pub type ProxyList = HashMap<i16, Vec<(String, u16)>>;
#[derive(Clone)]
pub struct MiddleInfo {
    pub v4: ProxyList,
    pub v6: ProxyList,
    pub secret: Vec<u8>,
}
impl Default for MiddleInfo {
    fn default() -> Self {
        let v4 = [
            "149.154.175.50",
            "149.154.161.144",
            "149.154.175.100",
            "91.108.4.136",
            "91.108.56.183",
        ];
        let v6 = [
            "2001:b28:f23d:f001::d",
            "2001:67c:04e8:f002::d",
            "2001:b28:f23d:f003::d",
            "2001:67c:04e8:f004::d",
            "2001:b28:f23f:f005::d",
        ];
        let mut info = Self {
            v4: HashMap::new(),
            v6: HashMap::new(),
            secret: hex::decode(concat!(
                "c4f9faca9678e6bb48ad6c7e2ce5c0d24430645d554addeb55419e034da62721",
                "d046eaab6e52ab14a95a443ecfb3463e79a05a66612adf9caeda8be9a80da698",
                "6fb0a6ff387af84d88ef3a6413713e5c3377f6e1a3d47d99f5e0c56eece8f05c",
                "54c490b079e31bef82ff0ee8f2b0a32756d249c5f21269816cb7061b265db212"
            ))
            .unwrap(),
        };
        for i in 0..5 {
            let dc = i as i16 + 1;
            info.v4.insert(dc, vec![(v4[i].into(), 8888)]);
            info.v4.insert(
                -dc,
                vec![(if dc == 4 { "149.154.165.109" } else { v4[i] }.into(), 8888)],
            );
            let p = if dc == 2 { 80 } else { 8888 };
            info.v6.insert(dc, vec![(v6[i].into(), p)]);
            info.v6.insert(-dc, vec![(v6[i].into(), p)]);
        }
        info
    }
}
/// Diagnostic events since the last stats print. Bounded independently of
/// connection traffic so rejected clients cannot cause unbounded memory growth.
#[derive(Default, Debug)]
pub struct ClientDiagnostics {
    pub new_ips: BTreeSet<IpAddr>,
    pub time_skews: BTreeMap<IpAddr, i64>,
    pub duplicate_handshakes: BTreeMap<IpAddr, u64>,
}
const DIAGNOSTIC_LIMIT: usize = 131072;

pub struct State {
    pub config: RwLock<Arc<Config>>,
    pub started: Instant,
    pub all: AtomicU64,
    pub bad: AtomicU64,
    pub timeouts: AtomicU64,
    pub current: AtomicUsize,
    pub durations: [AtomicU64; 11],
    pub users: Mutex<HashMap<[u8; 16], Arc<UserStats>>>,
    pub replays: Mutex<BoundedSet<Vec<u8>>>,
    pub client_ips: Mutex<BoundedSet<IpAddr>>,
    pub diagnostics: Mutex<ClientDiagnostics>,
    pub middle: RwLock<MiddleInfo>,
    pub public_ips: RwLock<[Option<IpAddr>; 2]>,
    pub cert_len: AtomicUsize,
    pub mask_dns: Mutex<Option<(String, IpAddr, Instant)>>,
}
impl State {
    pub fn new(config: Config) -> Arc<Self> {
        let ips = [config.public_v4, config.public_v6];
        let users = config
            .secrets
            .iter()
            .map(|s| (*s, Arc::new(UserStats::default())))
            .collect();
        Arc::new(Self {
            config: RwLock::new(Arc::new(config)),
            started: Instant::now(),
            all: AtomicU64::new(0),
            bad: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            current: AtomicUsize::new(0),
            durations: std::array::from_fn(|_| AtomicU64::new(0)),
            users: Mutex::new(users),
            replays: Mutex::new(BoundedSet::default()),
            client_ips: Mutex::new(BoundedSet::default()),
            diagnostics: Mutex::new(ClientDiagnostics::default()),
            middle: RwLock::new(MiddleInfo::default()),
            public_ips: RwLock::new(ips),
            cert_len: AtomicUsize::new(crypto::random_range(1024..4096)),
            mask_dns: Mutex::new(None),
        })
    }
    pub fn config(&self) -> Arc<Config> {
        self.config.read().unwrap().clone()
    }
    pub fn user(&self, secret: [u8; 16]) -> Arc<UserStats> {
        self.users
            .lock()
            .unwrap()
            .entry(secret)
            .or_default()
            .clone()
    }
    pub fn has_replay(&self, key: &[u8], limit: usize) -> bool {
        limit > 0 && self.replays.lock().unwrap().contains(key)
    }
    pub fn replay(&self, key: &[u8], limit: usize) -> bool {
        if limit == 0 {
            return true;
        }
        self.replays.lock().unwrap().insert(key.to_vec(), limit)
    }
    pub fn remember_ip(&self, ip: IpAddr, limit: usize) {
        if limit > 0 && self.client_ips.lock().unwrap().insert(ip, limit) {
            let mut diagnostics = self.diagnostics.lock().unwrap();
            if diagnostics.new_ips.len() < DIAGNOSTIC_LIMIT {
                diagnostics.new_ips.insert(ip);
            }
        }
    }
    pub fn duplicate_handshake(&self, ip: IpAddr) {
        let mut diagnostics = self.diagnostics.lock().unwrap();
        if diagnostics.duplicate_handshakes.contains_key(&ip)
            || diagnostics.duplicate_handshakes.len() < DIAGNOSTIC_LIMIT
        {
            let count = diagnostics.duplicate_handshakes.entry(ip).or_default();
            *count = count.saturating_add(1);
        }
    }
    pub fn time_skew(&self, ip: IpAddr, seconds: i64) {
        let mut diagnostics = self.diagnostics.lock().unwrap();
        if diagnostics.time_skews.contains_key(&ip)
            || diagnostics.time_skews.len() < DIAGNOSTIC_LIMIT
        {
            diagnostics.time_skews.insert(ip, seconds.div_euclid(60));
        }
    }
    pub fn take_diagnostics(&self) -> ClientDiagnostics {
        std::mem::take(&mut *self.diagnostics.lock().unwrap())
    }
    pub fn reload(&self, next: Config) -> anyhow::Result<()> {
        let previous = self.config();
        if !previous.same_listeners(&next) {
            anyhow::bail!("监听地址或端口变更需要重启");
        }
        for secret in &next.secrets {
            self.user(*secret);
        }
        {
            let mut ips = self.public_ips.write().unwrap();
            if next.public_v4.is_some() {
                ips[0] = next.public_v4;
            }
            if next.public_v6.is_some() {
                ips[1] = next.public_v6;
            }
        }
        if next.log_level != previous.log_level {
            tracing::warn!("日志级别变更需要重启");
        }
        self.replays.lock().unwrap().set_limit(next.replay_len);
        self.client_ips.lock().unwrap().set_limit(next.client_ips_len);
        *self.config.write().unwrap() = Arc::new(next);
        *self.mask_dns.lock().unwrap() = None;
        Ok(())
    }
    pub fn use_ipv6(&self, c: &Config) -> bool {
        let ips = self.public_ips.read().unwrap();
        ips[1].is_some() && (c.prefer_ipv6 || ips[0].is_none())
    }
    pub fn middle_enabled(&self, c: &Config) -> bool {
        c.middle && self.public_ips.read().unwrap().iter().any(Option::is_some)
    }
    pub fn links(&self, c: &Config) -> Vec<(String, String)> {
        let servers: Vec<String> = if !c.my_domain.is_empty() {
            vec![c.my_domain.clone()]
        } else {
            let ips = self.public_ips.read().unwrap();
            let list: Vec<_> = ips.iter().flatten().map(ToString::to_string).collect();
            if list.is_empty() {
                vec!["YOUR_IP".into()]
            } else {
                list
            }
        };
        let mut links = Vec::new();
        for secret in &c.secrets {
            let secret = hex::encode(secret);
            for host in &servers {
                for (enabled, value) in [
                    (c.classic, secret.clone()),
                    (c.secure, format!("dd{secret}")),
                    (
                        c.tls,
                        format!("ee{secret}{}", hex::encode(c.tls_domain.as_bytes())),
                    ),
                ] {
                    if enabled {
                        let query = url::form_urlencoded::Serializer::new(String::new())
                            .append_pair("server", host)
                            .append_pair("port", &c.port.to_string())
                            .append_pair("secret", &value)
                            .finish()
                            .replace("%3A", ":");
                        links.push((secret.clone(), format!("https://t.me/proxy?{query}")));
                    }
                }
            }
        }
        links
    }
    pub fn print_links(&self) {
        let c = self.config();
        for (_, link) in self.links(&c) {
            println!("Mtproxyurl: {link}");
        }
        for secret in &c.secrets {
            if *secret == [0; 16]
                || hex::encode(secret) == "0123456789abcdef0123456789abcdef"
                || hex::encode(secret) == "00000000000000000000000000000001"
            {
                tracing::warn!(
                    "正在使用示例 SECRET，请更换；随机示例：{}",
                    hex::encode(crypto::random::<16>())
                );
            }
        }
    }
}
pub struct ConnectionGuard {
    state: Arc<State>,
    user: Arc<UserStats>,
    started: Instant,
}
impl ConnectionGuard {
    pub fn new(state: Arc<State>, user: Arc<UserStats>) -> Self {
        state.current.fetch_add(1, Ordering::Relaxed);
        user.current.fetch_add(1, Ordering::Relaxed);
        Self {
            state,
            user,
            started: Instant::now(),
        }
    }
}
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.state.current.fetch_sub(1, Ordering::Relaxed);
        self.user.current.fetch_sub(1, Ordering::Relaxed);
        let duration = self.started.elapsed().as_secs_f64();
        let i = BUCKETS.iter().position(|b| duration <= *b).unwrap();
        self.state.durations[i].fetch_add(1, Ordering::Relaxed);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostics_unique_ips_counts_and_drain() {
        let state = State::new(Config::parse("{}").unwrap());
        let ip = "203.0.113.1".parse().unwrap();
        state.remember_ip(ip, 10);
        state.remember_ip(ip, 10);
        state.duplicate_handshake(ip);
        state.duplicate_handshake(ip);
        state.time_skew(ip, -61);
        let events = state.take_diagnostics();
        assert_eq!(events.new_ips.len(), 1);
        assert_eq!(events.duplicate_handshakes[&ip], 2);
        assert_eq!(events.time_skews[&ip], -2);
        assert!(state.take_diagnostics().new_ips.is_empty());
        state.remember_ip(ip, 10);
        assert!(state.take_diagnostics().new_ips.is_empty());
        state.remember_ip("203.0.113.2".parse().unwrap(), 0);
        assert!(state.take_diagnostics().new_ips.is_empty());
    }
    #[test]
    fn reload_preserves_listeners_and_rejects_bad_change() {
        let state = State::new(Config::parse("{}").unwrap());
        let mut next = (*state.config()).clone();
        next.ad_tag = Some([3; 16]);
        next.read_timeout = 7;
        state.reload(next).unwrap();
        assert_eq!(state.config().ad_tag, Some([3; 16]));
        assert_eq!(state.config().read_timeout, 7);
        let mut bad = (*state.config()).clone();
        bad.port += 1;
        assert!(state.reload(bad).is_err());
        assert_eq!(state.config().read_timeout, 7);
    }
    #[test]
    fn replay_eviction_and_disabled() {
        let mut s = BoundedSet::<Vec<u8>>::default();
        assert!(s.insert(vec![1], 2));
        assert!(!s.insert(vec![1], 2));
        assert!(s.insert(vec![2], 2));
        assert!(s.insert(vec![3], 2));
        assert!(s.insert(vec![1], 2));
        assert!(s.insert(vec![1], 0));
    }
    #[test]
    fn links_have_all_modes_and_tls_domain() {
        let state = State::new(Config::parse("MODES_CLASSIC: true\nMODES_TLS: true\nTLS_DOMAIN: itunes.apple.com\nMY_DOMAIN: example.com").unwrap());
        let links = state.links(&state.config());
        assert_eq!(links.len(), 3);
        assert!(links[2].1.contains(&format!(
            "secret=ee{}{}",
            "00".repeat(16),
            hex::encode("itunes.apple.com")
        )));
    }
}
