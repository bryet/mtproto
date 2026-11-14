use crate::crypto;
use anyhow::{bail, Context, Result};
use serde_yaml::{Mapping, Value};
use std::{collections::HashSet, net::IpAddr, path::Path};

#[derive(Clone, Debug)]
pub struct Config {
    pub log_level: String,
    pub port: u16,
    pub secrets: Vec<[u8; 16]>,
    pub classic: bool,
    pub secure: bool,
    pub tls: bool,
    pub tls_domain: String,
    pub ad_tag: Option<[u8; 16]>,
    pub mask: bool,
    pub mask_host: String,
    pub mask_port: u16,
    pub my_domain: String,
    pub listen_v4: String,
    pub listen_v6: String,
    pub listen_unix: String,
    pub middle: bool,
    pub prefer_ipv6: bool,
    pub fast: bool,
    pub proxy_protocol: bool,
    pub replay_len: usize,
    pub client_ips_len: usize,
    pub ignore_time_skew: bool,
    pub metrics_port: Option<u16>,
    pub metrics_v4: String,
    pub metrics_v6: String,
    pub metrics_prefix: String,
    pub metrics_whitelist: Vec<IpAddr>,
    pub metrics_links: bool,
    pub public_v4: Option<IpAddr>,
    pub public_v6: Option<IpAddr>,
    pub handshake_timeout: u64,
    pub connect_timeout: u64,
    pub read_timeout: u64,
    pub keepalive: u64,
    pub ack_timeout: u64,
    pub stats_period: u64,
    pub proxy_update_period: u64,
    pub cert_period: u64,
    pub to_tg_buf: BufferSize,
    pub to_client_buf: BufferSize,
}

#[derive(Clone, Debug)]
pub enum BufferSize {
    Fixed(usize),
    Adaptive(usize, usize, usize),
}
impl BufferSize {
    pub fn get(&self, connections: usize) -> usize {
        match *self {
            Self::Fixed(n) => n,
            Self::Adaptive(low, threshold, high) => {
                if connections < threshold {
                    high
                } else {
                    low
                }
            }
        }
    }
}
struct Fields(Mapping);
impl Fields {
    fn take(&mut self, key: &str) -> Option<Value> {
        self.0.remove(Value::String(key.into()))
    }
    fn text(&mut self, key: &str, default: &str) -> Result<String> {
        match self.take(key) {
            None | Some(Value::Null) => Ok(default.into()),
            Some(Value::String(s)) => Ok(s),
            Some(Value::Number(n)) => Ok(n.to_string()),
            _ => bail!("{key} 必须是字符串或数字"),
        }
    }
    fn number(&mut self, key: &str, default: u64) -> Result<u64> {
        self.text(key, &default.to_string())?
            .parse()
            .with_context(|| format!("{key} 必须是非负整数"))
    }
    fn port(&mut self, key: &str, default: u16) -> Result<u16> {
        let n = self.number(key, default.into())?;
        if !(1..=65535).contains(&n) {
            bail!("{key} 必须在 1..65535 之间");
        }
        Ok(n as u16)
    }
    fn boolean(&mut self, key: &str, default: bool) -> Result<bool> {
        match self.take(key) {
            None => Ok(default),
            Some(Value::Bool(b)) => Ok(b),
            Some(Value::String(s)) => match s.to_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => Ok(true),
                "false" | "0" | "no" | "off" => Ok(false),
                _ => bail!("{key} 必须是布尔值"),
            },
            Some(Value::Number(n)) if n.as_u64() == Some(0) => Ok(false),
            Some(Value::Number(n)) if n.as_u64() == Some(1) => Ok(true),
            _ => bail!("{key} 必须是布尔值"),
        }
    }
    fn interval(&mut self, key: &str, default: u64) -> Result<u64> {
        let n = self.number(key, default)?;
        if n == 0 || n > 31_536_000 {
            bail!("{key} 必须在 1..31536000 秒之间");
        }
        Ok(n)
    }
    fn ip(&mut self, key: &str, ipv6: bool) -> Result<Option<IpAddr>> {
        let text = self.text(key, "")?;
        if text.is_empty() {
            return Ok(None);
        }
        let ip: IpAddr = text.parse().with_context(|| format!("{key} 不是有效 IP"))?;
        if ip.is_ipv6() != ipv6 {
            bail!("{key} 地址族不正确");
        }
        Ok(Some(ip))
    }
    fn buffer(&mut self, key: &str, default: BufferSize) -> Result<BufferSize> {
        let Some(value) = self.take(key) else {
            return Ok(default);
        };
        let parse = |v: &Value| -> Result<usize> {
            let n = match v {
                Value::Number(n) => n.as_u64(),
                Value::String(s) => s.parse().ok(),
                _ => None,
            }
            .context("无效缓冲区大小")?;
            if n == 0 || n > 16 * 1024 * 1024 {
                bail!("缓冲区大小必须在 1..16777216 之间");
            }
            Ok(n as usize)
        };
        match value {
            Value::Sequence(v) if v.len() == 3 => Ok(BufferSize::Adaptive(
                parse(&v[0])?,
                parse(&v[1])?,
                parse(&v[2])?,
            )),
            v => Ok(BufferSize::Fixed(
                parse(&v).with_context(|| key.to_owned())?,
            )),
        }
    }
}
pub fn hex16(text: &str, name: &str) -> Result<[u8; 16]> {
    if text.len() != 32 {
        bail!("{name} 必须是 32 个十六进制字符（请用引号包裹）");
    }
    let v = hex::decode(text).with_context(|| format!("{name} 包含非十六进制字符"))?;
    Ok(v.try_into().unwrap())
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("无法读取配置 {}", path.display()))?;
        Self::parse(&text)
    }
    pub fn parse(text: &str) -> Result<Self> {
        Self::parse_with_overrides(text, Mapping::new())
    }
    pub fn parse_with_overrides(text: &str, overrides: Mapping) -> Result<Self> {
        // Normalize the original example's assignment syntax, not arbitrary YAML values.
        let normalized = text
            .lines()
            .map(|line| {
                if let Some((key, value)) = line.split_once('=') {
                    let key = key.trim();
                    if !key.is_empty()
                        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    {
                        return format!("{key}: {}", value.trim());
                    }
                }
                line.into()
            })
            .collect::<Vec<_>>()
            .join("\n");
        let mut fields: Mapping =
            serde_yaml::from_str(&normalized).context("配置必须为 YAML 映射")?;
        for (key, value) in overrides {
            fields.insert(key, value);
        }
        let mut f = Fields(fields);
        let log_level = f.text("LOG_LEVEL", "info")?.to_lowercase();
        if !["debug", "info", "warn", "error", "trace"].contains(&log_level.as_str()) {
            bail!("无效 LOG_LEVEL");
        }
        let port = f.port("PORT", 8443)?;
        let mut secrets = Vec::new();
        let mut unique = HashSet::new();
        for key in
            std::iter::once("SECRET".to_string()).chain((1..100).map(|i| format!("SECRET_{i}")))
        {
            if let Some(v) = f.take(&key) {
                let s = v
                    .as_str()
                    .with_context(|| format!("{key} 必须用引号包裹"))?;
                if s.is_empty() {
                    continue;
                }
                let secret = hex16(s, &key)?;
                if unique.insert(secret) {
                    secrets.push(secret);
                }
            }
        }
        if secrets.is_empty() {
            secrets.push([0; 16]);
        }
        let classic = f.boolean("MODES_CLASSIC", false)?;
        let secure = f.boolean("MODES_SECURE", true)?;
        let mut tls = f.boolean("MODES_TLS", false)?;
        if !classic && !secure && !tls {
            tls = true;
        }
        let tls_domain = f.text("TLS_DOMAIN", "www.google.com")?;
        if tls_domain.is_empty()
            || tls_domain.len() > 253
            || !tls_domain.is_ascii()
            || !tls_domain
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            bail!("TLS_DOMAIN 必须是 ASCII 域名（国际化域名请用 punycode）");
        }
        let tag = f.text("AD_TAG", "")?;
        let ad_tag = if tag.is_empty() {
            None
        } else {
            Some(hex16(&tag, "AD_TAG")?)
        };
        let mask = f.boolean("MASK", true)?;
        let mask_host = f.text("MASK_HOST", &tls_domain)?;
        let mask_port = f.port("MASK_PORT", 443)?;
        let my_domain = f.text("MY_DOMAIN", "")?;
        let listen_v4 = f.text("LISTEN_ADDR_IPV4", "0.0.0.0")?;
        let listen_v6 = f.text("LISTEN_ADDR_IPV6", "::")?;
        let listen_unix = f.text("LISTEN_UNIX_SOCK", "")?;
        if listen_v4.is_empty() && listen_v6.is_empty() && listen_unix.is_empty() {
            bail!("至少需要一个监听地址");
        }
        for (key, value, v6) in [
            ("LISTEN_ADDR_IPV4", &listen_v4, false),
            ("LISTEN_ADDR_IPV6", &listen_v6, true),
        ] {
            if !value.is_empty() {
                let ip: IpAddr = value.parse().with_context(|| format!("{key} 必须为 IP"))?;
                if ip.is_ipv6() != v6 {
                    bail!("{key} 地址族不正确");
                }
            }
        }
        let middle = f.boolean("USE_MIDDLE_PROXY", ad_tag.is_some())?;
        let prefer_ipv6 = f.boolean("PREFER_IPV6", !middle)?;
        let fast = f.boolean("FAST_MODE", true)?;
        let proxy_protocol = f.boolean("PROXY_PROTOCOL", false)?;
        let replay_len = f.number("REPLAY_CHECK_LEN", 65536)? as usize;
        let client_ips_len = f.number("CLIENT_IPS_LEN", 131072)? as usize;
        if replay_len > 10_000_000 || client_ips_len > 10_000_000 {
            bail!("缓存上限不能超过 10000000");
        }
        let ignore_time_skew = f.boolean("IGNORE_TIME_SKEW", false)?;
        let metrics_port = match f.take("METRICS_PORT") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s.is_empty() => None,
            Some(v) => {
                f.0.insert(Value::String("METRICS_PORT".into()), v);
                Some(f.port("METRICS_PORT", 9090)?)
            }
        };
        let metrics_v4 = f.text("METRICS_LISTEN_ADDR_IPV4", "0.0.0.0")?;
        let metrics_v6 = f.text("METRICS_LISTEN_ADDR_IPV6", "")?;
        let metrics_prefix = f.text("METRICS_PREFIX", "mtproxy_")?;
        if !metrics_prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b':')
            || metrics_prefix.starts_with(|c: char| c.is_ascii_digit())
        {
            bail!("无效 METRICS_PREFIX");
        }
        let metrics_whitelist = match f.take("METRICS_WHITELIST") {
            None => vec!["127.0.0.1".parse()?, "::1".parse()?],
            Some(Value::Sequence(values)) => values
                .iter()
                .map(|v| {
                    v.as_str()
                        .context("METRICS_WHITELIST 必须是 IP 列表")?
                        .parse()
                        .context("无效指标白名单 IP")
                })
                .collect::<Result<Vec<_>>>()?,
            _ => bail!("METRICS_WHITELIST 必须是 YAML 列表"),
        };
        let metrics_links = f.boolean("METRICS_EXPORT_LINKS", false)?;
        let public_v4 = f.ip("PUBLIC_IPV4", false)?;
        let public_v6 = f.ip("PUBLIC_IPV6", true)?;
        let handshake_timeout = f.interval(
            "CLIENT_HANDSHAKE_TIMEOUT",
            crypto::random_range(5..15) as u64,
        )?;
        let connect_timeout = f.interval("TG_CONNECT_TIMEOUT", 10)?;
        let read_timeout = f.interval("TG_READ_TIMEOUT", 60)?;
        let keepalive = f.interval("CLIENT_KEEPALIVE", 600)?;
        let ack_timeout = f.interval("CLIENT_ACK_TIMEOUT", 300)?;
        let stats_period = f.interval("STATS_PRINT_PERIOD", 600)?;
        let proxy_update_period = f.interval("PROXY_INFO_UPDATE_PERIOD", 86400)?;
        let cert_period = f.interval(
            "GET_CERT_LEN_PERIOD",
            crypto::random_range(4 * 3600..6 * 3600) as u64,
        )?;
        let to_tg_buf = f.buffer("TO_TG_BUFSIZE", BufferSize::Fixed(65536))?;
        let to_client_buf = f.buffer("TO_CLT_BUFSIZE", BufferSize::Adaptive(16384, 100, 131072))?;
        if !f.0.is_empty() {
            bail!(
                "未知配置字段：{}",
                f.0.keys()
                    .map(|k| k.as_str().unwrap_or("<非字符串>"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        Ok(Self {
            log_level,
            port,
            secrets,
            classic,
            secure,
            tls,
            tls_domain,
            ad_tag,
            mask,
            mask_host,
            mask_port,
            my_domain,
            listen_v4,
            listen_v6,
            listen_unix,
            middle,
            prefer_ipv6,
            fast,
            proxy_protocol,
            replay_len,
            client_ips_len,
            ignore_time_skew,
            metrics_port,
            metrics_v4,
            metrics_v6,
            metrics_prefix,
            metrics_whitelist,
            metrics_links,
            public_v4,
            public_v6,
            handshake_timeout,
            connect_timeout,
            read_timeout,
            keepalive,
            ack_timeout,
            stats_period,
            proxy_update_period,
            cert_period,
            to_tg_buf,
            to_client_buf,
        })
    }
    pub fn same_listeners(&self, other: &Self) -> bool {
        self.port == other.port
            && self.listen_v4 == other.listen_v4
            && self.listen_v6 == other.listen_v6
            && self.listen_unix == other.listen_unix
            && self.metrics_port == other.metrics_port
            && self.metrics_v4 == other.metrics_v4
            && self.metrics_v6 == other.metrics_v6
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn random_defaults_and_explicit_overrides() {
        for _ in 0..50 {
            let c = Config::parse("{}").unwrap();
            assert!((5..15).contains(&c.handshake_timeout));
            assert!((14400..21600).contains(&c.cert_period));
        }
        let c = Config::parse("CLIENT_HANDSHAKE_TIMEOUT: 20\nGET_CERT_LEN_PERIOD: 300").unwrap();
        assert_eq!(c.handshake_timeout, 20);
        assert_eq!(c.cert_period, 300);
    }
    #[test]
    fn example_and_legacy() {
        let c = Config::parse(include_str!("../config.example.yaml")).unwrap();
        assert_eq!(c.port, 8443);
        assert!(c.secure && !c.classic && !c.tls && !c.middle);
        let c = Config::parse("PORT = \"443\"\nSECRET = \"0123456789abcdef0123456789abcdef\"\nMODES_SECURE = false\nMODES_TLS = true\nAD_TAG = \"0123456789abcdef0123456789abcdef\"").unwrap();
        assert!(c.middle && c.tls);
        assert_eq!(c.port, 443);
    }
    #[test]
    fn rejects_invalid() {
        for s in [
            "SECRET: 1234",
            "SECRET: \"aa\"",
            "PORT: 0",
            "PORT: 65536",
            "MODES_TLS: maybe",
            "AD_TAG: bad",
            "TYPO: 1",
            "TG_READ_TIMEOUT: 0",
            "TLS_DOMAIN: \"a\\nb\"",
        ] {
            assert!(Config::parse(s).is_err(), "{s}");
        }
    }
    #[test]
    fn multiple_secrets_and_fallback() {
        let c = Config::parse("SECRET: \"0123456789abcdef0123456789abcdef\"\nSECRET_1: \"fedcba9876543210fedcba9876543210\"\nMODES_SECURE: false").unwrap();
        assert_eq!(c.secrets.len(), 2);
        assert!(c.tls);
    }
}
