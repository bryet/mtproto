use crate::{
    crypto,
    state::{ProxyList, State},
    wire,
};
use anyhow::{bail, Context, Result};
use std::{
    net::IpAddr,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

pub fn client_hello(domain: &str) -> Vec<u8> {
    let mut msg = vec![0x16, 3, 1, 2, 0, 1, 0, 1, 0xfc, 3, 3];
    msg.extend_from_slice(&crypto::random::<32>());
    msg.push(32);
    msg.extend_from_slice(&crypto::random::<32>());
    msg.extend_from_slice(
        &hex::decode(concat!(
            "00224a4a130113021303c02bc02fc02cc030cca9",
            "cca8c013c014009c009d002f0035000a01000191dada00000000"
        ))
        .unwrap(),
    );
    msg.extend_from_slice(&((domain.len() + 5) as u16).to_be_bytes());
    msg.extend_from_slice(&((domain.len() + 3) as u16).to_be_bytes());
    msg.push(0);
    msg.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    msg.extend_from_slice(domain.as_bytes());
    msg.extend_from_slice(
        &hex::decode(concat!(
            "00170000ff01000100000a000a0008aaaa001d00170018000b00020100002300000010000e000c02",
            "683208687474702f312e31000500050100000000000d001400120403080404010503080505010806",
            "06010201001200000033002b0029aaaa000100001d0020"
        ))
        .unwrap(),
    );
    msg.extend_from_slice(&crypto::fake_public_key());
    msg.extend_from_slice(
        &hex::decode("002d00020101002b000b0ababa0304030303020301001b00030200023a3a0001000015")
            .unwrap(),
    );
    // Long SNI domains need a larger valid record rather than integer underflow.
    let length = 517usize.max(msg.len() + 2);
    msg.extend_from_slice(&((length - msg.len() - 2) as u16).to_be_bytes());
    msg.resize(length, 0);
    msg[3..5].copy_from_slice(&((length - 5) as u16).to_be_bytes());
    msg[6..9].copy_from_slice(&((length - 9) as u32).to_be_bytes()[1..]);
    let extension_length = length - 116;
    msg[114..116].copy_from_slice(&(extension_length as u16).to_be_bytes());
    msg
}
async fn certificate_length(host: &str, port: u16, domain: &str) -> Result<usize> {
    let stream = TcpStream::connect((host, port)).await?;
    let (mut r, mut w) = wire::split(stream);
    w.write(&client_hello(domain)).await?;
    async fn record(r: &mut wire::Reader) -> Result<(u8, Vec<u8>)> {
        let header = r.exact(5).await?;
        if header[1..3] != [3, 3] {
            bail!("不是 TLS 1.3 兼容记录");
        }
        let len = u16::from_be_bytes(header[3..5].try_into().unwrap()) as usize;
        Ok((header[0], r.exact(len).await?))
    }
    if record(&mut r).await?.0 != 22 || record(&mut r).await?.0 != 20 {
        bail!("站点未返回 TLS 1.3 ServerHello/CCS");
    }
    let (kind, data) = record(&mut r).await?;
    if kind != 23 {
        bail!("没有加密证书记录");
    }
    let len = if data.len() >= 1024 {
        data.len()
    } else {
        let (kind, data) = record(&mut r).await?;
        if kind != 23 {
            bail!("没有后续证书记录");
        }
        data.len()
    };
    if len < 1024 {
        bail!("证书被拆分成过小记录");
    }
    Ok(len)
}
pub async fn cert_updater(state: Arc<State>) {
    loop {
        let c = state.config();
        if c.mask {
            match timeout(
                Duration::from_secs(10),
                certificate_length(&c.mask_host, c.mask_port, &c.tls_domain),
            )
            .await
            {
                Ok(Ok(len)) => {
                    state.cert_len.store(len, Ordering::Relaxed);
                    tracing::debug!(len, "Fake-TLS 证书长度更新");
                }
                Ok(Err(e)) => tracing::warn!(error = %e, "无法探测 MASK_HOST 证书，保留当前长度"),
                Err(_) => tracing::warn!("MASK_HOST 证书探测超时"),
            }
        }
        sleep(Duration::from_secs(if c.mask { c.cert_period } else { 60 })).await;
    }
}
pub fn parse_proxies(text: &str) -> Result<ProxyList> {
    let mut result = ProxyList::new();
    for statement in text.split(';') {
        let fields: Vec<_> = statement.split_whitespace().collect();
        let Some(pos) = fields.iter().position(|s| *s == "proxy_for") else {
            continue;
        };
        if pos + 2 >= fields.len() {
            continue;
        }
        let dc: i16 = fields[pos + 1].parse().context("无效中间代理 DC")?;
        if dc == 0 || dc.unsigned_abs() > 5 {
            continue;
        }
        let (host, port) = fields[pos + 2].rsplit_once(':').context("无效代理地址")?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let _: IpAddr = host.parse().context("中间代理不是 IP 地址")?;
        let port: u16 = port.parse().context("无效代理端口")?;
        if port == 0 {
            bail!("代理端口不能为 0");
        }
        result.entry(dc).or_default().push((host.into(), port));
    }
    if result.is_empty() {
        bail!("未找到中间代理列表");
    }
    Ok(result)
}
async fn fetch(client: &reqwest::Client, url: &str, limit: usize) -> Result<Vec<u8>> {
    let mut response = client.get(url).send().await?.error_for_status()?;
    if response.content_length().is_some_and(|n| n > limit as u64) {
        bail!("HTTP 响应过大");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > limit {
            bail!("HTTP 响应过大");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
pub async fn proxy_updater(state: Arc<State>) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("mtproto")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "HTTP 客户端初始化失败");
            return;
        }
    };
    loop {
        let c = state.config();
        if c.middle {
            for (url, v6) in [
                ("https://core.telegram.org/getProxyConfig", false),
                ("https://core.telegram.org/getProxyConfigV6", true),
            ] {
                let result = async {
                    let bytes = fetch(&client, url, 1024 * 1024).await?;
                    parse_proxies(std::str::from_utf8(&bytes)?)
                }
                .await;
                match result {
                    Ok(list) => {
                        let mut info = state.middle.write().unwrap();
                        if v6 {
                            info.v6 = list;
                        } else {
                            info.v4 = list;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, ipv6 = v6, "中间代理列表更新失败，保留旧列表")
                    }
                }
            }
            match fetch(&client, "https://core.telegram.org/getProxySecret", 4096).await {
                Ok(secret) if secret.len() >= 4 => {
                    state.middle.write().unwrap().secret = secret;
                }
                Ok(_) => tracing::warn!("中间代理密钥为空，保留旧密钥"),
                Err(e) => tracing::warn!(error = %e, "中间代理密钥更新失败，保留旧密钥"),
            }
        }
        sleep(Duration::from_secs(if c.middle {
            c.proxy_update_period
        } else {
            60
        }))
        .await;
    }
}
pub async fn init_ips(state: &State) {
    let c = state.config();
    let (v4, v6) = tokio::join!(
        async {
            if c.public_v4.is_some() {
                c.public_v4
            } else {
                crate::discovery::discover_ip(false).await
            }
        },
        async {
            if c.public_v6.is_some() {
                c.public_v6
            } else {
                crate::discovery::discover_ip(true).await
            }
        }
    );
    *state.public_ips.write().unwrap() = [v4, v6];
    if c.middle && v4.is_none() && v6.is_none() {
        tracing::warn!("公网 IP 探测失败，广告中间代理暂不可用；可配置 PUBLIC_IPV4/PUBLIC_IPV6");
    }
}
pub async fn stats_printer(state: Arc<State>) {
    loop {
        sleep(Duration::from_secs(state.config().stats_period)).await;
        tracing::info!(
            connections = state.all.load(Ordering::Relaxed),
            current = state.current.load(Ordering::Relaxed),
            bad = state.bad.load(Ordering::Relaxed),
            "代理统计"
        );
        for (secret, user) in state.users.lock().unwrap().iter() {
            tracing::info!(user = %hex::encode(secret), connects = user.connects.load(Ordering::Relaxed), current = user.current.load(Ordering::Relaxed), bytes = user.bytes_from.load(Ordering::Relaxed) + user.bytes_to.load(Ordering::Relaxed), messages = user.msgs_from.load(Ordering::Relaxed) + user.msgs_to.load(Ordering::Relaxed), "用户统计");
        }
        print_diagnostics(&state);
    }
}
pub fn print_diagnostics(state: &State) {
    let diagnostics = state.take_diagnostics();
    for ip in diagnostics.new_ips {
        tracing::info!(%ip, "新客户端 IP");
    }
    for (ip, minutes) in diagnostics.time_skews {
        tracing::warn!(%ip, skew_minutes = minutes, "客户端时间偏差（可能为重放攻击）");
    }
    for (ip, count) in diagnostics.duplicate_handshakes {
        tracing::warn!(%ip, count, "客户端重复握手（可能为重放攻击）");
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostics_are_logged_and_cleared() {
        #[derive(Clone)]
        struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let output = bytes.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || Capture(output.clone()))
            .finish();
        let state = State::new(crate::config::Config::parse("{}").unwrap());
        let ip = "203.0.113.1".parse().unwrap();
        state.remember_ip(ip, 10);
        state.time_skew(ip, 600);
        state.duplicate_handshake(ip);
        tracing::subscriber::with_default(subscriber, || print_diagnostics(&state));
        let log = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(
            log.contains("新客户端 IP")
                && log.contains("客户端时间偏差")
                && log.contains("客户端重复握手")
        );
        assert!(
            log.contains("203.0.113.1")
                && log.contains("skew_minutes=10")
                && log.contains("count=1")
        );
        assert!(state.take_diagnostics().duplicate_handshakes.is_empty());
    }
    #[test]
    fn parses_signed_dc_and_ipv6() {
        let p = parse_proxies("proxy_for 1 149.154.175.50:8888;\nproxy_for -4 [2001:db8::1]:80;")
            .unwrap();
        assert_eq!(p[&-4], vec![("2001:db8::1".into(), 80)]);
        assert!(parse_proxies("garbage").is_err());
    }
    #[test]
    fn client_hello_lengths() {
        for domain in ["example.com", "itunes.apple.com", &"a".repeat(253)] {
            let msg = client_hello(domain);
            assert_eq!(
                u16::from_be_bytes(msg[3..5].try_into().unwrap()) as usize,
                msg.len() - 5
            );
            assert_eq!(
                u16::from_be_bytes(msg[114..116].try_into().unwrap()) as usize,
                msg.len() - 116
            );
            assert!(msg.windows(domain.len()).any(|w| w == domain.as_bytes()));
        }
    }
}
