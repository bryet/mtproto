use crate::{
    auth::Authenticated,
    config::Config,
    crypto::{self, Crypto},
    protocol::{FrameReader, FrameWriter, Protocol, ProxyRequest},
    state::{unix_time, State},
    wire::{self, Reader, Writer},
};
use anyhow::{bail, Context, Result};
use md5::Md5;
use rand::seq::SliceRandom;
use sha1::{Digest, Sha1};
use socket2::{SockRef, TcpKeepalive};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpStream, time::timeout};

const DC_V4: [&str; 5] = [
    "149.154.175.50",
    "149.154.167.51",
    "149.154.175.100",
    "149.154.167.91",
    "149.154.171.5",
];
const DC_V6: [&str; 5] = [
    "2001:b28:f23d:f001::a",
    "2001:67c:04e8:f002::a",
    "2001:b28:f23d:f003::a",
    "2001:67c:04e8:f004::a",
    "2001:b28:f23f:f005::a",
];

pub fn socket_options(stream: &TcpStream, c: &Config, client: bool, connections: usize) {
    let sock = SockRef::from(stream);
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(if client { c.keepalive } else { 40 }))
        .with_interval(Duration::from_secs(if client { c.keepalive } else { 40 }))
        .with_retries(if client { 3 } else { 5 });
    let _ = sock.set_tcp_keepalive(&keepalive);
    let _ = stream.set_nodelay(true);
    let (recv, send) = if client {
        (
            c.to_tg_buf.get(connections),
            c.to_client_buf.get(connections),
        )
    } else {
        (
            c.to_client_buf.get(connections),
            c.to_tg_buf.get(connections),
        )
    };
    let _ = sock.set_recv_buffer_size(recv);
    let _ = sock.set_send_buffer_size(send);
    #[cfg(target_os = "linux")]
    if client {
        let _ = sock.set_tcp_user_timeout(Some(Duration::from_secs(c.ack_timeout)));
    }
}
async fn connect(host: &str, port: u16, c: &Config, state: &State) -> Result<TcpStream> {
    let stream = timeout(
        Duration::from_secs(c.connect_timeout),
        TcpStream::connect((host, port)),
    )
    .await
    .with_context(|| format!("连接 {host}:{port} 超时"))??;
    socket_options(
        &stream,
        c,
        false,
        state.current.load(std::sync::atomic::Ordering::Relaxed),
    );
    Ok(stream)
}
pub fn direct_header(
    protocol: Protocol,
    fast_key: Option<&[u8; 48]>,
) -> ([u8; 64], Crypto, Crypto) {
    let mut header = loop {
        let h = crypto::random::<64>();
        if h[0] == 0xef
            || h[4..8] == [0; 4]
            || [
                *b"HEAD",
                *b"POST",
                *b"GET ",
                [0xee; 4],
                [0xdd; 4],
                [0x16, 3, 1, 2],
            ]
            .contains(&h[..4].try_into().unwrap())
        {
            continue;
        }
        break h;
    };
    header[56..60].copy_from_slice(&protocol.tag());
    if let Some(key) = fast_key {
        for (dest, source) in header[8..56].iter_mut().zip(key.iter().rev()) {
            *dest = *source;
        }
    }
    let mut reverse = header[8..56].to_vec();
    reverse.reverse();
    let decrypt = Crypto::ctr(&reverse[..32], &reverse[32..]);
    let mut encrypt = Crypto::ctr(&header[8..40], &header[40..56]);
    let mut encrypted = header;
    encrypt.apply(&mut encrypted);
    header[56..64].copy_from_slice(&encrypted[56..64]);
    (header, decrypt, encrypt)
}
pub async fn direct(auth: &Authenticated, c: &Config, state: &State) -> Result<(Reader, Writer)> {
    let dc = usize::from(auth.dc.unsigned_abs())
        .checked_sub(1)
        .context("无效 DC")?;
    let hosts = if state.use_ipv6(c) { &DC_V6 } else { &DC_V4 };
    let host = hosts.get(dc).context("无效 DC")?;
    // A failed IPv6 connection may use IPv4 without changing the wire protocol.
    let stream = match connect(host, 443, c, state).await {
        Ok(s) => s,
        Err(e) if state.use_ipv6(c) => {
            tracing::debug!(error = %e, "IPv6 上游不可用，尝试 IPv4");
            connect(DC_V4[dc], 443, c, state).await?
        }
        Err(e) => return Err(e),
    };
    let (mut r, mut w) = wire::split_tcp(stream)?;
    let (header, decrypt, encrypt) = direct_header(auth.protocol, c.fast.then_some(&auth.fast_key));
    w.write(&header).await?;
    r.crypto = decrypt;
    w.crypto = encrypt;
    if c.fast {
        r.crypto = Crypto::Plain;
    }
    Ok((r, w))
}

pub struct KeyMaterial<'a> {
    pub server_nonce: &'a [u8],
    pub client_nonce: &'a [u8],
    pub timestamp: &'a [u8],
    pub server: SocketAddr,
    pub client: SocketAddr,
    pub secret: &'a [u8],
}
pub fn middle_key(material: &KeyMaterial<'_>, purpose: &[u8]) -> ([u8; 32], [u8; 16]) {
    let mut s = Vec::new();
    s.extend_from_slice(material.server_nonce);
    s.extend_from_slice(material.client_nonce);
    s.extend_from_slice(material.timestamp);
    let (server_ip, client_ip) = match (material.server.ip(), material.client.ip()) {
        (IpAddr::V4(s), IpAddr::V4(c)) => {
            let mut s = s.octets();
            s.reverse();
            let mut c = c.octets();
            c.reverse();
            (s, c)
        }
        _ => ([0; 4], [0; 4]),
    };
    s.extend_from_slice(&server_ip);
    s.extend_from_slice(&material.client.port().to_le_bytes());
    s.extend_from_slice(purpose);
    s.extend_from_slice(&client_ip);
    s.extend_from_slice(&material.server.port().to_le_bytes());
    s.extend_from_slice(material.secret);
    s.extend_from_slice(material.server_nonce);
    if let (IpAddr::V6(client), IpAddr::V6(server)) = (material.client.ip(), material.server.ip()) {
        s.extend_from_slice(&client.octets());
        s.extend_from_slice(&server.octets());
    }
    s.extend_from_slice(material.client_nonce);
    let mut key = [0; 32];
    key[..12].copy_from_slice(&Md5::digest(&s[1..])[..12]);
    key[12..].copy_from_slice(&Sha1::digest(&s));
    (key, Md5::digest(&s[2..]).into())
}
pub async fn middle_handshake(
    stream: TcpStream,
    secret: &[u8],
    public: Option<IpAddr>,
) -> Result<(FrameReader, FrameWriter, SocketAddr)> {
    if secret.len() < 4 {
        bail!("中间代理密钥过短");
    }
    let peer = stream.peer_addr()?;
    let local = stream.local_addr()?;
    let ours = SocketAddr::new(public.unwrap_or(local.ip()), local.port());
    let (r, w) = wire::split_tcp(stream)?;
    let mut r = FrameReader {
        reader: r,
        sequence: -2,
    };
    let mut w = FrameWriter {
        writer: w,
        sequence: -2,
    };
    let timestamp = (unix_time() as u32).to_le_bytes();
    let nonce = crypto::random::<16>();
    let mut msg = vec![0xaa, 0x87, 0xcb, 0x7a];
    msg.extend_from_slice(&secret[..4]);
    msg.extend_from_slice(&[1, 0, 0, 0]);
    msg.extend_from_slice(&timestamp);
    msg.extend_from_slice(&nonce);
    w.write(&msg).await?;
    let reply = r.read().await?;
    if reply.len() != 32
        || reply[..4] != msg[..4]
        || reply[4..8] != secret[..4]
        || reply[8..12] != [1, 0, 0, 0]
    {
        bail!("错误的中间代理 nonce 响应");
    }
    let material = KeyMaterial {
        server_nonce: &reply[16..32],
        client_nonce: &nonce,
        timestamp: &timestamp,
        server: peer,
        client: ours,
        secret,
    };
    let (key, iv) = middle_key(&material, b"CLIENT");
    w.writer.crypto = Crypto::cbc(&key, &iv, false);
    let (key, iv) = middle_key(&material, b"SERVER");
    r.reader.crypto = Crypto::cbc(&key, &iv, true);
    let mut handshake = vec![0xf5, 0xee, 0x82, 0x76, 0, 0, 0, 0];
    handshake.extend_from_slice(b"IPIPPRPDTIMEIPIPPRPDTIME");
    w.write(&handshake).await?;
    let reply = r.read().await?;
    if reply.len() != 32 || reply[..4] != handshake[..4] || &reply[20..32] != b"IPIPPRPDTIME" {
        bail!("错误的中间代理握手响应");
    }
    Ok((r, w, ours))
}
pub async fn middle(
    auth: &Authenticated,
    c: &Config,
    state: &Arc<State>,
) -> Result<(FrameReader, FrameWriter, ProxyRequest)> {
    let info = state.middle.read().unwrap().clone();
    let ipv6 = state.use_ipv6(c);
    let mut candidates = Vec::new();
    if ipv6 {
        if let Some(list) = info.v6.get(&auth.dc) {
            let mut shuffled = list.clone();
            shuffled.shuffle(&mut rand::rngs::OsRng);
            candidates.extend(shuffled);
        }
    }
    if let Some(list) = info.v4.get(&auth.dc) {
        let mut shuffled = list.clone();
        shuffled.shuffle(&mut rand::rngs::OsRng);
        candidates.extend(shuffled);
    }
    let mut last_error = None;
    for (host, port) in candidates {
        let attempt = async {
            let stream = connect(&host, port, c, state).await?;
            let public =
                state.public_ips.read().unwrap()[usize::from(stream.peer_addr()?.is_ipv6())];
            middle_handshake(stream, &info.secret, public).await
        };
        match timeout(Duration::from_secs(c.connect_timeout), attempt).await {
            Ok(Ok((r, w, ours))) => {
                return Ok((
                    r,
                    w,
                    ProxyRequest::new(auth.peer, ours, auth.protocol, c.ad_tag),
                ))
            }
            Ok(Err(e)) => {
                tracing::debug!(%host, port, error = %e, "中间代理连接失败");
                last_error = Some(e);
            }
            Err(e) => {
                last_error = Some(e.into());
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("DC {} 没有可用中间代理", auth.dc)))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn keepalive_matches_python_idle_and_interval() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let c = Config::parse("CLIENT_KEEPALIVE: 123").unwrap();
        socket_options(&stream, &c, true, 0);
        // SAFETY: getsockopt writes into a valid integer with its exact size.
        unsafe {
            use std::os::fd::AsRawFd;
            for (option, expected) in [
                (libc::TCP_KEEPIDLE, 123),
                (libc::TCP_KEEPINTVL, 123),
                (libc::TCP_KEEPCNT, 3),
            ] {
                let mut value: libc::c_int = 0;
                let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
                assert_eq!(
                    libc::getsockopt(
                        stream.as_raw_fd(),
                        libc::IPPROTO_TCP,
                        option,
                        (&mut value as *mut libc::c_int).cast(),
                        &mut len
                    ),
                    0
                );
                assert_eq!(value, expected);
            }
        }
    }
    #[test]
    fn direct_fast_key_and_ctr_offset() {
        let key = crypto::random::<48>();
        let (header, mut dec, mut enc) = direct_header(Protocol::Secure, Some(&key));
        let mut reverse = header[8..56].to_vec();
        reverse.reverse();
        assert_eq!(reverse, key);
        let mut outgoing = Crypto::ctr(&header[8..40], &header[40..56]);
        let mut plain = header;
        outgoing.apply(&mut plain);
        assert_eq!(&plain[56..60], &Protocol::Secure.tag());
        let mut payload = vec![7; 33];
        enc.apply(&mut payload);
        outgoing.apply(&mut payload);
        assert_eq!(payload, [7; 33]);
        let mut incoming = Crypto::ctr(&key[..32], &key[32..]);
        let mut payload = vec![8; 27];
        incoming.apply(&mut payload);
        dec.apply(&mut payload);
        assert_eq!(payload, [8; 27]);
    }
}
