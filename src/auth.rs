use crate::{
    config::Config,
    crypto::{self, Crypto},
    protocol::Protocol,
    state::{unix_time, State},
    wire::{invalid, Reader, Writer},
};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};
use tokio::{io::AsyncReadExt, net::TcpStream, time::timeout};

pub struct Authenticated {
    pub protocol: Protocol,
    pub secret: [u8; 16],
    pub dc: i16,
    pub fast_key: [u8; 48],
    pub peer: SocketAddr,
}
pub enum Handshake {
    Accepted(Authenticated),
    Rejected(Vec<u8>),
}

pub async fn proxy_header(reader: &mut Reader, original: SocketAddr) -> io::Result<SocketAddr> {
    let mut header = reader.exact(6).await?;
    if header == b"PROXY " {
        while !header.ends_with(b"\r\n") {
            if header.len() >= 108 {
                return Err(invalid("PROXY v1 header too long"));
            }
            header.extend_from_slice(&reader.exact(1).await?);
        }
        let text = std::str::from_utf8(&header[..header.len() - 2])
            .map_err(|_| invalid("bad PROXY ASCII"))?;
        let fields: Vec<_> = text.split_whitespace().collect();
        if fields.get(1) == Some(&"UNKNOWN") {
            return Ok(original);
        }
        if fields.len() != 6 || !["TCP4", "TCP6"].contains(&fields[1]) {
            return Err(invalid("bad PROXY v1 header"));
        }
        let source: IpAddr = fields[2]
            .parse()
            .map_err(|_| invalid("bad PROXY source IP"))?;
        let dest: IpAddr = fields[3]
            .parse()
            .map_err(|_| invalid("bad PROXY destination IP"))?;
        let source_port: u16 = fields[4]
            .parse()
            .map_err(|_| invalid("bad PROXY source port"))?;
        let _: u16 = fields[5]
            .parse()
            .map_err(|_| invalid("bad PROXY destination port"))?;
        if source.is_ipv6() != (fields[1] == "TCP6") || dest.is_ipv6() != source.is_ipv6() {
            return Err(invalid("bad PROXY address family"));
        }
        return Ok(SocketAddr::new(source, source_port));
    }
    header.extend_from_slice(&reader.exact(10).await?);
    if header[..12] != *b"\r\n\r\n\0\r\nQUIT\n" || header[12] & 0xf0 != 0x20 {
        return Err(invalid("bad PROXY v2 signature"));
    }
    let len = u16::from_be_bytes(header[14..16].try_into().unwrap()) as usize;
    let addresses = reader.exact(len).await?;
    match header[12] {
        0x20 => Ok(original),
        0x21 => match header[13] >> 4 {
            0 => Ok(original),
            1 if len >= 12 && header[13] & 0x0f == 1 => Ok(SocketAddr::new(
                Ipv4Addr::new(addresses[0], addresses[1], addresses[2], addresses[3]).into(),
                u16::from_be_bytes(addresses[8..10].try_into().unwrap()),
            )),
            2 if len >= 36 && header[13] & 0x0f == 1 => Ok(SocketAddr::new(
                Ipv6Addr::from(<[u8; 16]>::try_from(&addresses[..16]).unwrap()).into(),
                u16::from_be_bytes(addresses[32..34].try_into().unwrap()),
            )),
            _ => Err(invalid("bad PROXY v2 address")),
        },
        _ => Err(invalid("bad PROXY v2 command")),
    }
}

pub fn tls_auth(hello: &[u8], c: &Config, now: u64) -> Option<([u8; 16], Vec<u8>)> {
    tls_auth_diagnostic(hello, c, now, None)
}
fn tls_auth_diagnostic(
    hello: &[u8],
    c: &Config,
    now: u64,
    diagnostic: Option<(&State, IpAddr)>,
) -> Option<([u8; 16], Vec<u8>)> {
    // Bounds and lengths are checked before accessing the ClientHello fields.
    if hello.len() < 44 || hello[..3] != [0x16, 3, 1] || hello[5] != 1 || hello[9..11] != [3, 3] {
        return None;
    }
    let record_len = u16::from_be_bytes(hello[3..5].try_into().ok()?) as usize;
    let handshake_len =
        (usize::from(hello[6]) << 16) | (usize::from(hello[7]) << 8) | usize::from(hello[8]);
    if hello.len() != record_len + 5 || handshake_len + 4 != record_len {
        return None;
    }
    let session_len = hello[43] as usize;
    if session_len > 32 || 44 + session_len + 3 > hello.len() {
        return None;
    }
    let digest = &hello[11..43];
    let mut zeroed = hello.to_vec();
    zeroed[11..43].fill(0);
    for secret in &c.secrets {
        let computed = crypto::hmac(secret, &zeroed);
        if !crypto::constant_time_prefix_eq(&computed, digest, 28) {
            continue;
        }
        let mut timestamp = [0; 4];
        for i in 0..4 {
            timestamp[i] = digest[28 + i] ^ computed[28 + i];
        }
        let timestamp = u32::from_le_bytes(timestamp) as u64;
        let skew = now as i64 - timestamp as i64;
        if !c.ignore_time_skew && timestamp >= 86400 * 1000 && !(skew > -1200 && skew < 600) {
            if let Some((state, ip)) = diagnostic {
                state.time_skew(ip, skew);
            }
            continue;
        }
        return Some((*secret, hello[44..44 + session_len].to_vec()));
    }
    None
}
pub fn tls_response(digest: &[u8], session: &[u8], secret: &[u8], cert_len: usize) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.push(session.len() as u8);
    body.extend_from_slice(session);
    body.extend_from_slice(&[0x13, 1, 0, 0, 0x2e, 0, 0x33, 0, 0x24, 0, 0x1d, 0, 0x20]);
    body.extend_from_slice(&crypto::fake_public_key());
    body.extend_from_slice(&[0, 0x2b, 0, 2, 3, 4]);
    let mut response = vec![0x16, 3, 3];
    response.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    response.push(2);
    response.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    response.extend_from_slice(&body);
    response.extend_from_slice(&[0x14, 3, 3, 0, 1, 1, 0x17, 3, 3]);
    response.extend_from_slice(&(cert_len as u16).to_be_bytes());
    response.extend_from_slice(&crypto::random_vec(cert_len));
    let mut signed = digest.to_vec();
    signed.extend_from_slice(&response);
    let mac = crypto::hmac(secret, &signed);
    response[11..43].copy_from_slice(&mac);
    response
}
pub fn obfuscated_auth(
    header: &[u8],
    c: &Config,
    tls: bool,
) -> Option<(Authenticated, Crypto, Crypto)> {
    if header.len() != 64 {
        return None;
    }
    let mut reverse = header[8..56].to_vec();
    reverse.reverse();
    for secret in &c.secrets {
        let mut key_data = header[8..40].to_vec();
        key_data.extend_from_slice(secret);
        let dec_key = crypto::sha256(&key_data);
        let mut decrypt = Crypto::ctr(&dec_key, &header[40..56]);
        let mut plain = header.to_vec();
        decrypt.apply(&mut plain);
        let Some(protocol) = Protocol::from_tag(&plain[56..60]) else {
            continue;
        };
        let enabled = match protocol {
            Protocol::Secure => {
                if tls {
                    c.tls
                } else {
                    c.secure
                }
            }
            _ => c.classic,
        };
        if !enabled {
            continue;
        }
        let dc = i16::from_le_bytes(plain[60..62].try_into().unwrap());
        if dc == 0 || dc.unsigned_abs() > 5 {
            continue;
        }
        let mut key_data = reverse[..32].to_vec();
        key_data.extend_from_slice(secret);
        let enc_key = crypto::sha256(&key_data);
        let encrypt = Crypto::ctr(&enc_key, &reverse[32..]);
        let mut fast_key = [0; 48];
        fast_key[..32].copy_from_slice(&enc_key);
        fast_key[32..].copy_from_slice(&reverse[32..]);
        return Some((
            Authenticated {
                protocol,
                secret: *secret,
                dc,
                fast_key,
                peer: "0.0.0.0:0".parse().unwrap(),
            },
            decrypt,
            encrypt,
        ));
    }
    None
}
pub async fn handshake(
    reader: &mut Reader,
    writer: &mut Writer,
    peer: SocketAddr,
    c: &Config,
    state: &State,
) -> io::Result<Handshake> {
    let peer = if c.proxy_protocol {
        match proxy_header(reader, peer).await {
            Ok(source) => source,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                state.bad.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%peer, %error, "客户端发送了无效 PROXY protocol 头");
                // Python drains these clients without forwarding malformed headers.
                while !reader.chunk(8192).await?.is_empty() {}
                return Err(error);
            }
            Err(error) => return Err(error),
        }
    } else {
        peer
    };
    let mut header = Vec::new();
    let mut tls = true;
    for byte in [0x16, 3, 1] {
        let got = reader.exact(1).await?[0];
        header.push(got);
        if byte != got {
            tls = false;
            break;
        }
    }
    if tls {
        header.extend_from_slice(&reader.exact(2).await?);
        let len = u16::from_be_bytes(header[3..5].try_into().unwrap()) as usize;
        if len < 512 {
            tls = false;
        } else {
            header.extend_from_slice(&reader.exact(len).await?);
        }
    }
    if tls {
        // No TLS response is produced if no compatible mode is enabled.
        if !c.tls && !c.classic {
            return Ok(Handshake::Rejected(header));
        }
        if state.has_replay(&header[11..27], c.replay_len) {
            state.duplicate_handshake(peer.ip());
            return Ok(Handshake::Rejected(header));
        }
        let Some((secret, session)) =
            tls_auth_diagnostic(&header, c, unix_time(), Some((state, peer.ip())))
        else {
            return Ok(Handshake::Rejected(header));
        };
        if !state.replay(&header[11..27], c.replay_len) {
            state.duplicate_handshake(peer.ip());
            return Ok(Handshake::Rejected(header));
        }
        let cert_len = state.cert_len.load(Ordering::Relaxed);
        writer
            .write(&tls_response(&header[11..43], &session, &secret, cert_len))
            .await?;
        state.remember_ip(peer.ip(), c.client_ips_len);
        reader.tls = true;
        writer.tls = true;
        header = reader.exact(64).await?;
    } else {
        if !c.classic && !c.secure {
            return Ok(Handshake::Rejected(header));
        }
        header.extend_from_slice(&reader.exact(64 - header.len()).await?);
    }
    if state.has_replay(&header[8..56], c.replay_len) {
        state.duplicate_handshake(peer.ip());
        return Ok(Handshake::Rejected(header));
    }
    let Some((mut auth, decrypt, encrypt)) = obfuscated_auth(&header, c, tls) else {
        return Ok(Handshake::Rejected(header));
    };
    if !state.replay(&header[8..56], c.replay_len) {
        state.duplicate_handshake(peer.ip());
        return Ok(Handshake::Rejected(header));
    }
    state.remember_ip(peer.ip(), c.client_ips_len);
    reader.install_crypto(decrypt);
    writer.crypto = encrypt;
    auth.peer = peer;
    Ok(Handshake::Accepted(auth))
}

pub async fn mask(
    reader: &mut Reader,
    writer: &mut Writer,
    first: &[u8],
    c: &Config,
    state: &Arc<State>,
) -> io::Result<()> {
    state.bad.fetch_add(1, Ordering::Relaxed);
    if let Some(client) = &writer.tcp {
        client.set_buffers(8192);
    }
    if !c.mask {
        let mut buffer = [0; 8192];
        while reader.raw.read(&mut buffer).await? != 0 {}
        return Ok(());
    }
    // The fallback always forwards raw bytes, including the consumed initial prefix.
    let cached = state
        .mask_dns
        .lock()
        .unwrap()
        .as_ref()
        .filter(|(host, _, time)| host == &c.mask_host && time.elapsed() < Duration::from_secs(90))
        .map(|(_, ip, _)| *ip);
    let stream = timeout(Duration::from_secs(5), async {
        if let Some(ip) = cached {
            TcpStream::connect(SocketAddr::new(ip, c.mask_port)).await
        } else {
            let addresses: Vec<_> = tokio::net::lookup_host((c.mask_host.as_str(), c.mask_port))
                .await?
                .collect();
            connect_addresses(&addresses).await
        }
    })
    .await??;
    let address = stream.peer_addr()?;
    *state.mask_dns.lock().unwrap() = Some((c.mask_host.clone(), address.ip(), Instant::now()));
    let (mut remote_r, mut remote_w) = crate::wire::split_tcp(stream)?;
    let control = remote_w.tcp.clone();
    // Also ensure cancellation/timeouts shut down the mask connection rather
    // than leaving a peer waiting on a half-open write side.
    struct MaskClose(Option<Arc<crate::wire::TcpControl>>);
    impl Drop for MaskClose {
        fn drop(&mut self) {
            if let Some(control) = &self.0 {
                let _ = control.shutdown_write();
            }
        }
    }
    let _close = MaskClose(control.clone());
    remote_w.write(first).await?;
    remote_w.write(&reader.take_buffer()).await?;
    async fn pipe(r: &mut crate::wire::RawRead, w: &mut crate::wire::RawWrite) -> io::Result<()> {
        tokio::io::copy(r, w).await?;
        use tokio::io::AsyncWriteExt;
        w.shutdown().await
    }
    let (result, remote_finished) = tokio::select! {
        result = pipe(&mut reader.raw, &mut remote_w.raw) => (result, false),
        result = pipe(&mut remote_r.raw, &mut writer.raw) => (result, true),
    };
    if control
        .as_ref()
        .is_some_and(|control| control.shutdown_write().is_err())
        || result.is_err()
        || remote_finished
    {
        if let Some(client) = &writer.tcp {
            let _ = client.reset_on_close();
        }
    }
    result
}

/// Try all DNS answers under the caller's single connection deadline.
pub async fn connect_addresses(addresses: &[SocketAddr]) -> io::Result<TcpStream> {
    let mut last = invalid("mask DNS empty");
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = error,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hello(secret: &[u8], now: u32) -> Vec<u8> {
        let mut hello = crate::maintenance::client_hello("example.com");
        hello[11..43].fill(0);
        let mut digest = crypto::hmac(secret, &hello);
        for (d, t) in digest[28..].iter_mut().zip(now.to_le_bytes()) {
            *d ^= t;
        }
        hello[11..43].copy_from_slice(&digest);
        hello
    }
    #[test]
    fn tls_time_skew_diagnostics_and_strict_boundaries() {
        let c = Config::parse("MODES_TLS: true").unwrap();
        let state = State::new(c.clone());
        let ip = "203.0.113.1".parse().unwrap();
        let now = 1_800_000_000u32;
        for (timestamp, accepted) in [
            (now - 599, true),
            (now - 600, false),
            (now + 1199, true),
            (now + 1200, false),
        ] {
            let hello = hello(&c.secrets[0], timestamp);
            assert_eq!(
                tls_auth_diagnostic(&hello, &c, now.into(), Some((&state, ip))).is_some(),
                accepted
            );
        }
        assert_eq!(state.take_diagnostics().time_skews[&ip], -20);
        let mut ignore = c.clone();
        ignore.ignore_time_skew = true;
        assert!(tls_auth_diagnostic(
            &hello(&[0; 16], now - 1200),
            &ignore,
            now.into(),
            Some((&state, ip))
        )
        .is_some());
        assert!(state.take_diagnostics().time_skews.is_empty());
        assert!(tls_auth(&hello(&[0; 16], 1), &c, now.into()).is_some());
    }
    #[tokio::test]
    async fn fallback_tries_remaining_addresses() {
        let refused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refused_address = refused.local_addr().unwrap();
        drop(refused);
        let available = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connected = timeout(
            Duration::from_secs(2),
            connect_addresses(&[refused_address, available.local_addr().unwrap()]),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            connected.peer_addr().unwrap(),
            available.local_addr().unwrap()
        );
        assert!(connect_addresses(&[]).await.is_err());
    }
    #[test]
    fn tls_digest_timestamp_response() {
        let c = Config::parse("MODES_TLS: true").unwrap();
        let now = 1_800_000_000u32;
        let hello = hello(&c.secrets[0], now);
        let (secret, session) = tls_auth(&hello, &c, now as u64).unwrap();
        assert!(tls_auth(&hello, &c, now as u64 + 601).is_none());
        let response = tls_response(&hello[11..43], &session, &secret, 2048);
        let digest = response[11..43].to_vec();
        let mut zeroed = response;
        zeroed[11..43].fill(0);
        let mut data = hello[11..43].to_vec();
        data.extend_from_slice(&zeroed);
        assert_eq!(digest, crypto::hmac(&secret, &data));
    }
    #[test]
    fn malformed_tls_never_panics() {
        let c = Config::parse("MODES_TLS: true").unwrap();
        for n in 0..600 {
            let input = crypto::random_vec(n);
            assert!(tls_auth(&input, &c, unix_time()).is_none());
        }
        let mut h = hello(&[0; 16], 1);
        h[43] = 255;
        assert!(tls_auth(&h, &c, 1).is_none());
    }
    #[tokio::test]
    async fn proxy_protocol_v1_v2() {
        let original = "127.0.0.1:1234".parse().unwrap();
        let (a, b) = tokio::io::duplex(256);
        let (mut r, _) = crate::wire::split(a);
        let (_, mut w) = crate::wire::split(b);
        w.write(b"PROXY TCP4 203.0.113.1 192.0.2.1 5678 443\r\n")
            .await
            .unwrap();
        assert_eq!(
            proxy_header(&mut r, original).await.unwrap(),
            "203.0.113.1:5678".parse().unwrap()
        );
        let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        header.extend_from_slice(&[0x21, 0x11, 0, 12]);
        header.extend_from_slice(&[203, 0, 113, 2, 192, 0, 2, 1, 0x16, 0x2e, 1, 0xbb]);
        w.write(&header).await.unwrap();
        assert_eq!(
            proxy_header(&mut r, original).await.unwrap(),
            "203.0.113.2:5678".parse().unwrap()
        );
    }
}
