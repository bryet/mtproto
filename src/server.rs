use crate::{
    auth::{self, Handshake},
    config::Config,
    crypto::Crypto,
    maintenance,
    protocol::{self, FrameReader, FrameWriter, Protocol, ProxyRequest},
    state::{ConnectionGuard, State, UserStats, BUCKETS},
    upstream,
    wire::{self, Reader, Writer},
};
use anyhow::{bail, Context, Result};
use socket2::{Domain, Protocol as SocketProtocol, SockAddr, Socket, Type};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};

struct CloseTcp(Option<Arc<wire::TcpControl>>);
impl Drop for CloseTcp {
    fn drop(&mut self) {
        if let Some(control) = &self.0 {
            let _ = control.shutdown_write();
        }
    }
}
async fn pipe_raw(
    mut reader: Reader,
    mut writer: Writer,
    user: Arc<UserStats>,
    buffer: usize,
    read_timeout: Option<u64>,
    state: Arc<State>,
) -> Result<()> {
    loop {
        let mut data = if read_timeout.is_some() {
            timeout(
                Duration::from_secs(state.config().read_timeout),
                reader.chunk(buffer),
            )
            .await??
        } else {
            reader.chunk(buffer).await?
        };
        if data.is_empty() {
            writer.shutdown().await?;
            return Ok(());
        }
        user.transfer(data.len(), read_timeout.is_none());
        writer.write_mut(&mut data).await?;
    }
}
async fn pipe_client(
    mut reader: Reader,
    mut writer: FrameWriter,
    request: Arc<ProxyRequest>,
    user: Arc<UserStats>,
    protocol: Protocol,
    state: Arc<State>,
) -> Result<()> {
    loop {
        let packet = protocol::read_client(&mut reader, protocol).await?;
        if packet.data.is_empty() {
            writer.writer.shutdown().await?;
            return Ok(());
        }
        user.transfer(packet.data.len(), true);
        writer
            .write(&request.encode_with_tag(&packet, state.config().ad_tag)?)
            .await?;
    }
}
async fn pipe_middle(
    mut reader: FrameReader,
    mut writer: Writer,
    request: Arc<ProxyRequest>,
    user: Arc<UserStats>,
    protocol: Protocol,
    state: Arc<State>,
) -> Result<()> {
    loop {
        let data = timeout(
            Duration::from_secs(state.config().read_timeout),
            reader.read(),
        )
        .await??;
        let packet = request.decode(data)?;
        if packet.skip {
            continue;
        }
        if packet.data.is_empty() {
            writer.shutdown().await?;
            return Ok(());
        }
        user.transfer(packet.data.len(), false);
        let mut encoded = protocol::encode_client(protocol, &packet)?;
        writer.write_mut(&mut encoded).await?;
    }
}
pub async fn handle_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    peer: SocketAddr,
    state: Arc<State>,
) -> Result<()> {
    state.all.fetch_add(1, Ordering::Relaxed);
    let (r, w) = wire::split(stream);
    handle_parts(r, w, peer, state).await
}
async fn handle_parts(
    mut r: Reader,
    mut w: Writer,
    peer: SocketAddr,
    state: Arc<State>,
) -> Result<()> {
    let c = state.config();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(c.handshake_timeout);
    let result =
        tokio::time::timeout_at(deadline, auth::handshake(&mut r, &mut w, peer, &c, &state)).await;
    let authenticated = match result {
        Err(_) => {
            state.timeouts.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        Ok(Err(e)) => return Err(e.into()),
        Ok(Ok(Handshake::Rejected(prefix))) => {
            // As in Python, masking is inside the handshake deadline, not an
            // unbounded unauthenticated connection task.
            match tokio::time::timeout_at(deadline, auth::mask(&mut r, &mut w, &prefix, &c, &state))
                .await
            {
                Ok(result) => result?,
                Err(_) => {
                    state.timeouts.fetch_add(1, Ordering::Relaxed);
                }
            }
            return Ok(());
        }
        Ok(Ok(Handshake::Accepted(a))) => a,
    };
    let c = state.config();
    let user = state.user(authenticated.secret);
    user.connects.fetch_add(1, Ordering::Relaxed);
    let connections = state.current.load(Ordering::Relaxed);
    if state.middle_enabled(&c) {
        let (tg_r, tg_w, request) = upstream::middle(&authenticated, &c, &state).await?;
        let _close = CloseTcp(tg_w.writer.tcp.clone());
        let request = Arc::new(request);
        let _guard = ConnectionGuard::new(state.clone(), user.clone());
        tokio::select! {
            result = pipe_client(r, tg_w, request.clone(), user.clone(), authenticated.protocol, state.clone()) => result,
            result = pipe_middle(tg_r, w, request.clone(), user, authenticated.protocol, state.clone()) => result,
        }
    } else {
        let (tg_r, tg_w) = upstream::direct(&authenticated, &c, &state).await?;
        let _close = CloseTcp(tg_w.tcp.clone());
        if c.fast {
            w.crypto = Crypto::Plain;
        }
        let _guard = ConnectionGuard::new(state.clone(), user.clone());
        tokio::select! {
            result = pipe_raw(r, tg_w, user.clone(), c.to_tg_buf.get(connections), None, state.clone()) => result,
            result = pipe_raw(tg_r, w, user, c.to_client_buf.get(connections), Some(c.read_timeout), state.clone()) => result,
        }
    }
}

pub fn metrics(state: &State, c: &Config) -> String {
    fn escaped(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('\n', "\\n")
            .replace('"', "\\\"")
    }
    fn metric(
        out: &mut String,
        prefix: &str,
        name: &str,
        kind: &str,
        help: &str,
        values: Vec<(String, u64)>,
    ) {
        let name = format!("{prefix}{name}");
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
        for (labels, value) in values {
            out.push_str(&format!("{name}{labels} {value}\n"));
        }
    }
    let mut out = String::new();
    let prefix = &c.metrics_prefix;
    for (name, help, value) in [
        ("uptime", "proxy uptime", state.started.elapsed().as_secs()),
        (
            "connects_all",
            "incoming connects",
            state.all.load(Ordering::Relaxed),
        ),
        (
            "connects_bad",
            "connects with bad secret",
            state.bad.load(Ordering::Relaxed),
        ),
        (
            "handshake_timeouts",
            "timed out handshakes",
            state.timeouts.load(Ordering::Relaxed),
        ),
    ] {
        metric(
            &mut out,
            prefix,
            name,
            "counter",
            help,
            vec![(String::new(), value)],
        );
    }
    let mut values = Vec::new();
    let mut start = "0".to_string();
    for (i, bucket) in BUCKETS.iter().enumerate() {
        let end = if bucket.is_infinite() {
            "+Inf".into()
        } else {
            bucket.to_string()
        };
        values.push((
            format!("{{bucket=\"{start}-{end}\"}}"),
            state.durations[i].load(Ordering::Relaxed),
        ));
        start = end;
    }
    metric(
        &mut out,
        prefix,
        "connects_by_duration",
        "counter",
        "connects by duration",
        values,
    );
    let users = state.users.lock().unwrap();
    for (name, kind, key) in [
        ("user_connects", "counter", 0),
        ("user_connects_curr", "gauge", 1),
        ("user_octets", "counter", 2),
        ("user_msgs", "counter", 3),
        ("user_octets_from", "counter", 4),
        ("user_octets_to", "counter", 5),
        ("user_msgs_from", "counter", 6),
        ("user_msgs_to", "counter", 7),
    ] {
        let values = users
            .iter()
            .map(|(secret, user)| {
                let value = match key {
                    0 => user.connects.load(Ordering::Relaxed),
                    1 => user.current.load(Ordering::Relaxed) as u64,
                    2 => {
                        user.bytes_from.load(Ordering::Relaxed)
                            + user.bytes_to.load(Ordering::Relaxed)
                    }
                    3 => {
                        user.msgs_from.load(Ordering::Relaxed)
                            + user.msgs_to.load(Ordering::Relaxed)
                    }
                    4 => user.bytes_from.load(Ordering::Relaxed),
                    5 => user.bytes_to.load(Ordering::Relaxed),
                    6 => user.msgs_from.load(Ordering::Relaxed),
                    _ => user.msgs_to.load(Ordering::Relaxed),
                };
                (format!("{{user=\"{}\"}}", hex::encode(secret)), value)
            })
            .collect();
        metric(&mut out, prefix, name, kind, name, values);
    }
    if c.metrics_links {
        let values = state
            .links(c)
            .into_iter()
            .map(|(secret, link)| {
                (
                    format!("{{secret=\"{secret}\",link=\"{}\"}}", escaped(&link)),
                    1,
                )
            })
            .collect();
        metric(
            &mut out,
            prefix,
            "proxy_link_info",
            "gauge",
            "proxy link info",
            values,
        );
    }
    out
}
async fn serve_metrics(stream: TcpStream, peer: SocketAddr, state: Arc<State>) -> Result<()> {
    let c = state.config();
    if !c.metrics_whitelist.contains(&peer.ip()) {
        return Ok(());
    }
    let (_, mut w) = wire::split(stream);
    let body = metrics(&state, &c);
    let header = format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\n\r\n", body.len());
    timeout(Duration::from_secs(5), async {
        w.write(header.as_bytes()).await?;
        w.write(body.as_bytes()).await?;
        w.shutdown().await
    })
    .await??;
    Ok(())
}
pub fn bind_tcp(ip: &str, port: u16) -> Result<TcpListener> {
    let ip: IpAddr = ip.parse().context("无效监听 IP")?;
    let addr = SocketAddr::new(ip, port);
    let socket = Socket::new(
        Domain::for_address(addr),
        Type::STREAM,
        Some(SocketProtocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    if ip.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(1024)?;
    Ok(TcpListener::from_std(socket.into())?)
}
fn retryable_accept_error(error: &std::io::Error) -> bool {
    if matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
    ) {
        return true;
    }
    #[cfg(unix)]
    if matches!(
        error.raw_os_error(),
        Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOBUFS) | Some(libc::ENOMEM)
    ) {
        return true;
    }
    false
}
async fn accept_tcp(listener: TcpListener, state: Arc<State>, is_metrics: bool) -> Result<()> {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(connection) => connection,
                    Err(error) if retryable_accept_error(&error) => {
                        tracing::warn!(%error, "接受 TCP 连接失败，稍后重试");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let state = state.clone();
                if !is_metrics { upstream::socket_options(&stream, &state.config(), true, state.current.load(Ordering::Relaxed)); }
                clients.spawn(async move {
                    let result = if is_metrics { serve_metrics(stream, peer, state).await } else {
                        match wire::split_tcp(stream) {
                            Ok((r, w)) => {
                                state.all.fetch_add(1, Ordering::Relaxed);
                                let _close = CloseTcp(w.tcp.clone());
                                handle_parts(r, w, peer, state).await
                            }
                            Err(error) => Err(error.into()),
                        }
                    };
                    if let Err(e) = result { tracing::debug!(%peer, error = %e, "连接结束"); }
                });
            }
            Some(result) = clients.join_next(), if !clients.is_empty() => { if let Err(e) = result { tracing::error!(error = %e, "连接任务异常"); } }
        }
    }
}
#[cfg(unix)]
async fn accept_unix(listener: tokio::net::UnixListener, state: Arc<State>) -> Result<()> {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(connection) => connection,
                    Err(error) if retryable_accept_error(&error) => {
                        tracing::warn!(%error, "接受 Unix 连接失败，稍后重试");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let state = state.clone();
                clients.spawn(async move {
                    if let Err(e) = handle_stream(stream, "0.0.0.0:0".parse().unwrap(), state).await { tracing::debug!(error = %e, "Unix 连接结束"); }
                });
            }
            Some(result) = clients.join_next(), if !clients.is_empty() => { if let Err(e) = result { tracing::error!(error = %e, "Unix 连接任务异常"); } }
        }
    }
}
#[cfg(unix)]
struct UnixPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}
#[cfg(unix)]
impl Drop for UnixPath {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if std::fs::symlink_metadata(&self.path).is_ok_and(|m| {
            m.dev() == self.device && m.ino() == self.inode && m.file_type().is_socket()
        }) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub async fn run(state: Arc<State>, path: PathBuf) -> Result<()> {
    let c = state.config();
    // Install handlers before potentially slow public-IP discovery.
    #[cfg(unix)]
    let (mut terminate, mut interrupt, mut reload, mut debug) = {
        use tokio::signal::unix::{signal, SignalKind};
        (
            signal(SignalKind::terminate())?,
            signal(SignalKind::interrupt())?,
            signal(SignalKind::user_defined2())?,
            signal(SignalKind::user_defined1())?,
        )
    };
    let mut tasks = JoinSet::new();
    let mut listeners = Vec::new();
    let mut bound = 0;
    for (ip, port, is_metrics) in [
        (&c.listen_v4, c.port, false),
        (&c.listen_v6, c.port, false),
        (&c.metrics_v4, c.metrics_port.unwrap_or(0), true),
        (&c.metrics_v6, c.metrics_port.unwrap_or(0), true),
    ] {
        if ip.is_empty() || port == 0 {
            continue;
        }
        let listener = match bind_tcp(ip, port) {
            Ok(listener) => listener,
            Err(e)
                if !is_metrics && ip.contains(':') && bound > 0
                    && e.downcast_ref::<std::io::Error>().is_some_and(|error| {
                        error.kind() == std::io::ErrorKind::AddrNotAvailable
                            || matches!(
                                error.raw_os_error(),
                                Some(libc::EAFNOSUPPORT) | Some(libc::EPROTONOSUPPORT)
                            )
                    }) =>
            {
                tracing::warn!(%ip, port, error = %e, "IPv6 监听不可用");
                continue;
            }
            Err(e) => return Err(e).with_context(|| format!("无法监听 {ip}:{port}")),
        };
        if !is_metrics {
            bound += 1;
        }
        tracing::info!(%ip, port, metrics = is_metrics, "开始监听");
        listeners.push((listener, is_metrics));
    }
    #[cfg(unix)]
    let unix_listener = if !c.listen_unix.is_empty() {
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
        let unix_path = PathBuf::from(&c.listen_unix);
        if let Ok(metadata) = std::fs::symlink_metadata(&unix_path) {
            if !metadata.file_type().is_socket() {
                bail!("LISTEN_UNIX_SOCK 已存在且不是 socket，拒绝覆盖");
            }
            // Only connection refusal establishes that a socket is stale.
            // Permission errors, timeouts and other failures must not unlink it.
            match timeout(
                Duration::from_secs(1),
                tokio::net::UnixStream::connect(&unix_path),
            )
            .await
            {
                Ok(Ok(_)) => bail!("Unix socket 已被其他服务使用"),
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    let current = std::fs::symlink_metadata(&unix_path)?;
                    if current.dev() != metadata.dev() || current.ino() != metadata.ino()
                        || !current.file_type().is_socket()
                    {
                        bail!("Unix socket 路径在检测过程中发生变化，拒绝删除");
                    }
                    std::fs::remove_file(&unix_path)?;
                }
                Ok(Err(error)) => return Err(error).context("无法检查 Unix socket 是否被使用"),
                Err(_) => bail!("Unix socket 检查超时，拒绝删除"),
            }
        }
        let listener = tokio::net::UnixListener::bind(&unix_path)?;
        let metadata = std::fs::symlink_metadata(&unix_path)?;
        let guard = UnixPath {
            path: unix_path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        std::fs::set_permissions(&unix_path, std::fs::Permissions::from_mode(0o666))?;
        bound += 1;
        Some((listener, guard))
    } else {
        None
    };
    #[cfg(not(unix))]
    if !c.listen_unix.is_empty() {
        bail!("此平台不支持 Unix socket");
    }
    if bound == 0 {
        bail!("没有可用的代理监听器");
    }
    #[cfg(unix)]
    tokio::select! {
        _ = maintenance::init_ips(&state) => (),
        _ = terminate.recv() => return Ok(()),
        _ = interrupt.recv() => return Ok(()),
    }
    #[cfg(not(unix))]
    tokio::select! {
        _ = maintenance::init_ips(&state) => (),
        result = tokio::signal::ctrl_c() => { result?; return Ok(()); }
    }
    // Do not authenticate clients until public IPs and routing are initialized.
    for (listener, is_metrics) in listeners {
        tasks.spawn(accept_tcp(listener, state.clone(), is_metrics));
    }
    #[cfg(unix)]
    let _unix_path = if let Some((listener, guard)) = unix_listener {
        tasks.spawn(accept_unix(listener, state.clone()));
        Some(guard)
    } else {
        None
    };
    state.print_links();
    let s = state.clone();
    tasks.spawn(async move {
        maintenance::cert_updater(s).await;
        Ok(())
    });
    let s = state.clone();
    tasks.spawn(async move {
        maintenance::proxy_updater(s).await;
        Ok(())
    });
    let s = state.clone();
    tasks.spawn(async move {
        maintenance::stats_printer(s).await;
        Ok(())
    });
    #[cfg(unix)]
    {
        loop {
            tokio::select! {
                _ = terminate.recv() => break,
                _ = interrupt.recv() => break,
                _ = reload.recv() => {
                    match Config::load(&path) {
                        Ok(next) => match state.reload(next) {
                            Ok(()) => { tracing::info!("配置已重载：新连接使用新配置，已有连接后续请求更新广告标签和读取超时"); state.print_links(); }
                            Err(error) => tracing::error!(%error, "配置重载失败，保留旧配置"),
                        },
                        Err(e) => tracing::error!(error = %e, "配置重载失败，保留旧配置"),
                    }
                }
                _ = debug.recv() => { tracing::info!(current = state.current.load(Ordering::Relaxed), "SIGUSR1 运行状态"); maintenance::print_diagnostics(&state); },
                Some(result) = tasks.join_next() => { result??; bail!("后台任务意外结束"); }
            }
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    tracing::info!("正在关闭监听器及连接");
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn active_relay_uses_reloaded_read_timeout_next_iteration() {
        let state = State::new(Config::parse("TG_READ_TIMEOUT: 60").unwrap());
        let (upstream, proxy) = tokio::io::duplex(128);
        let (_, mut upstream_w) = wire::split(upstream);
        let (r, _) = wire::split(proxy);
        let (client, proxy) = tokio::io::duplex(128);
        let (mut client_r, _) = wire::split(client);
        let (_, w) = wire::split(proxy);
        let task = tokio::spawn(pipe_raw(
            r,
            w,
            state.user([0; 16]),
            128,
            Some(60),
            state.clone(),
        ));
        tokio::task::yield_now().await;
        let mut next = (*state.config()).clone();
        next.read_timeout = 1;
        state.reload(next).unwrap();
        upstream_w.write(b"hello").await.unwrap();
        assert_eq!(client_r.exact(5).await.unwrap(), b"hello");
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(task
            .await
            .unwrap()
            .unwrap_err()
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some());
    }
    #[tokio::test]
    async fn active_middle_request_uses_reloaded_tag() {
        let state =
            State::new(Config::parse("AD_TAG: \"11111111111111111111111111111111\"").unwrap());
        let request = Arc::new(ProxyRequest::new(
            "203.0.113.1:1234".parse().unwrap(),
            "127.0.0.1:8443".parse().unwrap(),
            Protocol::Intermediate,
            Some([0x11; 16]),
        ));
        let (client, proxy) = tokio::io::duplex(512);
        let (r, _) = wire::split(proxy);
        let (_, mut cl_w) = wire::split(client);
        let (remote, proxy) = tokio::io::duplex(1024);
        let (remote_r, _) = wire::split(remote);
        let (_, w) = wire::split(proxy);
        let task = tokio::spawn(pipe_client(
            r,
            FrameWriter {
                writer: w,
                sequence: 0,
            },
            request,
            state.user([0; 16]),
            Protocol::Intermediate,
            state.clone(),
        ));
        let mut remote = FrameReader {
            reader: remote_r,
            sequence: 0,
        };
        for tag in [Some([0x11; 16]), Some([0x22; 16]), None] {
            let mut next = (*state.config()).clone();
            next.ad_tag = tag;
            state.reload(next).unwrap();
            cl_w.write(&[4, 0, 0, 0, 7, 7, 7, 7]).await.unwrap();
            let frame = timeout(Duration::from_secs(2), remote.read())
                .await
                .unwrap()
                .unwrap();
            let flags = u32::from_le_bytes(frame[4..8].try_into().unwrap());
            assert_eq!(flags & 8 != 0, tag.is_some());
            if let Some(tag) = tag {
                assert_eq!(&frame[65..81], &tag);
            } else {
                assert_eq!(frame.len(), 60);
            }
        }
        task.abort();
        let _ = task.await;
    }
    #[test]
    fn metrics_export_and_guard_cleanup() {
        let state = State::new(Config::parse("METRICS_EXPORT_LINKS: true").unwrap());
        let user = state.user([0; 16]);
        {
            let _guard = ConnectionGuard::new(state.clone(), user.clone());
            assert_eq!(user.current.load(Ordering::Relaxed), 1);
        }
        assert_eq!(user.current.load(Ordering::Relaxed), 0);
        user.transfer(100, true);
        let text = metrics(&state, &state.config());
        assert!(text
            .contains("mtproxy_user_octets_from{user=\"00000000000000000000000000000000\"} 100"));
        assert!(text.contains("mtproxy_proxy_link_info"));
    }
    #[tokio::test]
    async fn unauthenticated_mask_forwards_original_prefix() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = State::new(
            Config::parse(&format!(
                "MASK_HOST: 127.0.0.1\nMASK_PORT: {port}\nMODES_SECURE: false\nMODES_TLS: true"
            ))
            .unwrap(),
        );
        let (client, proxy) = tokio::io::duplex(256);
        let task = tokio::spawn(handle_stream(
            proxy,
            "127.0.0.1:1234".parse().unwrap(),
            state,
        ));
        let remote = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 5];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"hello");
            stream.write_all(b"world").await.unwrap();
        });
        let (mut r, mut w) = tokio::io::split(client);
        w.write_all(b"hello").await.unwrap();
        let mut response = [0; 5];
        r.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"world");
        remote.await.unwrap();
        task.await.unwrap().unwrap();
    }
}
