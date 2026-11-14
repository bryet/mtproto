//! Public address discovery with Python-compatible Linux device binding.
use anyhow::{bail, Context, Result};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::{TcpSocket, TcpStream},
    time::timeout,
};

fn interface_name(name: &str) -> bool {
    ["eth", "ens", "enp"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}
pub fn net_interfaces() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        let mut interfaces: Vec<_> = std::fs::read_dir("/sys/class/net")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| interface_name(name))
            .collect();
        interfaces.sort();
        interfaces
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}
async fn connect_bound(address: SocketAddr, interface: Option<&str>) -> Result<TcpStream> {
    let socket = if address.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    #[cfg(target_os = "linux")]
    if let Some(interface) = interface {
        socket2::SockRef::from(&socket).bind_device(Some(interface.as_bytes()))?;
    }
    #[cfg(not(target_os = "linux"))]
    if interface.is_some() {
        bail!("此平台不支持 SO_BINDTODEVICE");
    }
    Ok(socket.connect(address).await?)
}
// Python's public-IP endpoints use HTTP. Bind the actual TCP socket to each
// interface; binding only an unspecified IPv4/IPv6 source is not equivalent.
async fn ip_from_url(url: &str, interface: Option<&str>, ipv6: bool) -> Result<IpAddr> {
    let parsed = url::Url::parse(url)?;
    if parsed.scheme() != "http" {
        bail!("公网 IP 网卡探测端点必须使用 HTTP");
    }
    let host = parsed.host_str().context("IP 探测端点缺少域名")?;
    let port = parsed.port().unwrap_or(80);
    let addresses: Vec<_> = tokio::net::lookup_host((host, port))
        .await?
        .filter(|addr| addr.is_ipv6() == ipv6)
        .collect();
    let mut last = None;
    for address in addresses {
        let attempt = async {
            let stream = connect_bound(address, interface).await?;
            let (mut sender, connection) = hyper::client::conn::handshake(stream).await?;
            let task = tokio::spawn(connection);
            struct ConnectionTask(tokio::task::JoinHandle<Result<(), hyper::Error>>);
            impl Drop for ConnectionTask {
                fn drop(&mut self) {
                    self.0.abort();
                }
            }
            let _task = ConnectionTask(task);
            let mut path = parsed.path().to_string();
            if let Some(query) = parsed.query() {
                path.push('?');
                path.push_str(query);
            }
            let authority = parsed[url::Position::BeforeHost..url::Position::AfterPort].to_string();
            let request = hyper::Request::builder()
                .uri(path)
                .header("Host", authority)
                .header("Connection", "close")
                .header("User-Agent", "mtproto")
                .body(hyper::Body::empty())?;
            let mut response = sender.send_request(request).await?;
            if !response.status().is_success() {
                bail!("IP 探测返回 {}", response.status());
            }
            use hyper::body::HttpBody;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.body_mut().data().await {
                let chunk = chunk?;
                if bytes.len() + chunk.len() > 256 {
                    bail!("IP 探测响应过大");
                }
                bytes.extend_from_slice(&chunk);
            }
            let ip: IpAddr = std::str::from_utf8(&bytes)?.trim().parse()?;
            if ip.is_ipv6() != ipv6 {
                bail!("IP 探测返回了错误地址族");
            }
            Ok(ip)
        }
        .await;
        match attempt {
            Ok(ip) => return Ok(ip),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("端点无对应地址族")))
}
pub async fn discover_ip(ipv6: bool) -> Option<IpAddr> {
    let interfaces = net_interfaces();
    let mut candidates: Vec<_> = interfaces.iter().map(|name| Some(name.as_str())).collect();
    // Preserve device probing, with a default-route fallback for nonstandard
    // device names, systems without Linux, and unprivileged deployments.
    candidates.push(None);
    for interface in candidates {
        for url in [
            "http://ip.gs",
            "http://ip.sb",
            "http://ident.me",
            "http://ifconfig.me",
            "http://api.ipify.org",
            "http://icanhazip.com",
        ] {
            match timeout(Duration::from_secs(5), ip_from_url(url, interface, ipv6)).await {
                Ok(Ok(ip)) => return Some(ip),
                Ok(Err(error)) => tracing::debug!(?interface, ipv6, %error, "公网 IP 探测失败"),
                Err(_) => tracing::debug!(?interface, ipv6, "公网 IP 探测超时"),
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn python_interface_prefixes() {
        for name in ["eth0", "ens3", "enp0s8"] {
            assert!(interface_name(name));
        }
        for name in ["lo", "wlan0", "docker0"] {
            assert!(!interface_name(name));
        }
    }
    #[tokio::test]
    async fn device_bound_probe_uses_local_mock() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let remote = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let n = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..n]).starts_with("GET /ip?test=1 HTTP/1.1"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n203.0.113.1").await.unwrap();
        });
        #[cfg(target_os = "linux")]
        let interface = Some("lo");
        #[cfg(not(target_os = "linux"))]
        let interface = None;
        assert_eq!(
            timeout(
                Duration::from_secs(2),
                ip_from_url(&format!("http://{address}/ip?test=1"), interface, false)
            )
            .await
            .unwrap()
            .unwrap(),
            "203.0.113.1".parse::<IpAddr>().unwrap()
        );
        remote.await.unwrap();
    }
}
