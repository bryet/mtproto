use crate::crypto::Crypto;
use socket2::{SockRef, Socket};
use std::{collections::VecDeque, io, net::Shutdown, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub type RawRead = Box<dyn AsyncRead + Unpin + Send>;
pub type RawWrite = Box<dyn AsyncWrite + Unpin + Send>;
pub struct Reader {
    pub raw: RawRead,
    pub crypto: Crypto,
    pub tls: bool,
    buffer: VecDeque<u8>,
}
pub struct TcpControl(Socket);
impl TcpControl {
    pub fn new(stream: &tokio::net::TcpStream) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self(SockRef::from(stream).try_clone()?)))
    }
    pub fn reset_on_close(&self) -> io::Result<()> {
        self.0.set_linger(Some(Duration::ZERO))
    }
    pub fn shutdown_write(&self) -> io::Result<()> {
        self.0.shutdown(Shutdown::Write)
    }
    pub fn set_buffers(&self, size: usize) {
        let _ = self.0.set_recv_buffer_size(size);
        let _ = self.0.set_send_buffer_size(size);
    }
}
pub struct Writer {
    pub raw: RawWrite,
    pub crypto: Crypto,
    pub tls: bool,
    pub tcp: Option<Arc<TcpControl>>,
}
pub fn split<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(stream: S) -> (Reader, Writer) {
    let (r, w) = tokio::io::split(stream);
    (
        Reader {
            raw: Box::new(r),
            crypto: Crypto::Plain,
            tls: false,
            buffer: VecDeque::new(),
        },
        Writer {
            raw: Box::new(w),
            crypto: Crypto::Plain,
            tls: false,
            tcp: None,
        },
    )
}
pub fn split_tcp(stream: tokio::net::TcpStream) -> io::Result<(Reader, Writer)> {
    let tcp = TcpControl::new(&stream)?;
    let (reader, mut writer) = split(stream);
    writer.tcp = Some(tcp);
    Ok((reader, writer))
}
pub fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
impl Reader {
    pub fn install_crypto(&mut self, mut crypto: Crypto) {
        // Fake-TLS may put the obfuscated header and payload in one record.
        // Bytes buffered while reading that header still need the new cipher.
        let mut pending: Vec<u8> = self.buffer.drain(..).collect();
        crypto.apply(&mut pending);
        self.buffer.extend(pending);
        self.crypto = crypto;
    }
    pub fn take_buffer(&mut self) -> Vec<u8> {
        self.buffer.drain(..).collect()
    }
    async fn fill(&mut self, n: usize) -> io::Result<bool> {
        let mut data;
        if self.tls {
            loop {
                let mut header = [0u8; 5];
                match self.raw.read_exact(&mut header).await {
                    Ok(_) => (),
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
                    Err(e) => return Err(e),
                }
                if ![0x14, 0x17].contains(&header[0]) || header[1..3] != [3, 3] {
                    return Err(invalid("bad Fake-TLS record"));
                }
                let len = u16::from_be_bytes(header[3..5].try_into().unwrap()) as usize;
                data = vec![0; len];
                self.raw.read_exact(&mut data).await?;
                if header[0] == 0x14 || len == 0 {
                    continue;
                }
                break;
            }
        } else {
            let block = self.crypto.block_size();
            data = vec![0; n.max(block)];
            let read = self.raw.read(&mut data).await?;
            if read == 0 {
                return Ok(false);
            }
            data.truncate(read);
            let extra = (block - read % block) % block;
            if extra > 0 {
                data.resize(read + extra, 0);
                self.raw.read_exact(&mut data[read..]).await?;
            }
        }
        if data.len() % self.crypto.block_size() != 0 {
            return Err(invalid("unaligned ciphertext"));
        }
        self.crypto.apply(&mut data);
        self.buffer.extend(data);
        Ok(true)
    }
    pub async fn exact(&mut self, n: usize) -> io::Result<Vec<u8>> {
        while self.buffer.len() < n {
            if !self.fill(n - self.buffer.len()).await? {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        Ok(self.buffer.drain(..n).collect())
    }
    pub async fn chunk(&mut self, n: usize) -> io::Result<Vec<u8>> {
        if self.buffer.is_empty() && !self.fill(n).await? {
            return Ok(Vec::new());
        }
        let count = n.min(self.buffer.len());
        Ok(self.buffer.drain(..count).collect())
    }
}
impl Writer {
    pub async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        if data.len() % self.crypto.block_size() != 0 {
            return Err(invalid("unaligned plaintext"));
        }
        let mut data = data.to_vec();
        self.crypto.apply(&mut data);
        if self.tls {
            for part in data.chunks(16384 + 24) {
                let len = (part.len() as u16).to_be_bytes();
                self.raw.write_all(&[0x17, 3, 3, len[0], len[1]]).await?;
                self.raw.write_all(part).await?;
            }
        } else {
            self.raw.write_all(&data).await?;
        }
        self.raw.flush().await
    }
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.raw.shutdown().await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn tcp_control_requests_reset_and_shutdown() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let control = TcpControl::new(&server).unwrap();
        control.reset_on_close().unwrap();
        assert_eq!(
            SockRef::from(&server).linger().unwrap(),
            Some(Duration::ZERO)
        );
        control.shutdown_write().unwrap();
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
    }
    #[tokio::test]
    async fn tls_fragmented_exact_and_chunks() {
        let (a, b) = tokio::io::duplex(64);
        let (mut r, _) = split(a);
        let (_, mut w) = split(b);
        r.tls = true;
        w.tls = true;
        r.crypto = Crypto::ctr(&[7; 32], &[9; 16]);
        w.crypto = Crypto::ctr(&[7; 32], &[9; 16]);
        let task = tokio::spawn(async move {
            w.write(b"a").await.unwrap();
            w.write(b"bcdef").await.unwrap();
            w.shutdown().await.unwrap();
        });
        assert_eq!(r.exact(4).await.unwrap(), b"abcd");
        assert_eq!(r.chunk(1).await.unwrap(), b"e");
        assert_eq!(r.exact(1).await.unwrap(), b"f");
        assert!(r.chunk(1).await.unwrap().is_empty());
        task.await.unwrap();
    }
    #[tokio::test]
    async fn cbc_buffer_preserves_padding() {
        let (a, b) = tokio::io::duplex(64);
        let (mut r, _) = split(a);
        let (_, mut w) = split(b);
        r.crypto = Crypto::cbc(&[1; 32], &[2; 16], true);
        w.crypto = Crypto::cbc(&[1; 32], &[2; 16], false);
        w.write(&[3; 32]).await.unwrap();
        assert_eq!(r.exact(4).await.unwrap(), vec![3; 4]);
        assert_eq!(r.exact(28).await.unwrap(), vec![3; 28]);
    }
}
