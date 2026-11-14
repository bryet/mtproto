use crate::{
    crypto,
    wire::{invalid, Reader, Writer},
};
use std::{io, net::SocketAddr};

pub const MAX_MESSAGE: usize = 1 << 24;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Abridged,
    Intermediate,
    Secure,
}
impl Protocol {
    pub fn tag(self) -> [u8; 4] {
        [match self {
            Self::Abridged => 0xef,
            Self::Intermediate => 0xee,
            Self::Secure => 0xdd,
        }; 4]
    }
    pub fn from_tag(tag: &[u8]) -> Option<Self> {
        match tag {
            [0xef, 0xef, 0xef, 0xef] => Some(Self::Abridged),
            [0xee, 0xee, 0xee, 0xee] => Some(Self::Intermediate),
            [0xdd, 0xdd, 0xdd, 0xdd] => Some(Self::Secure),
            _ => None,
        }
    }
}
#[derive(Default, Debug)]
pub struct Packet {
    pub data: Vec<u8>,
    pub quickack: bool,
    pub simple_ack: bool,
    pub skip: bool,
}
pub async fn read_client(reader: &mut Reader, protocol: Protocol) -> io::Result<Packet> {
    let (len, quickack) = if protocol == Protocol::Abridged {
        let byte = reader.exact(1).await?[0];
        let mut words = (byte & 0x7f) as usize;
        if words == 0x7f {
            let bytes = reader.exact(3).await?;
            words = usize::from(bytes[0])
                | (usize::from(bytes[1]) << 8)
                | (usize::from(bytes[2]) << 16);
        }
        (words * 4, byte & 0x80 != 0)
    } else {
        let length = u32::from_le_bytes(reader.exact(4).await?.try_into().unwrap());
        ((length & 0x7fffffff) as usize, length & 0x80000000 != 0)
    };
    if len == 0 || len > MAX_MESSAGE {
        return Err(invalid("bad client frame length"));
    }
    if protocol != Protocol::Secure && len % 4 != 0 {
        return Err(invalid("unaligned client frame"));
    }
    let mut data = reader.exact(len).await?;
    if protocol == Protocol::Secure {
        data.truncate(len - len % 4);
    }
    Ok(Packet {
        data,
        quickack,
        ..Default::default()
    })
}
pub fn encode_client(protocol: Protocol, packet: &Packet) -> io::Result<Vec<u8>> {
    if packet.simple_ack {
        if packet.data.len() != 4 {
            return Err(invalid("bad quickack"));
        }
        let mut data = packet.data.clone();
        if protocol == Protocol::Abridged {
            data.reverse();
        }
        return Ok(data);
    }
    let len = packet.data.len();
    if len > MAX_MESSAGE || len % 4 != 0 {
        return Err(invalid("bad upstream frame length"));
    }
    let mut out = Vec::with_capacity(len + 8);
    match protocol {
        Protocol::Abridged => {
            let words = len / 4;
            if words < 0x7f {
                out.push(words as u8);
            } else {
                out.push(0x7f);
                out.extend_from_slice(&(words as u32).to_le_bytes()[..3]);
            }
            out.extend_from_slice(&packet.data);
        }
        Protocol::Intermediate => {
            out.extend_from_slice(&(len as u32).to_le_bytes());
            out.extend_from_slice(&packet.data);
        }
        Protocol::Secure => {
            let padding = crypto::random_range(0..4);
            out.extend_from_slice(&((len + padding) as u32).to_le_bytes());
            out.extend_from_slice(&packet.data);
            out.extend_from_slice(&crypto::random_vec(padding));
        }
    }
    Ok(out)
}
pub struct FrameReader {
    pub reader: Reader,
    pub sequence: i32,
}
pub struct FrameWriter {
    pub writer: Writer,
    pub sequence: i32,
}
impl FrameReader {
    pub async fn read(&mut self) -> io::Result<Vec<u8>> {
        let len_bytes = loop {
            let b = self.reader.exact(4).await?;
            if b != [4, 0, 0, 0] {
                break b;
            }
        };
        let len = u32::from_le_bytes(len_bytes.as_slice().try_into().unwrap()) as usize;
        if !(12..=MAX_MESSAGE).contains(&len) || len % 4 != 0 {
            return Err(invalid("bad RPC frame length"));
        }
        let seq = self.reader.exact(4).await?;
        if i32::from_le_bytes(seq.as_slice().try_into().unwrap()) != self.sequence {
            return Err(invalid("bad RPC sequence"));
        }
        self.sequence = self.sequence.wrapping_add(1);
        let data = self.reader.exact(len - 12).await?;
        let checksum = u32::from_le_bytes(self.reader.exact(4).await?.try_into().unwrap());
        let mut hash = crc32fast::Hasher::new();
        hash.update(&len_bytes);
        hash.update(&seq);
        hash.update(&data);
        if hash.finalize() != checksum {
            return Err(invalid("bad RPC checksum"));
        }
        Ok(data)
    }
}
impl FrameWriter {
    pub async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let out = encode_frame(data, self.sequence)?;
        self.sequence = self.sequence.wrapping_add(1);
        self.writer.write(&out).await
    }
}
pub fn encode_frame(data: &[u8], sequence: i32) -> io::Result<Vec<u8>> {
    if data.len() + 12 > MAX_MESSAGE || data.len() % 4 != 0 {
        return Err(invalid("bad RPC output length"));
    }
    let mut out = Vec::with_capacity(data.len() + 28);
    out.extend_from_slice(&((data.len() + 12) as u32).to_le_bytes());
    out.extend_from_slice(&sequence.to_le_bytes());
    out.extend_from_slice(data);
    let checksum = crc32fast::hash(&out);
    out.extend_from_slice(&checksum.to_le_bytes());
    while out.len() % 16 != 0 {
        out.extend_from_slice(&[4, 0, 0, 0]);
    }
    Ok(out)
}
fn address_bytes(addr: SocketAddr) -> Vec<u8> {
    let mut bytes = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped().octets().to_vec(),
        std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    bytes.extend_from_slice(&u32::from(addr.port()).to_le_bytes());
    bytes
}
pub struct ProxyRequest {
    prefix: Vec<u8>,
    pub connection_id: [u8; 8],
    protocol: Protocol,
    tag: Option<[u8; 16]>,
}
impl ProxyRequest {
    pub fn new(
        client: SocketAddr,
        ours: SocketAddr,
        protocol: Protocol,
        tag: Option<[u8; 16]>,
    ) -> Self {
        let mut prefix = address_bytes(client);
        prefix.extend_from_slice(&address_bytes(ours));
        Self {
            prefix,
            connection_id: crypto::random(),
            protocol,
            tag,
        }
    }
    pub fn encode(&self, packet: &Packet) -> io::Result<Vec<u8>> {
        self.encode_with_tag(packet, self.tag)
    }
    pub fn encode_with_tag(&self, packet: &Packet, tag: Option<[u8; 16]>) -> io::Result<Vec<u8>> {
        if packet.data.len() % 4 != 0 {
            return Err(invalid("unaligned proxy request"));
        }
        let mut flags: u32 = 0x1000 | 0x20000;
        flags |= match self.protocol {
            Protocol::Abridged => 0x40000000,
            Protocol::Intermediate => 0x20000000,
            Protocol::Secure => 0x20000000 | 0x8000000,
        };
        if packet.quickack {
            flags |= 0x80000000;
        }
        if packet.data.starts_with(&[0; 8]) {
            flags |= 2;
        }
        if tag.is_some() {
            flags |= 8;
        }
        let mut out = Vec::new();
        out.extend_from_slice(&[0xee, 0xf1, 0xce, 0x36]);
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&self.connection_id);
        out.extend_from_slice(&self.prefix);
        if let Some(tag) = tag {
            out.extend_from_slice(&[0x18, 0, 0, 0, 0xae, 0x26, 0x1e, 0xdb, 16]);
            out.extend_from_slice(&tag);
            out.extend_from_slice(&[0; 3]);
        }
        out.extend_from_slice(&packet.data);
        Ok(out)
    }
    pub fn decode(&self, data: Vec<u8>) -> io::Result<Packet> {
        if data.len() < 4 {
            return Err(invalid("short proxy answer"));
        }
        match &data[..4] {
            [0xa2, 0x34, 0xb6, 0x5e] => Ok(Packet::default()),
            [0x0d, 0xda, 0x03, 0x44] if data.len() >= 16 => {
                if data[8..16] != self.connection_id {
                    return Err(invalid("wrong proxy connection id"));
                }
                Ok(Packet {
                    data: data[16..].to_vec(),
                    ..Default::default()
                })
            }
            [0x9b, 0x40, 0xac, 0x3b] if data.len() == 16 => {
                if data[4..12] != self.connection_id {
                    return Err(invalid("wrong ack connection id"));
                }
                Ok(Packet {
                    data: data[12..16].to_vec(),
                    simple_ack: true,
                    ..Default::default()
                })
            }
            [0x0d, 0xda, 0x03, 0x44] | [0x9b, 0x40, 0xac, 0x3b] => {
                Err(invalid("truncated proxy answer"))
            }
            _ => Ok(Packet {
                skip: true,
                ..Default::default()
            }),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire;
    #[tokio::test]
    async fn rpc_frames_padding_and_sequence() {
        let (a, b) = tokio::io::duplex(256);
        let (r, _) = wire::split(a);
        let (_, w) = wire::split(b);
        let mut r = FrameReader {
            reader: r,
            sequence: -2,
        };
        let mut w = FrameWriter {
            writer: w,
            sequence: -2,
        };
        w.write(&[1; 32]).await.unwrap();
        w.write(&[2; 32]).await.unwrap();
        assert_eq!(r.read().await.unwrap(), [1; 32]);
        assert_eq!(r.read().await.unwrap(), [2; 32]);
    }
    #[tokio::test]
    async fn rejects_crc_and_oversized_frames() {
        let (a, b) = tokio::io::duplex(128);
        let (r, _) = wire::split(a);
        let (_, mut w) = wire::split(b);
        let mut bytes = encode_frame(&[0; 32], 0).unwrap();
        bytes[10] ^= 1;
        w.write(&bytes).await.unwrap();
        assert!(FrameReader {
            reader: r,
            sequence: 0
        }
        .read()
        .await
        .is_err());
        let (a, b) = tokio::io::duplex(32);
        let (mut r, _) = wire::split(a);
        let (_, mut w) = wire::split(b);
        w.write(&0x7fffffffu32.to_le_bytes()).await.unwrap();
        assert!(read_client(&mut r, Protocol::Secure).await.is_err());
    }
    #[tokio::test]
    async fn client_framing_and_padding() {
        for protocol in [Protocol::Abridged, Protocol::Intermediate, Protocol::Secure] {
            let (a, b) = tokio::io::duplex(4096);
            let (mut r, _) = wire::split(a);
            let (_, mut w) = wire::split(b);
            let packet = Packet {
                data: vec![7; 512],
                ..Default::default()
            };
            w.write(&encode_client(protocol, &packet).unwrap())
                .await
                .unwrap();
            assert_eq!(
                read_client(&mut r, protocol).await.unwrap().data,
                packet.data
            );
        }
    }
    #[test]
    fn proxy_ad_tag_flags_and_ack() {
        let req = ProxyRequest::new(
            "127.0.0.1:1234".parse().unwrap(),
            "[::1]:8443".parse().unwrap(),
            Protocol::Secure,
            Some([3; 16]),
        );
        let data = req
            .encode(&Packet {
                data: vec![0; 16],
                quickack: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(data[4..8].try_into().unwrap()),
            0xa802100a
        );
        assert_eq!(&data[65..81], &[3; 16]);
        let ack = Packet {
            data: vec![1, 2, 3, 4],
            simple_ack: true,
            ..Default::default()
        };
        assert_eq!(
            encode_client(Protocol::Abridged, &ack).unwrap(),
            [4, 3, 2, 1]
        );
    }
}
