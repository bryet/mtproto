use aes::Aes256;
use cipher::{
    generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher,
};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use rand::{rngs::OsRng, Rng, RngCore};
use sha2::{Digest, Sha256};

pub type AesCtr = ctr::Ctr128BE<Aes256>;
pub fn ctr(key: &[u8], iv: &[u8]) -> AesCtr {
    AesCtr::new_from_slices(key, iv).expect("AES-256 key/IV lengths")
}
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
pub fn hmac(secret: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().into()
}
pub fn verify_hmac_prefix(secret: &[u8], data: &[u8], digest: &[u8], prefix: usize) -> bool {
    let expected = hmac(secret, data);
    let mut difference = 0u8;
    for i in 0..prefix {
        difference |= expected[i] ^ digest[i];
    }
    difference == 0
}
pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
pub fn random_vec(n: usize) -> Vec<u8> {
    let mut bytes = vec![0; n];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
pub fn random_range(range: std::ops::Range<usize>) -> usize {
    OsRng.gen_range(range)
}
pub fn fake_public_key() -> [u8; 32] {
    // Match Python: quadratic residue modulo 2^255-19, not a real TLS exchange.
    let p = (BigUint::from(1u8) << 255) - BigUint::from(19u8);
    let n = loop {
        let n = BigUint::from_bytes_le(&random::<32>());
        if n < p {
            break n;
        }
    };
    let bytes = ((&n * &n) % p).to_bytes_le();
    let mut out = [0u8; 32];
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}
pub enum Crypto {
    Plain,
    Ctr(Box<AesCtr>),
    Cbc {
        aes: Box<Aes256>,
        iv: [u8; 16],
        decrypt: bool,
    },
}
impl Crypto {
    pub fn ctr(key: &[u8], iv: &[u8]) -> Self {
        Self::Ctr(Box::new(ctr(key, iv)))
    }
    pub fn cbc(key: &[u8], iv: &[u8], decrypt: bool) -> Self {
        Self::Cbc {
            aes: Box::new(Aes256::new_from_slice(key).unwrap()),
            iv: iv.try_into().unwrap(),
            decrypt,
        }
    }
    pub fn block_size(&self) -> usize {
        if matches!(self, Self::Cbc { .. }) {
            16
        } else {
            1
        }
    }
    pub fn apply(&mut self, data: &mut [u8]) {
        match self {
            Self::Plain => (),
            Self::Ctr(c) => c.apply_keystream(data),
            Self::Cbc { aes, iv, decrypt } => {
                assert_eq!(data.len() % 16, 0);
                for block in data.chunks_exact_mut(16) {
                    if *decrypt {
                        let next: [u8; 16] = block.try_into().unwrap();
                        aes.decrypt_block(GenericArray::from_mut_slice(block));
                        for (b, prev) in block.iter_mut().zip(iv.iter()) {
                            *b ^= prev;
                        }
                        *iv = next;
                    } else {
                        for (b, prev) in block.iter_mut().zip(iv.iter()) {
                            *b ^= prev;
                        }
                        aes.encrypt_block(GenericArray::from_mut_slice(block));
                        iv.copy_from_slice(block);
                    }
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nist_ctr_vector_and_stream_position() {
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap();
        let iv = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let mut data =
            hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
                .unwrap();
        let mut c = Crypto::ctr(&key, &iv);
        c.apply(&mut data[..7]);
        c.apply(&mut data[7..]);
        assert_eq!(
            hex::encode(data),
            "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
        );
    }
    #[test]
    fn nist_cbc_vector() {
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let original =
            hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
                .unwrap();
        let mut data = original.clone();
        Crypto::cbc(&key, &iv, false).apply(&mut data);
        assert_eq!(
            hex::encode(&data),
            "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
        );
        Crypto::cbc(&key, &iv, true).apply(&mut data);
        assert_eq!(data, original);
    }
}
