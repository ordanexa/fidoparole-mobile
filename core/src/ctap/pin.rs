//! PIN/UV auth protocols 1 and 2 (CTAP 2.1 §6.5.6, §6.5.7).
//!
//! A [`Shared`] secret is established with the authenticator's key-agreement
//! key (ECDH on P-256). It encrypts the PIN hash and the hmac-secret salts,
//! decrypts the returned token and hmac-secret output, and authenticates the
//! salts. The PIN/UV auth *token* then authenticates commands.

use aes::cipher::{block_padding::NoPadding, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use ciborium::Value;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::cbor::{self, get, imap, int};
use super::{Error, R};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    One = 1,
    Two = 2,
}

impl Protocol {
    pub fn id(self) -> i64 { self as i64 }
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::fill(&mut b[..]);
    b
}

fn cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], pt: &[u8]) -> R<Vec<u8>> {
    if pt.len() % 16 != 0 { return Err(Error::Protocol("PIN protocol: plaintext not block aligned".into())); }
    let mut buf = pt.to_vec();
    let n = buf.len();
    Aes256CbcEnc::new(key.into(), iv.into())
        .encrypt_padded::<NoPadding>(&mut buf, n)
        .map_err(|_| Error::Protocol("AES-CBC encryption failed".into()))?;
    Ok(buf)
}

fn cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], ct: &[u8]) -> R<Zeroizing<Vec<u8>>> {
    if ct.is_empty() || ct.len() % 16 != 0 { return Err(Error::Protocol("PIN protocol: ciphertext not block aligned".into())); }
    let mut buf = Zeroizing::new(ct.to_vec());
    Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded::<NoPadding>(&mut buf)
        .map_err(|_| Error::Protocol("AES-CBC decryption failed".into()))?;
    Ok(buf)
}

/// COSE_Key for an ECDH P-256 public key: {1: 2, 3: -25, -1: 1, -2: x, -3: y}.
pub fn cose_key(sec1: &[u8]) -> Value {
    imap(vec![(1, int(2)), (3, int(-25)), (-1, int(1)), (-2, cbor::bytes(&sec1[1..33])), (-3, cbor::bytes(&sec1[33..65]))])
}

/// Parse a COSE_Key (EC2, P-256) into an uncompressed SEC1 point.
pub fn cose_to_sec1(v: &Value) -> R<Vec<u8>> {
    let x = cbor::as_bytes(get(v, -2)).ok_or_else(|| Error::Protocol("key agreement: no x".into()))?;
    let y = cbor::as_bytes(get(v, -3)).ok_or_else(|| Error::Protocol("key agreement: no y".into()))?;
    if x.len() != 32 || y.len() != 32 { return Err(Error::Protocol("key agreement: bad coordinates".into())); }
    let mut p = vec![4u8];
    p.extend_from_slice(x);
    p.extend_from_slice(y);
    Ok(p)
}

/// The established shared secret, plus our public key to send along.
pub struct Shared {
    pub protocol: Protocol,
    /// Protocol 1: SHA-256(Z). Protocol 2: HMAC key (32) || AES key (32).
    secret: Zeroizing<Vec<u8>>,
    /// Our ephemeral public key as COSE_Key ("keyAgreement" in requests).
    pub platform_key: Value,
}

impl Shared {
    /// ECDH with the authenticator's key-agreement key (a COSE_Key).
    pub fn establish(protocol: Protocol, peer_cose: &Value) -> R<Shared> {
        let peer = p256::PublicKey::from_sec1_bytes(&cose_to_sec1(peer_cose)?)
            .map_err(|_| Error::Protocol("key agreement: the key's public key is not on P-256".into()))?;
        let sk = loop {
            let b = Zeroizing::new(random::<32>());
            if let Ok(k) = p256::SecretKey::from_slice(&b[..]) { break k; }
        };
        let platform_key = cose_key(&sk.public_key().to_sec1_bytes());
        let z = sk.diffie_hellman(&peer);
        Ok(Shared { protocol, secret: Self::kdf(protocol, z.raw_secret_bytes().as_slice()), platform_key })
    }

    /// KDF from the ECDH x-coordinate Z.
    pub fn kdf(protocol: Protocol, z: &[u8]) -> Zeroizing<Vec<u8>> {
        match protocol {
            Protocol::One => Zeroizing::new(sha256(z).to_vec()),
            Protocol::Two => {
                let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), z);
                let mut out = Zeroizing::new(vec![0u8; 64]);
                hk.expand(b"CTAP2 HMAC key", &mut out[..32]).expect("32 bytes is valid");
                hk.expand(b"CTAP2 AES key", &mut out[32..]).expect("32 bytes is valid");
                out
            }
        }
    }

    #[cfg(any(test, feature = "mock"))]
    pub fn from_secret(protocol: Protocol, secret: Vec<u8>) -> Shared {
        Shared { protocol, secret: Zeroizing::new(secret), platform_key: Value::Null }
    }

    fn aes_key(&self) -> [u8; 32] {
        let k = match self.protocol { Protocol::One => &self.secret[..32], Protocol::Two => &self.secret[32..64] };
        k.try_into().unwrap()
    }

    fn hmac_key(&self) -> &[u8] {
        &self.secret[..32]
    }

    pub fn encrypt(&self, pt: &[u8]) -> R<Vec<u8>> {
        match self.protocol {
            Protocol::One => cbc_encrypt(&self.aes_key(), &[0u8; 16], pt),
            Protocol::Two => {
                let iv = random::<16>();
                let mut out = iv.to_vec();
                out.extend(cbc_encrypt(&self.aes_key(), &iv, pt)?);
                Ok(out)
            }
        }
    }

    pub fn decrypt(&self, ct: &[u8]) -> R<Zeroizing<Vec<u8>>> {
        match self.protocol {
            Protocol::One => cbc_decrypt(&self.aes_key(), &[0u8; 16], ct),
            Protocol::Two => {
                if ct.len() < 32 { return Err(Error::Protocol("PIN protocol 2: ciphertext too short".into())); }
                let iv: [u8; 16] = ct[..16].try_into().unwrap();
                cbc_decrypt(&self.aes_key(), &iv, &ct[16..])
            }
        }
    }

    /// authenticate() keyed with the shared secret (used for hmac-secret saltAuth).
    pub fn authenticate(&self, msg: &[u8]) -> Vec<u8> {
        authenticate(self.protocol, self.hmac_key(), msg)
    }
}

/// authenticate(key, message): protocol 1 → first 16 bytes of HMAC-SHA-256,
/// protocol 2 → the full 32 bytes.
pub fn authenticate(protocol: Protocol, key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mac = hmac_sha256(key, msg);
    match protocol {
        Protocol::One => mac[..16].to_vec(),
        Protocol::Two => mac.to_vec(),
    }
}

/// A PIN/UV auth token obtained from the key.
pub struct Token {
    pub protocol: Protocol,
    pub token: Zeroizing<Vec<u8>>,
}

impl Token {
    pub fn authenticate(&self, msg: &[u8]) -> Vec<u8> {
        authenticate(self.protocol, &self.token, msg)
    }
}

/// LEFT(SHA-256(pin), 16), the value the authenticator compares.
pub fn pin_hash(pin: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(sha256(pin.as_bytes())[..16].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_roundtrips() {
        for p in [Protocol::One, Protocol::Two] {
            let s = Shared::from_secret(p, Shared::kdf(p, &[7u8; 32]).to_vec());
            let ct = s.encrypt(&[1u8; 32]).unwrap();
            assert_eq!(ct.len(), if p == Protocol::One { 32 } else { 48 });
            assert_eq!(&s.decrypt(&ct).unwrap()[..], &[1u8; 32]);
            assert_eq!(s.authenticate(b"x").len(), if p == Protocol::One { 16 } else { 32 });
        }
    }

    #[test]
    fn ecdh_agrees() {
        // Both sides derive the same secret.
        let auth_sk = p256::SecretKey::from_slice(&[9u8; 32]).unwrap();
        let auth_cose = cose_key(&auth_sk.public_key().to_sec1_bytes());
        let s = Shared::establish(Protocol::Two, &auth_cose).unwrap();
        let plat = p256::PublicKey::from_sec1_bytes(&cose_to_sec1(&s.platform_key).unwrap()).unwrap();
        let z = auth_sk.diffie_hellman(&plat);
        let other = Shared::from_secret(Protocol::Two, Shared::kdf(Protocol::Two, z.raw_secret_bytes().as_slice()).to_vec());
        assert_eq!(other.decrypt(&s.encrypt(&[5u8; 16]).unwrap()).unwrap().as_slice(), &[5u8; 16]);
    }
}
