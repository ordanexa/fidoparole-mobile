//! The serialized largeBlob array (CTAP 2.1 §6.10.3):
//! `CBOR array of entries || LEFT(SHA-256(array), 16)`.
//!
//! Each entry is `{1: ciphertext, 2: nonce(12), 3: origSize}`, encrypted with
//! AES-256-GCM under a credential's largeBlobKey over raw-DEFLATE-compressed
//! data, with AAD = "blob" || uint64LE(origSize). Entries of other credentials
//! (or other apps) are kept untouched.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ciborium::Value;
use flate2::{read::DeflateDecoder, write::DeflateEncoder, Compression};
use std::io::{Read, Write};
use zeroize::Zeroizing;

use super::cbor::{self, as_bytes, as_u64, get, imap, int};
use super::{pin::sha256, Error, R};

/// The array an authenticator starts with: an empty CBOR array + checksum.
pub fn empty() -> Vec<u8> {
    let mut v = vec![0x80];
    v.extend_from_slice(&sha256(&[0x80])[..16]);
    v
}

pub fn verify(serialized: &[u8]) -> R<()> {
    if serialized.len() < 17 { return Err(Error::Protocol("largeBlob array too short".into())); }
    let (body, sum) = serialized.split_at(serialized.len() - 16);
    if sha256(body)[..16] != *sum { return Err(Error::Protocol("largeBlob array checksum mismatch".into())); }
    Ok(())
}

pub fn entries(serialized: &[u8]) -> R<Vec<Value>> {
    verify(serialized)?;
    let body = &serialized[..serialized.len() - 16];
    match cbor::decode(body)? {
        Value::Array(a) => Ok(a),
        _ => Err(Error::Protocol("largeBlob array is not a CBOR array".into())),
    }
}

pub fn serialize(entries: &[Value]) -> Vec<u8> {
    let mut body = cbor::encode(&Value::Array(entries.to_vec()));
    let sum = sha256(&body);
    body.extend_from_slice(&sum[..16]);
    body
}

fn aad(orig: u64) -> Vec<u8> {
    let mut a = b"blob".to_vec();
    a.extend_from_slice(&orig.to_le_bytes());
    a
}

/// Decrypt an entry with `key`; None if it isn't ours (or is damaged).
pub fn open_entry(entry: &Value, key: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let ct = as_bytes(get(entry, 1))?;
    let nonce: [u8; 12] = as_bytes(get(entry, 2))?.try_into().ok()?;
    let orig = as_u64(get(entry, 3))?;
    let c = Aes256Gcm::new_from_slice(key).ok()?;
    let packed = Zeroizing::new(c.decrypt(&Nonce::from(nonce), Payload { msg: ct, aad: &aad(orig) }).ok()?);
    let mut out = Zeroizing::new(Vec::with_capacity(orig as usize));
    DeflateDecoder::new(&packed[..]).take(orig.min(1 << 20) + 1).read_to_end(&mut out).ok()?;
    (out.len() as u64 == orig).then_some(out)
}

pub fn seal_entry(data: &[u8], key: &[u8]) -> R<Value> {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
    enc.write_all(data).and_then(|_| Ok(())).map_err(|e| Error::Protocol(e.to_string()))?;
    let packed = Zeroizing::new(enc.finish().map_err(|e| Error::Protocol(e.to_string()))?);
    let mut nonce = [0u8; 12];
    rand::fill(&mut nonce[..]);
    let c = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Protocol("bad largeBlobKey".into()))?;
    let ct = c.encrypt(&Nonce::from(nonce), Payload { msg: &packed, aad: &aad(data.len() as u64) })
        .map_err(|_| Error::Protocol("largeBlob encryption failed".into()))?;
    Ok(imap(vec![(1, cbor::bytes(&ct)), (2, cbor::bytes(&nonce)), (3, int(data.len() as i64))]))
}

/// This credential's data in the array, if any.
pub fn find(serialized: &[u8], key: &[u8]) -> R<Option<Zeroizing<Vec<u8>>>> {
    Ok(entries(serialized)?.iter().find_map(|e| open_entry(e, key)))
}

/// A new array with this credential's entry replaced by `data` (or removed when None).
pub fn replace(serialized: &[u8], key: &[u8], data: Option<&[u8]>) -> R<Vec<u8>> {
    let mut list: Vec<Value> = entries(serialized)?.into_iter().filter(|e| open_entry(e, key).is_none()).collect();
    if let Some(d) = data { list.push(seal_entry(d, key)?); }
    Ok(serialize(&list))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_array_matches_spec() {
        // Initial value given in CTAP 2.1: 80 76be8b528d0075f7aae98d6fa57a6d3c
        assert_eq!(empty().iter().map(|b| format!("{b:02x}")).collect::<String>(), "8076be8b528d0075f7aae98d6fa57a6d3c");
    }

    #[test]
    fn replace_keeps_other_entries() {
        let a = replace(&empty(), &[1u8; 32], Some(b"first vault")).unwrap();
        let b = replace(&a, &[2u8; 32], Some(b"second vault")).unwrap();
        let c = replace(&b, &[1u8; 32], Some(b"first, updated")).unwrap();
        assert_eq!(&find(&c, &[1u8; 32]).unwrap().unwrap()[..], b"first, updated");
        assert_eq!(&find(&c, &[2u8; 32]).unwrap().unwrap()[..], b"second vault");
        let d = replace(&c, &[1u8; 32], None).unwrap();
        assert!(find(&d, &[1u8; 32]).unwrap().is_none());
        assert_eq!(entries(&d).unwrap().len(), 1);
    }
}
