//! Vault operations on a security key, on top of [`crate::ctap`].
//!
//! Same scheme as the desktop app (which uses libfido2): one discoverable
//! credential per vault under [`RP_ID`], credProtect level 3, hmac-secret with
//! the fixed [`vault::hmac_salt`] for the encryption secret, and the encrypted
//! vault in that credential's largeBlob entry.

use zeroize::Zeroizing;

use crate::ctap::{self, largeblob, perm, Auth, Device, Error, Transport, R};
use crate::vault;

/// Relying-party id of vault credentials. Part of the on-key format.
pub const RP_ID: &str = "fido2-vault.token2";
pub const RP_NAME: &str = "FidoParole";
/// Longest vault name (credential user name), in bytes.
pub const MAX_NAME_BYTES: usize = 32;

/// What the UI shows about a key before unlocking (no PIN needed).
#[derive(Clone, Debug, Default)]
pub struct KeyInfo {
    pub hmac_secret: bool,
    pub large_blob: bool,
    pub max_large_blob: u64,
    pub has_pin: bool,
    pub has_uv: bool,
    pub pin_retries: i32,
    pub aaguid: String,
    pub firmware: String,
    pub rk_remaining: i64,
}

impl KeyInfo {
    /// Why this key can't hold a vault, if it can't.
    pub fn problem(&self) -> Option<String> {
        if !self.hmac_secret || !self.large_blob {
            Some("This key lacks hmac-secret or largeBlob support, so it cannot hold a vault.".into())
        } else if !self.has_pin {
            Some("Set a FIDO2 PIN on this key first, with a FIDO2 management tool.".into())
        } else {
            None
        }
    }
}

pub fn key_info<T: Transport>(dev: &mut Device<T>) -> KeyInfo {
    let i = dev.info.clone();
    let pin_retries = if i.pin_set() { dev.pin_retries().map(|n| n as i32).unwrap_or(-1) } else { -1 };
    KeyInfo {
        hmac_secret: i.has_ext("hmac-secret"),
        large_blob: i.large_blobs() && i.max_large_blob > 0,
        max_large_blob: i.max_large_blob as u64,
        has_pin: i.pin_set(),
        has_uv: i.uv_ready(),
        pin_retries,
        aaguid: i.aaguid_string(),
        firmware: if i.firmware != 0 { format!("0x{:x}", i.firmware) } else { String::new() },
        rk_remaining: i.rk_remaining.map(|n| n as i64).unwrap_or(-1),
    }
}

/// A vault credential after a successful assertion. Secrets wiped on drop.
pub struct VaultCredential {
    pub cred_id: Vec<u8>,
    pub name: String,
    pub hmac_secret: Zeroizing<[u8; 32]>,
    pub large_blob_key: Zeroizing<Vec<u8>>,
}

/// Credentials found on a key with their (still encrypted) vault blobs.
pub struct Found {
    pub creds: Vec<(VaultCredential, Option<Vec<u8>>)>,
    /// Size of the key's whole largeBlob array, and its capacity.
    pub used: usize,
    pub max: usize,
}

fn to_vault_cred(a: ctap::Assertion) -> Option<VaultCredential> {
    // PIN or fingerprint was used, so the key must report user verification.
    if a.flags & 0x04 == 0 { return None; }
    let name = if a.user_name.is_empty() { vault::name_from_user_handle(&a.user_id).unwrap_or_default() } else { a.user_name };
    Some(VaultCredential { cred_id: a.cred_id, name, hmac_secret: a.hmac_secret?, large_blob_key: a.large_blob_key? })
}

fn check_vault_key<T: Transport>(dev: &Device<T>) -> R<()> {
    let i = &dev.info;
    if !i.has_ext("hmac-secret") || !i.large_blobs() {
        return Err(Error::Unsupported("this key lacks hmac-secret or largeBlob support, so it cannot hold a vault".into()));
    }
    Ok(())
}

/// Unlock: one assertion (PIN or fingerprint + touch), then one largeBlob read.
pub fn unlock<T: Transport>(dev: &mut Device<T>, auth: &Auth) -> R<Found> {
    check_vault_key(dev)?;
    let token = dev.token(auth, perm::GET_ASSERTION, Some(RP_ID))?;
    let found = dev.get_assertions(RP_ID, None, &vault::hmac_salt(), &token)?;
    let creds: Vec<VaultCredential> = found.into_iter().filter_map(to_vault_cred).collect();
    if creds.is_empty() {
        return Err(Error::Protocol("the key answered but returned no hmac-secret / largeBlob key".into()));
    }
    let array = dev.large_blob_read()?;
    let mut out = Vec::new();
    for c in creds {
        let blob = largeblob::find(&array, &c.large_blob_key)?.map(|b| b.to_vec());
        out.push((c, blob));
    }
    Ok(Found { creds: out, used: array.len(), max: dev.info.max_large_blob })
}

/// Write with a token, getting a fresh largeBlobWrite token if the first is refused.
fn write_array<T: Transport>(dev: &mut Device<T>, auth: &Auth, token: Option<ctap::pin::Token>, array: &[u8]) -> R<()> {
    if let Some(t) = token {
        match dev.large_blob_write(array, &t) {
            Err(Error::Ctap(ctap::ERR_PIN_AUTH_INVALID)) | Err(Error::Ctap(ctap::ERR_PUAT_REQUIRED)) => {}
            other => return other,
        }
    }
    let t = dev.token(auth, perm::LARGE_BLOB_WRITE, None)?;
    dev.large_blob_write(array, &t)
}

/// Create a vault credential and store `data` in it (two touches; with a
/// fingerprint, two fingerprint checks).
pub fn create<T: Transport>(dev: &mut Device<T>, auth: &Auth, name: &str, data: &vault::VaultData, exclude: &[Vec<u8>]) -> R<Found> {
    check_vault_key(dev)?;
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return Err(Error::Unsupported(format!("use a vault name of 1 to {MAX_NAME_BYTES} bytes")));
    }
    let t1 = dev.token(auth, perm::MAKE_CREDENTIAL, Some(RP_ID))?;
    let nc = dev.make_credential(RP_ID, RP_NAME, &vault::user_handle(name), name, Some(3), exclude, &t1)?;
    // Keep largeBlobWrite on the second token: after getAssertion the key
    // drops every permission except that one, so it can write the vault.
    let t2 = dev.token(auth, perm::GET_ASSERTION | perm::LARGE_BLOB_WRITE, Some(RP_ID))?;
    let a = dev.get_assertions(RP_ID, Some(&nc.cred_id), &vault::hmac_salt(), &t2)?;
    let mut cred = a.into_iter().find(|a| a.cred_id == nc.cred_id).and_then(to_vault_cred)
        .ok_or_else(|| Error::Protocol("the new vault credential did not return its secrets".into()))?;
    if cred.name.is_empty() { cred.name = name.to_string(); }
    let blob = vault::seal(data, &cred.hmac_secret).map_err(Error::Protocol)?;
    let array = largeblob::replace(&dev.large_blob_read()?, &cred.large_blob_key, Some(&blob))?;
    write_array(dev, auth, Some(t2), &array)?;
    Ok(Found { creds: vec![(cred, Some(blob))], used: array.len(), max: dev.info.max_large_blob })
}

/// Store a sealed vault blob; returns the new size of the key's largeBlob array.
pub fn write<T: Transport>(dev: &mut Device<T>, auth: &Auth, large_blob_key: &[u8], blob: &[u8]) -> R<usize> {
    let array = largeblob::replace(&dev.large_blob_read()?, large_blob_key, Some(blob))?;
    write_array(dev, auth, None, &array)?;
    Ok(array.len())
}

/// Remove the vault: its largeBlob entry, then the credential.
pub fn delete<T: Transport>(dev: &mut Device<T>, auth: &Auth, cred_id: &[u8], large_blob_key: &[u8]) -> R<()> {
    let array = largeblob::replace(&dev.large_blob_read()?, large_blob_key, None)?;
    write_array(dev, auth, None, &array)?;
    let t = dev.token(auth, perm::CRED_MGMT, None)?;
    dev.delete_credential(cred_id, &t)
}

/// Find an open vault again on a key (after the link was lost). The
/// hmac-secret must match the open vault's.
pub fn reconnect<T: Transport>(dev: &mut Device<T>, auth: &Auth, cred_id: &[u8], hmac_secret: &[u8; 32]) -> R<(VaultCredential, Option<Vec<u8>>, usize, usize)> {
    let token = dev.token(auth, perm::GET_ASSERTION, Some(RP_ID))?;
    let a = dev.get_assertions(RP_ID, Some(cred_id), &vault::hmac_salt(), &token).map_err(|e| match e {
        Error::Ctap(ctap::ERR_NO_CREDENTIALS) => Error::Unsupported("this vault is not on that key".into()),
        e => e,
    })?;
    let cred = a.into_iter().find(|a| a.cred_id == cred_id).and_then(to_vault_cred)
        .ok_or_else(|| Error::Unsupported("this vault is not on that key".into()))?;
    let diff = cred.hmac_secret.iter().zip(hmac_secret.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    if diff != 0 { return Err(Error::Unsupported("the key answered with a different secret for this vault".into())); }
    let array = dev.large_blob_read()?;
    let blob = largeblob::find(&array, &cred.large_blob_key)?.map(|b| b.to_vec());
    let max = dev.info.max_large_blob;
    Ok((cred, blob, array.len(), max))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap::hid::HidTransport;
    use crate::ctap::mock::{HidLoop, MockAuthenticator, NfcLoop};
    use crate::ctap::nfc::NfcTransport;
    use crate::vault::{Entry, VaultData};

    fn pin() -> Auth { Auth::Pin(Zeroizing::new("123456".into())) }

    fn sample(n: usize) -> VaultData {
        let mut v = VaultData::default();
        for i in 0..n {
            let mut e = Entry::new(&format!("Site {i}"));
            e.username = format!("user{i}@example.com");
            e.password = format!("pw-{i}-{}", "x".repeat(i % 7));
            e.url = format!("https://site{i}.example.org/login");
            v.entries.push(e);
        }
        v
    }

    fn device<T: Transport>(t: T) -> Device<T> {
        Device::open(t, Box::new(|_| {})).unwrap()
    }

    /// The full life of two vaults on one key.
    fn lifecycle<T: Transport>(dev: &mut Device<T>, big: usize) {
        let info = key_info(dev);
        assert!(info.problem().is_none(), "{:?}", info.problem());
        assert_eq!(info.pin_retries, 8);

        let data = sample(big);
        let f = create(dev, &pin(), "Personal", &data, &[]).unwrap();
        let (cred, blob) = &f.creds[0];
        assert_eq!(cred.name, "Personal");
        assert!(f.used > blob.as_ref().unwrap().len());

        // Unlock finds it and decrypts the same entries.
        let u = unlock(dev, &pin()).unwrap();
        assert_eq!(u.creds.len(), 1);
        let (c, b) = &u.creds[0];
        assert_eq!(c.cred_id, cred.cred_id);
        let opened = vault::open(b.as_ref().unwrap(), &c.hmac_secret).unwrap();
        assert_eq!(opened.entries.len(), big);
        assert_eq!(opened.entries[big - 1].password, data.entries[big - 1].password);

        // A second vault leaves the first one alone.
        create(dev, &pin(), "Work", &sample(2), &[]).unwrap();
        let u = unlock(dev, &pin()).unwrap();
        assert_eq!(u.creds.len(), 2);
        let names: Vec<_> = u.creds.iter().map(|(c, _)| c.name.clone()).collect();
        assert!(names.contains(&"Personal".to_string()) && names.contains(&"Work".to_string()));
        assert!(u.creds.iter().all(|(_, b)| b.is_some()));

        // Save an updated vault.
        let (pc, _) = u.creds.iter().find(|(c, _)| c.name == "Personal").unwrap();
        let mut more = opened.clone();
        more.entries.push(Entry::new("Added"));
        let sealed = vault::seal(&more, &pc.hmac_secret).unwrap();
        write(dev, &pin(), &pc.large_blob_key, &sealed).unwrap();
        let (pc2, b2, _, _) = reconnect(dev, &pin(), &pc.cred_id, &pc.hmac_secret).unwrap();
        assert_eq!(vault::open(&b2.unwrap(), &pc2.hmac_secret).unwrap().entries.len(), big + 1);

        // Reconnect refuses a vault with another secret.
        assert!(reconnect(dev, &pin(), &pc.cred_id, &[0u8; 32]).is_err());

        // Copy protection: excluding an existing credential is refused by the key.
        assert_eq!(create(dev, &pin(), "Again", &sample(1), &[pc.cred_id.clone()]).err(), Some(Error::Ctap(0x19)));

        // Delete removes credential and data; the other vault survives.
        delete(dev, &pin(), &pc.cred_id, &pc.large_blob_key).unwrap();
        let u = unlock(dev, &pin()).unwrap();
        assert_eq!(u.creds.len(), 1);
        assert_eq!(u.creds[0].0.name, "Work");
        assert!(reconnect(dev, &pin(), &pc.cred_id, &pc.hmac_secret).is_err());
    }

    #[test]
    fn vault_lifecycle_cbor() {
        let mut dev = device(MockAuthenticator::new(Some("123456")));
        lifecycle(&mut dev, 5);
        // PIN: create ×3 (2 touches each, one refused by exclusion = 1), unlocks, reconnects…
        assert!(dev.into_transport().touches > 6);
    }

    #[test]
    fn vault_lifecycle_usb_hid() {
        let hid = HidTransport::open(HidLoop::new(MockAuthenticator::new(Some("123456")))).unwrap();
        let touches = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let t2 = touches.clone();
        let mut dev = Device::open(hid, Box::new(move |e| {
            if e == crate::ctap::Event::TouchNeeded { t2.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
        })).unwrap();
        lifecycle(&mut dev, 30);
        // The HID keep-alive "touch needed" reached the callback.
        assert!(touches.load(std::sync::atomic::Ordering::Relaxed) > 0);
    }

    #[test]
    fn vault_lifecycle_nfc_with_fragments() {
        let mut auth = MockAuthenticator::new(Some("123456"));
        auth.max_msg_size = 300; // forces multi-fragment largeBlob reads and writes
        auth.max_large_blob = 8192;
        let nfc = NfcTransport::open(NfcLoop::new(auth)).unwrap();
        let mut dev = device(nfc);
        lifecycle(&mut dev, 40);
    }

    #[test]
    fn pin_protocol_one() {
        let mut auth = MockAuthenticator::new(Some("123456"));
        auth.protocols = vec![1];
        let mut dev = device(auth);
        lifecycle(&mut dev, 3);
    }

    #[test]
    fn wrong_pin_counts_down() {
        let mut dev = device(MockAuthenticator::new(Some("123456")));
        let bad = Auth::Pin(Zeroizing::new("000000".into()));
        assert_eq!(unlock(&mut dev, &bad).err(), Some(Error::Ctap(0x31)));
        assert_eq!(dev.pin_retries().unwrap(), 7);
        assert_eq!(create(&mut dev, &bad, "X", &sample(1), &[]).err(), Some(Error::Ctap(0x31)));
        assert_eq!(dev.pin_retries().unwrap(), 6);
        // A correct PIN resets the counter.
        create(&mut dev, &pin(), "X", &sample(1), &[]).unwrap();
        assert_eq!(dev.pin_retries().unwrap(), 8);
    }

    #[test]
    fn fingerprint_flow() {
        let mut auth = MockAuthenticator::new(Some("123456"));
        auth.uv_configured = true;
        let mut dev = device(auth);
        let f = create(&mut dev, &Auth::Uv, "Bio", &sample(4), &[]).unwrap();
        let u = unlock(&mut dev, &Auth::Uv).unwrap();
        assert_eq!(u.creds[0].0.cred_id, f.creds[0].0.cred_id);
        // The same vault opens with the PIN: both give the UV variant of hmac-secret.
        let u2 = unlock(&mut dev, &pin()).unwrap();
        assert_eq!(*u2.creds[0].0.hmac_secret, *u.creds[0].0.hmac_secret);
    }

    #[test]
    fn no_pin_set_is_explained() {
        let mut dev = device(MockAuthenticator::new(None));
        assert!(key_info(&mut dev).problem().unwrap().contains("PIN"));
        let e = unlock(&mut dev, &pin()).err().unwrap();
        assert!(e.to_string().contains("no FIDO PIN"), "{e}");
    }

    #[test]
    fn storage_full_is_reported() {
        let mut auth = MockAuthenticator::new(Some("123456"));
        auth.max_large_blob = 600;
        let mut dev = device(auth);
        let e = create(&mut dev, &pin(), "Big", &sample(60), &[]).err();
        assert_eq!(e, Some(Error::Ctap(0x18)));
    }
}
