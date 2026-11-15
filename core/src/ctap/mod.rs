//! A CTAP2 client in pure Rust, enough for FidoParole: getInfo, clientPIN
//! (PIN/UV auth protocols 1 and 2, tokens with permissions), makeCredential and
//! getAssertion with hmac-secret / largeBlobKey / credProtect, largeBlobs and
//! credential deletion.
//!
//! The platform supplies the bytes: [`hid::HidDevice`] for USB HID reports or
//! [`nfc::ApduChannel`] for ISO 7816 APDUs. Everything above the wire lives here,
//! so Android, iOS and the desktop share one implementation.

pub mod cbor;
pub mod hid;
pub mod largeblob;
pub mod nfc;
pub mod pin;
#[cfg(any(test, feature = "mock"))]
pub mod mock;

use ciborium::Value;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use cbor::{as_bool, as_bytes, as_i64, as_text, as_u64, get, get_t, imap, int, text, tmap};
use pin::{Protocol, Shared, Token};

pub type R<T> = Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The key answered with a CTAP status code.
    Ctap(u8),
    /// Talking to the key failed (USB/NFC).
    Transport(String),
    /// The key's answer made no sense.
    Protocol(String),
    Timeout,
    /// Something the key or the request doesn't allow (no PIN set, unsupported…).
    Unsupported(String),
}

pub const ERR_NO_CREDENTIALS: u8 = 0x2e;
pub const ERR_PIN_INVALID: u8 = 0x31;
pub const ERR_PIN_AUTH_INVALID: u8 = 0x33;
pub const ERR_PUAT_REQUIRED: u8 = 0x36;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Ctap(c) => f.write_str(&status_text(*c)),
            Error::Transport(s) | Error::Protocol(s) | Error::Unsupported(s) => f.write_str(s),
            Error::Timeout => f.write_str("timed out waiting for the key — touch it when it blinks"),
        }
    }
}

impl std::error::Error for Error {}

/// User-facing text for CTAP status codes (same wording as the desktop app).
pub fn status_text(c: u8) -> String {
    match c {
        0x11 => "the key rejected the request (invalid CBOR)".into(),
        0x12 => "the key rejected a parameter".into(),
        0x14 => "the key is missing a required parameter".into(),
        0x18 => "the key's largeBlob storage is full".into(),
        0x19 => "this vault already exists on the key".into(),
        0x26 => "the key does not support this option".into(),
        0x27 => "the key denied the operation".into(),
        0x28 => "the key has no room for another discoverable credential".into(),
        0x2b => "this key does not support a required option".into(),
        0x2c => "this key does not support a required option".into(),
        0x2d => "cancelled".into(),
        0x2e => "no vault was found on this key".into(),
        0x2f | 0x3a => "timed out waiting for the key — touch it when it blinks".into(),
        0x30 => "operation not allowed by the key".into(),
        0x31 => "wrong PIN".into(),
        0x32 => "PIN is blocked — the key must be reset".into(),
        0x33 => "the key rejected the PIN authentication".into(),
        0x34 => "PIN temporarily blocked — remove and reinsert the key".into(),
        0x35 => "no FIDO PIN is set on this key — set one first with a FIDO2 management tool".into(),
        0x36 => "a PIN is required for this operation".into(),
        0x37 => "the new PIN does not meet the key's rules".into(),
        0x38 => "the key's storage is full".into(),
        0x3b => "touch the key to confirm (user presence required)".into(),
        0x3c => "fingerprint verification is blocked — use the PIN".into(),
        0x3d => "the request does not match the key's integrity check".into(),
        0x3f => "user verification failed".into(),
        _ => format!("the key returned error 0x{c:02x}"),
    }
}

/// Progress reported while waiting for the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Processing,
    /// The key is blinking and waits for a touch (or a fingerprint).
    TouchNeeded,
}

/// A link to one authenticator: send a CTAP2 command, get the raw response
/// (status byte + CBOR).
pub trait Transport: Send {
    fn cbor(&mut self, cmd: u8, payload: &[u8], events: &mut dyn FnMut(Event)) -> R<Vec<u8>>;
}

impl Transport for Box<dyn Transport> {
    fn cbor(&mut self, cmd: u8, payload: &[u8], events: &mut dyn FnMut(Event)) -> R<Vec<u8>> {
        (**self).cbor(cmd, payload, events)
    }
}

pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CMD_GET_ASSERTION: u8 = 0x02;
pub const CMD_GET_INFO: u8 = 0x04;
pub const CMD_CLIENT_PIN: u8 = 0x06;
pub const CMD_GET_NEXT_ASSERTION: u8 = 0x08;
pub const CMD_CRED_MGMT: u8 = 0x0a;
pub const CMD_SELECTION: u8 = 0x0b;
pub const CMD_LARGE_BLOBS: u8 = 0x0c;
pub const CMD_CRED_MGMT_PREVIEW: u8 = 0x41;

/// pinUvAuthToken permissions.
pub mod perm {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const CRED_MGMT: u8 = 0x04;
    pub const LARGE_BLOB_WRITE: u8 = 0x10;
}

/// The parts of authenticatorGetInfo FidoParole uses.
#[derive(Clone, Debug, Default)]
pub struct Info {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub aaguid: Vec<u8>,
    pub options: BTreeMap<String, bool>,
    pub max_msg_size: usize,
    pub pin_protocols: Vec<u8>,
    pub max_large_blob: usize,
    pub firmware: u64,
    pub rk_remaining: Option<u64>,
}

impl Info {
    pub fn option(&self, name: &str) -> Option<bool> { self.options.get(name).copied() }
    pub fn has_ext(&self, name: &str) -> bool { self.extensions.iter().any(|e| e == name) }
    pub fn pin_set(&self) -> bool { self.option("clientPin") == Some(true) }
    /// Built-in user verification (fingerprint) configured and usable.
    pub fn uv_ready(&self) -> bool { self.option("uv") == Some(true) }
    pub fn tokens_with_permissions(&self) -> bool { self.option("pinUvAuthToken") == Some(true) }
    pub fn large_blobs(&self) -> bool { self.option("largeBlobs") == Some(true) && self.has_ext("largeBlobKey") }
    pub fn aaguid_string(&self) -> String {
        if self.aaguid.len() != 16 { return String::new(); }
        let h: String = self.aaguid.iter().map(|b| format!("{b:02x}")).collect();
        format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
    }

    fn parse(v: &Value) -> Info {
        let strs = |k| get(v, k).and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|s| s.as_text().map(String::from)).collect()).unwrap_or_default();
        let options = get(v, 4).and_then(|m| m.as_map()).map(|m| m.iter()
            .filter_map(|(k, v)| Some((k.as_text()?.to_string(), v.as_bool()?))).collect()).unwrap_or_default();
        Info {
            versions: strs(1),
            extensions: strs(2),
            aaguid: as_bytes(get(v, 3)).unwrap_or_default().to_vec(),
            options,
            max_msg_size: as_u64(get(v, 5)).unwrap_or(1024) as usize,
            pin_protocols: get(v, 6).and_then(|a| a.as_array()).map(|a| a.iter()
                .filter_map(|p| as_u64(Some(p)).map(|p| p as u8)).collect()).unwrap_or_default(),
            max_large_blob: as_u64(get(v, 0x0b)).unwrap_or(0) as usize,
            firmware: as_u64(get(v, 0x0e)).unwrap_or(0),
            rk_remaining: as_u64(get(v, 0x14)),
        }
    }
}

/// How the user proves who they are.
#[derive(Clone)]
pub enum Auth {
    Pin(Zeroizing<String>),
    /// Built-in user verification (fingerprint).
    Uv,
}

pub struct NewCredential {
    pub cred_id: Vec<u8>,
    pub large_blob_key: Option<Zeroizing<Vec<u8>>>,
}

pub struct Assertion {
    pub cred_id: Vec<u8>,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub hmac_secret: Option<Zeroizing<[u8; 32]>>,
    pub large_blob_key: Option<Zeroizing<Vec<u8>>>,
    /// Authenticator-data flags (0x01 user present, 0x04 user verified).
    pub flags: u8,
}

/// One open authenticator.
pub struct Device<T: Transport> {
    t: T,
    pub info: Info,
    events: Box<dyn FnMut(Event) + Send>,
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::fill(&mut b[..]);
    b
}

/// Parse authenticator data: (flags, extensions map, attested credential id).
fn parse_auth_data(ad: &[u8]) -> R<(u8, Option<Value>, Option<Vec<u8>>)> {
    if ad.len() < 37 { return Err(Error::Protocol("authenticator data too short".into())); }
    let flags = ad[32];
    let mut pos = 37;
    let mut cred_id = None;
    if flags & 0x40 != 0 {
        if ad.len() < pos + 18 { return Err(Error::Protocol("attested credential data truncated".into())); }
        pos += 16; // aaguid
        let n = u16::from_be_bytes([ad[pos], ad[pos + 1]]) as usize;
        pos += 2;
        if ad.len() < pos + n { return Err(Error::Protocol("credential id truncated".into())); }
        cred_id = Some(ad[pos..pos + n].to_vec());
        pos += n;
        let (_, used) = cbor::decode_prefix(&ad[pos..])?; // credential public key
        pos += used;
    }
    let ext = if flags & 0x80 != 0 { Some(cbor::decode_prefix(&ad[pos..])?.0) } else { None };
    Ok((flags, ext, cred_id))
}

impl<T: Transport> Device<T> {
    pub fn open(t: T, events: Box<dyn FnMut(Event) + Send>) -> R<Self> {
        let mut d = Device { t, info: Info::default(), events };
        let v = d.call(CMD_GET_INFO, None)?;
        d.info = Info::parse(&v);
        Ok(d)
    }

    /// Send a command; returns the decoded CBOR map (Null when empty).
    pub fn call(&mut self, cmd: u8, params: Option<&Value>) -> R<Value> {
        let payload = params.map(cbor::encode).unwrap_or_default();
        let resp = self.t.cbor(cmd, &payload, &mut *self.events)?;
        let (&status, body) = resp.split_first().ok_or_else(|| Error::Protocol("empty answer from the key".into()))?;
        if status != 0 { return Err(Error::Ctap(status)); }
        if body.is_empty() { Ok(Value::Null) } else { cbor::decode(body) }
    }

    fn protocol(&self) -> Protocol {
        if self.info.pin_protocols.contains(&2) { Protocol::Two } else { Protocol::One }
    }

    // ---------------------------------------------------------- clientPIN --

    pub fn pin_retries(&mut self) -> R<u32> {
        let p = self.protocol();
        let v = self.call(CMD_CLIENT_PIN, Some(&imap(vec![(1, int(p.id())), (2, int(1))])))?;
        as_u64(get(&v, 3)).map(|n| n as u32).ok_or_else(|| Error::Protocol("no PIN retry count".into()))
    }

    pub fn shared_secret(&mut self) -> R<Shared> {
        let p = self.protocol();
        let v = self.call(CMD_CLIENT_PIN, Some(&imap(vec![(1, int(p.id())), (2, int(2))])))?;
        let ka = get(&v, 1).ok_or_else(|| Error::Protocol("no key agreement key".into()))?;
        Shared::establish(p, ka)
    }

    /// Get a PIN/UV auth token for `permissions` (bound to `rp_id` for mc/ga).
    pub fn token(&mut self, auth: &Auth, permissions: u8, rp_id: Option<&str>) -> R<Token> {
        let shared = self.shared_secret()?;
        let p = shared.protocol;
        let modern = self.info.tokens_with_permissions();
        let mut params = vec![(1, int(p.id())), (3, shared.platform_key.clone())];
        match auth {
            Auth::Pin(pin) => {
                if !self.info.pin_set() {
                    return Err(Error::Unsupported("no FIDO PIN is set on this key — set one first with a FIDO2 management tool".into()));
                }
                params.push((2, int(if modern { 9 } else { 5 })));
                params.push((6, cbor::bytes(&shared.encrypt(&pin::pin_hash(pin))?)));
            }
            Auth::Uv => {
                if !(modern && self.info.uv_ready()) {
                    return Err(Error::Unsupported("this key has no fingerprint set up for this — use the PIN".into()));
                }
                params.push((2, int(6)));
            }
        }
        if modern {
            params.push((9, int(permissions as i64)));
            if let Some(rp) = rp_id { params.push((0x0a, text(rp))); }
        }
        let v = self.call(CMD_CLIENT_PIN, Some(&imap(params)))?;
        let enc = as_bytes(get(&v, 2)).ok_or_else(|| Error::Protocol("no PIN token in the answer".into()))?;
        let token = shared.decrypt(enc)?;
        if token.len() != 16 && token.len() != 32 { return Err(Error::Protocol("PIN token has a strange length".into())); }
        Ok(Token { protocol: p, token })
    }

    // ------------------------------------------------- credentials (mc/ga) --

    /// makeCredential: discoverable, credProtect, hmac-secret, largeBlobKey.
    #[allow(clippy::too_many_arguments)]
    pub fn make_credential(&mut self, rp_id: &str, rp_name: &str, user_id: &[u8], user_name: &str,
                           cred_protect: Option<u8>, exclude: &[Vec<u8>], token: &Token) -> R<NewCredential> {
        let cdh = random32();
        let mut ext = vec![("hmac-secret", cbor::bool(true))];
        if self.info.large_blobs() { ext.push(("largeBlobKey", cbor::bool(true))); }
        if let Some(cp) = cred_protect { ext.push(("credProtect", int(cp as i64))); }
        let mut params = vec![
            (1, cbor::bytes(&cdh)),
            (2, tmap(vec![("id", text(rp_id)), ("name", text(rp_name))])),
            (3, tmap(vec![("id", cbor::bytes(user_id)), ("name", text(user_name)), ("displayName", text(user_name))])),
            (4, Value::Array(vec![tmap(vec![("alg", int(-7)), ("type", text("public-key"))])])),
            (6, tmap(ext)),
            (7, tmap(vec![("rk", cbor::bool(true))])),
            (8, cbor::bytes(&token.authenticate(&cdh))),
            (9, int(token.protocol.id())),
        ];
        if !exclude.is_empty() {
            params.push((5, Value::Array(exclude.iter().map(|id| tmap(vec![("id", cbor::bytes(id)), ("type", text("public-key"))])).collect())));
        }
        let v = self.call(CMD_MAKE_CREDENTIAL, Some(&imap(params)))?;
        let ad = as_bytes(get(&v, 2)).ok_or_else(|| Error::Protocol("no authenticator data".into()))?;
        let (_, ext, cred_id) = parse_auth_data(ad)?;
        let cred_id = cred_id.ok_or_else(|| Error::Protocol("no credential id in the answer".into()))?;
        if ext.as_ref().and_then(|e| as_bool(get_t(e, "hmac-secret"))) != Some(true) {
            return Err(Error::Unsupported("the key did not enable hmac-secret for the vault credential".into()));
        }
        let large_blob_key = as_bytes(get(&v, 5)).map(|b| Zeroizing::new(b.to_vec()));
        Ok(NewCredential { cred_id, large_blob_key })
    }

    /// getAssertion with an hmac-secret salt (+ largeBlobKey). Returns every
    /// matching credential (getNextAssertion for discoverable ones).
    pub fn get_assertions(&mut self, rp_id: &str, allow: Option<&[u8]>, salt: &[u8; 32], token: &Token) -> R<Vec<Assertion>> {
        let cdh = random32();
        let shared = self.shared_secret()?;
        let salt_enc = shared.encrypt(salt)?;
        let mut hs = vec![(1, shared.platform_key.clone()), (2, cbor::bytes(&salt_enc)), (3, cbor::bytes(&shared.authenticate(&salt_enc)))];
        if shared.protocol == Protocol::Two { hs.push((4, int(2))); }
        let mut ext = vec![("hmac-secret", imap(hs))];
        if self.info.large_blobs() { ext.push(("largeBlobKey", cbor::bool(true))); }
        let mut params = vec![
            (1, text(rp_id)),
            (2, cbor::bytes(&cdh)),
            (4, tmap(ext)),
            (6, cbor::bytes(&token.authenticate(&cdh))),
            (7, int(token.protocol.id())),
        ];
        if let Some(id) = allow {
            params.push((3, Value::Array(vec![tmap(vec![("id", cbor::bytes(id)), ("type", text("public-key"))])])));
        }
        let first = self.call(CMD_GET_ASSERTION, Some(&imap(params)))?;
        let count = as_u64(get(&first, 5)).unwrap_or(1).max(1);
        if count > 64 { return Err(Error::Protocol("the key reported an implausible number of credentials".into())); }
        let mut out = vec![self.parse_assertion(&first, &shared, rp_id)?];
        for _ in 1..count {
            let v = self.call(CMD_GET_NEXT_ASSERTION, None)?;
            out.push(self.parse_assertion(&v, &shared, rp_id)?);
        }
        Ok(out)
    }

    fn parse_assertion(&self, v: &Value, shared: &Shared, rp_id: &str) -> R<Assertion> {
        let cred_id = get(v, 1).and_then(|c| as_bytes(get_t(c, "id"))).unwrap_or_default().to_vec();
        let ad = as_bytes(get(v, 2)).ok_or_else(|| Error::Protocol("no authenticator data".into()))?;
        let (flags, ext, _) = parse_auth_data(ad)?;
        // The answer must be for our RP and the user must have touched the key.
        if ad[..32] != pin::sha256(rp_id.as_bytes()) {
            return Err(Error::Protocol("the key answered for a different site (RP id hash mismatch)".into()));
        }
        if flags & 0x01 == 0 {
            return Err(Error::Protocol("the key answered without a touch (user-present flag missing)".into()));
        }
        let hmac_secret = match ext.as_ref().and_then(|e| as_bytes(get_t(e, "hmac-secret"))) {
            Some(enc) => {
                let out = shared.decrypt(enc)?;
                if out.len() < 32 { return Err(Error::Protocol("hmac-secret output too short".into())); }
                let mut h = Zeroizing::new([0u8; 32]);
                h.copy_from_slice(&out[..32]);
                Some(h)
            }
            None => None,
        };
        let user = get(v, 4);
        Ok(Assertion {
            cred_id,
            user_id: user.and_then(|u| as_bytes(get_t(u, "id"))).unwrap_or_default().to_vec(),
            user_name: user.and_then(|u| as_text(get_t(u, "name"))).unwrap_or_default().to_string(),
            hmac_secret,
            large_blob_key: as_bytes(get(v, 7)).map(|b| Zeroizing::new(b.to_vec())),
            flags,
        })
    }

    // -------------------------------------------------------- largeBlobs --

    fn max_fragment(&self) -> usize {
        self.info.max_msg_size.saturating_sub(64).max(64)
    }

    /// Read the whole serialized largeBlob array (checksum verified).
    pub fn large_blob_read(&mut self) -> R<Vec<u8>> {
        let frag = self.max_fragment();
        let mut out = Vec::new();
        loop {
            let v = self.call(CMD_LARGE_BLOBS, Some(&imap(vec![(1, int(frag as i64)), (3, int(out.len() as i64))])))?;
            let part = as_bytes(get(&v, 1)).ok_or_else(|| Error::Protocol("largeBlobs: no data".into()))?;
            out.extend_from_slice(part);
            if part.len() < frag { break; }
            if out.len() > 1 << 20 { return Err(Error::Protocol("largeBlobs: array too large".into())); }
        }
        largeblob::verify(&out)?;
        Ok(out)
    }

    /// Replace the serialized largeBlob array. Needs a token with largeBlobWrite.
    pub fn large_blob_write(&mut self, serialized: &[u8], token: &Token) -> R<()> {
        if self.info.max_large_blob > 0 && serialized.len() > self.info.max_large_blob {
            return Err(Error::Ctap(0x18));
        }
        let frag = self.max_fragment();
        let mut offset = 0usize;
        while offset < serialized.len() {
            let chunk = &serialized[offset..(offset + frag).min(serialized.len())];
            // pinUvAuthParam over 32×0xff || 0x0c 0x00 || uint32LE(offset) || SHA-256(chunk)
            let mut msg = vec![0xffu8; 32];
            msg.extend_from_slice(&[0x0c, 0x00]);
            msg.extend_from_slice(&(offset as u32).to_le_bytes());
            msg.extend_from_slice(&pin::sha256(chunk));
            let mut params = vec![
                (2, cbor::bytes(chunk)),
                (3, int(offset as i64)),
                (5, cbor::bytes(&token.authenticate(&msg))),
                (6, int(token.protocol.id())),
            ];
            if offset == 0 { params.push((4, int(serialized.len() as i64))); }
            self.call(CMD_LARGE_BLOBS, Some(&imap(params)))?;
            offset += chunk.len();
        }
        Ok(())
    }

    // ----------------------------------------------- credential management --

    /// Delete a discoverable credential. Needs a token with credMgmt.
    pub fn delete_credential(&mut self, cred_id: &[u8], token: &Token) -> R<()> {
        let cmd = if self.info.option("credMgmt") == Some(true) { CMD_CRED_MGMT }
                  else if self.info.option("credentialMgmtPreview") == Some(true) { CMD_CRED_MGMT_PREVIEW }
                  else { return Err(Error::Unsupported("this key cannot delete credentials".into())) };
        let sub_params = imap(vec![(2, tmap(vec![("id", cbor::bytes(cred_id)), ("type", text("public-key"))]))]);
        let mut msg = vec![0x06u8];
        msg.extend(cbor::encode(&sub_params));
        self.call(cmd, Some(&imap(vec![
            (1, int(6)),
            (2, sub_params),
            (3, int(token.protocol.id())),
            (4, cbor::bytes(&token.authenticate(&msg))),
        ])))?;
        Ok(())
    }

    /// authenticatorSelection: blink and wait for a touch (CTAP 2.1).
    pub fn selection(&mut self) -> R<()> {
        self.call(CMD_SELECTION, None).map(|_| ())
    }

    pub fn into_transport(self) -> T { self.t }
}

#[allow(dead_code)]
fn _assert_send<T: Transport>(d: Device<T>) -> impl Send { d }

/// Bytes of a CBOR integer (for diagnostics).
pub fn int_of(v: &Value) -> Option<i64> { as_i64(Some(v)) }
