//! A software authenticator implementing the subset of CTAP 2.1 FidoParole
//! uses, written from the spec. It lets the whole vault flow run in tests —
//! CBOR level ([`MockAuthenticator`] as a [`Transport`]) and through the real
//! USB HID and NFC framing ([`HidLoop`], [`NfcLoop`]).

use ciborium::Value;

use super::cbor::{self, as_bytes, as_text, as_u64, get, get_t, imap, int, text, tmap};
use super::hid::{HidDevice, REPORT};
use super::nfc::ApduChannel;
use super::pin::{self, authenticate, cose_key, cose_to_sec1, hmac_sha256, sha256, Protocol, Shared};
use super::{largeblob, perm, Error, Event, Transport, R};

pub struct MockCred {
    pub rp_id: String,
    pub id: Vec<u8>,
    pub user_id: Vec<u8>,
    pub user_name: String,
    cred_random_uv: [u8; 32],
    pub large_blob_key: [u8; 32],
    pub cred_protect: u8,
}

struct TokenState {
    token: [u8; 32],
    protocol: Protocol,
    permissions: u8,
    rp_id: Option<String>,
}

pub struct MockAuthenticator {
    pin_hash: Option<[u8; 16]>,
    pub pin_retries: u32,
    pub uv_configured: bool,
    ka: p256::SecretKey,
    token: Option<TokenState>,
    pub creds: Vec<MockCred>,
    pub large_blob: Vec<u8>,
    pending_blob: Option<(Vec<u8>, usize)>,
    pending_assertions: Vec<Value>,
    pub max_msg_size: usize,
    pub max_large_blob: usize,
    /// Number of user-presence checks (touches) so far.
    pub touches: u32,
    /// PIN/UV auth protocols advertised in getInfo.
    pub protocols: Vec<i64>,
}

fn rnd<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::fill(&mut b[..]);
    b
}

fn new_ka() -> p256::SecretKey {
    loop {
        if let Ok(k) = p256::SecretKey::from_slice(&rnd::<32>()) { return k; }
    }
}

type Res = Result<Value, u8>;

impl MockAuthenticator {
    pub fn new(pin: Option<&str>) -> Self {
        MockAuthenticator {
            pin_hash: pin.map(|p| sha256(p.as_bytes())[..16].try_into().unwrap()),
            pin_retries: 8,
            uv_configured: false,
            ka: new_ka(),
            token: None,
            creds: vec![],
            large_blob: largeblob::empty(),
            pending_blob: None,
            pending_assertions: vec![],
            max_msg_size: 1200,
            max_large_blob: 2048,
            touches: 0,
            protocols: vec![2, 1],
        }
    }

    fn shared_from(&self, platform_key: &Value, protocol: Protocol) -> Result<Shared, u8> {
        let peer = p256::PublicKey::from_sec1_bytes(&cose_to_sec1(platform_key).map_err(|_| 0x11u8)?).map_err(|_| 0x11u8)?;
        let z = self.ka.diffie_hellman(&peer);
        Ok(Shared::from_secret(protocol, Shared::kdf(protocol, z.raw_secret_bytes().as_slice()).to_vec()))
    }

    fn protocol_of(v: Option<&Value>) -> Result<Protocol, u8> {
        match as_u64(v) { Some(1) => Ok(Protocol::One), Some(2) => Ok(Protocol::Two), _ => Err(0x02) }
    }

    /// Check pinUvAuthParam against the current token; returns its permissions.
    fn verify(&self, param: Option<&Value>, protocol: Option<&Value>, msg: &[u8], need: u8, rp_id: Option<&str>) -> Result<(), u8> {
        let param = as_bytes(param).ok_or(0x36u8)?;
        let p = Self::protocol_of(protocol)?;
        let t = self.token.as_ref().ok_or(0x33u8)?;
        if t.protocol != p || authenticate(p, &t.token, msg) != param { return Err(0x33); }
        if t.permissions & need != need { return Err(0x33); }
        if let (Some(bound), Some(rp)) = (&t.rp_id, rp_id) { if bound != rp { return Err(0x33); } }
        Ok(())
    }

    fn keep_only_lbw(&mut self) {
        if let Some(t) = self.token.as_mut() { t.permissions &= perm::LARGE_BLOB_WRITE; }
    }

    fn info(&self) -> Res {
        Ok(imap(vec![
            (1, Value::Array(vec![text("FIDO_2_0"), text("FIDO_2_1")])),
            (2, Value::Array(vec![text("credProtect"), text("hmac-secret"), text("largeBlobKey")])),
            (3, cbor::bytes(&[0xab; 16])),
            (4, tmap(vec![
                ("rk", cbor::bool(true)), ("up", cbor::bool(true)), ("clientPin", cbor::bool(self.pin_hash.is_some())),
                ("uv", cbor::bool(self.uv_configured)), ("pinUvAuthToken", cbor::bool(true)),
                ("largeBlobs", cbor::bool(true)), ("credMgmt", cbor::bool(true)),
            ])),
            (5, int(self.max_msg_size as i64)),
            (6, Value::Array(self.protocols.iter().map(|p| int(*p)).collect())),
            (0x0b, int(self.max_large_blob as i64)),
            (0x0e, int(0x30300)),
            (0x14, int(25 - self.creds.len() as i64)),
        ]))
    }

    fn client_pin(&mut self, p: &Value) -> Res {
        let sub = as_u64(get(p, 2)).ok_or(0x14u8)?;
        match sub {
            1 => Ok(imap(vec![(3, int(self.pin_retries as i64))])),
            2 => Ok(imap(vec![(1, cose_key(&self.ka.public_key().to_sec1_bytes()))])),
            5 | 9 | 6 => {
                let proto = Self::protocol_of(get(p, 1))?;
                let shared = self.shared_from(get(p, 3).ok_or(0x14u8)?, proto)?;
                if sub == 6 {
                    if !self.uv_configured { return Err(0x2b); }
                    self.touches += 1; // fingerprint touch
                } else {
                    let stored = self.pin_hash.ok_or(0x35u8)?;
                    if self.pin_retries == 0 { return Err(0x32); }
                    let enc = as_bytes(get(p, 6)).ok_or(0x14u8)?;
                    let got = shared.decrypt(enc).map_err(|_| 0x31u8)?;
                    if got.as_slice() != stored {
                        self.pin_retries -= 1;
                        self.ka = new_ka(); // regenerate after a failure (spec)
                        return Err(if self.pin_retries == 0 { 0x32 } else { 0x31 });
                    }
                    self.pin_retries = 8;
                }
                let permissions = if sub == 5 { 0xff } else { as_u64(get(p, 9)).ok_or(0x14u8)? as u8 };
                if permissions == 0 { return Err(0x02); }
                let token = rnd::<32>();
                self.token = Some(TokenState { token, protocol: proto, permissions, rp_id: as_text(get(p, 0x0a)).map(String::from) });
                Ok(imap(vec![(2, cbor::bytes(&shared.encrypt(&token).map_err(|_| 0x7fu8)?))]))
            }
            _ => Err(0x02),
        }
    }

    fn auth_data(rp_id: &str, flags: u8, attested: Option<&[u8]>, ext: Option<Value>) -> Vec<u8> {
        let mut ad = sha256(rp_id.as_bytes()).to_vec();
        ad.push(flags | if ext.is_some() { 0x80 } else { 0 } | if attested.is_some() { 0x40 } else { 0 });
        ad.extend_from_slice(&1u32.to_be_bytes());
        if let Some(id) = attested {
            ad.extend_from_slice(&[0xab; 16]);
            ad.extend_from_slice(&(id.len() as u16).to_be_bytes());
            ad.extend_from_slice(id);
            ad.extend(cbor::encode(&imap(vec![(1, int(2)), (3, int(-7)), (-1, int(1)), (-2, cbor::bytes(&[1; 32])), (-3, cbor::bytes(&[2; 32]))])));
        }
        if let Some(e) = ext { ad.extend(cbor::encode(&e)); }
        ad
    }

    fn make_credential(&mut self, p: &Value) -> Res {
        let cdh = as_bytes(get(p, 1)).ok_or(0x14u8)?.to_vec();
        let rp_id = as_text(get(p, 2).and_then(|rp| get_t(rp, "id"))).ok_or(0x14u8)?.to_string();
        self.verify(get(p, 8), get(p, 9), &cdh, perm::MAKE_CREDENTIAL, Some(&rp_id))?;
        if let Some(Value::Array(ex)) = get(p, 5) {
            for d in ex {
                let id = as_bytes(get_t(d, "id")).unwrap_or_default();
                if self.creds.iter().any(|c| c.id == id) { self.touches += 1; return Err(0x19); }
            }
        }
        let user = get(p, 3).ok_or(0x14u8)?;
        let ext = get(p, 6);
        let cred_protect = ext.and_then(|e| as_u64(get_t(e, "credProtect"))).unwrap_or(1) as u8;
        let want_lbk = ext.and_then(|e| get_t(e, "largeBlobKey")).and_then(|v| v.as_bool()) == Some(true);
        let want_hs = ext.and_then(|e| get_t(e, "hmac-secret")).and_then(|v| v.as_bool()) == Some(true);
        self.touches += 1;
        let user_id = as_bytes(get_t(user, "id")).ok_or(0x14u8)?.to_vec();
        self.creds.retain(|c| !(c.rp_id == rp_id && c.user_id == user_id)); // same user replaces
        let id = rnd::<16>().to_vec();
        let cred = MockCred {
            rp_id: rp_id.clone(), id: id.clone(), user_id,
            user_name: as_text(get_t(user, "name")).unwrap_or_default().to_string(),
            cred_random_uv: rnd(), large_blob_key: rnd(), cred_protect,
        };
        let lbk = cred.large_blob_key;
        self.creds.push(cred);
        let mut out_ext = vec![];
        if cred_protect > 1 { out_ext.push(("credProtect", int(cred_protect as i64))); }
        if want_hs { out_ext.push(("hmac-secret", cbor::bool(true))); }
        let ad = Self::auth_data(&rp_id, 0x05, Some(&id), (!out_ext.is_empty()).then(|| tmap(out_ext)));
        self.keep_only_lbw();
        let mut resp = vec![(1, text("none")), (2, cbor::bytes(&ad)), (3, Value::Map(vec![]))];
        if want_lbk { resp.push((5, cbor::bytes(&lbk))); }
        Ok(imap(resp))
    }

    fn assertion_for(&self, idx: usize, hs: &Option<(Shared, Vec<u8>)>, total: Option<usize>, lbk: bool, rk: bool) -> Result<Value, u8> {
        let c = &self.creds[idx];
        let ext = match hs {
            Some((shared, salts)) => {
                let mut out = hmac_sha256(&c.cred_random_uv, &salts[..32]).to_vec();
                if salts.len() == 64 { out.extend(hmac_sha256(&c.cred_random_uv, &salts[32..])); }
                Some(tmap(vec![("hmac-secret", cbor::bytes(&shared.encrypt(&out).map_err(|_| 0x7fu8)?))]))
            }
            None => None,
        };
        let ad = Self::auth_data(&c.rp_id, 0x05, None, ext);
        let mut r = vec![
            (1, tmap(vec![("id", cbor::bytes(&c.id)), ("type", text("public-key"))])),
            (2, cbor::bytes(&ad)),
            (3, cbor::bytes(&[0x30; 70])),
        ];
        if rk { r.push((4, tmap(vec![("id", cbor::bytes(&c.user_id)), ("name", text(&c.user_name))]))); }
        if let Some(n) = total { r.push((5, int(n as i64))); }
        if lbk { r.push((7, cbor::bytes(&c.large_blob_key))); }
        Ok(imap(r))
    }

    fn get_assertion(&mut self, p: &Value) -> Res {
        let rp_id = as_text(get(p, 1)).ok_or(0x14u8)?.to_string();
        let cdh = as_bytes(get(p, 2)).ok_or(0x14u8)?.to_vec();
        self.verify(get(p, 6), get(p, 7), &cdh, perm::GET_ASSERTION, Some(&rp_id))?;
        let allow: Option<Vec<Vec<u8>>> = match get(p, 3) {
            Some(Value::Array(a)) => Some(a.iter().filter_map(|d| as_bytes(get_t(d, "id")).map(|b| b.to_vec())).collect()),
            _ => None,
        };
        // UV was done through the token, so credProtect 3 credentials are visible.
        let idx: Vec<usize> = self.creds.iter().enumerate()
            .filter(|(_, c)| c.rp_id == rp_id && allow.as_ref().map(|a| a.contains(&c.id)).unwrap_or(true))
            .map(|(i, _)| i).collect();
        self.touches += 1;
        if idx.is_empty() { return Err(0x2e); }
        let ext = get(p, 4);
        let lbk = ext.and_then(|e| get_t(e, "largeBlobKey")).and_then(|v| v.as_bool()) == Some(true);
        let hs = match ext.and_then(|e| get_t(e, "hmac-secret")) {
            Some(h) => {
                let proto = Self::protocol_of(get(h, 4).or(Some(&int(1))))?;
                let shared = self.shared_from(get(h, 1).ok_or(0x14u8)?, proto)?;
                let salt_enc = as_bytes(get(h, 2)).ok_or(0x14u8)?;
                if shared.authenticate(salt_enc) != as_bytes(get(h, 3)).ok_or(0x14u8)? { return Err(0x12); }
                let salts = shared.decrypt(salt_enc).map_err(|_| 0x12u8)?.to_vec();
                if salts.len() != 32 && salts.len() != 64 { return Err(0x12); }
                Some((shared, salts))
            }
            None => None,
        };
        let rk = allow.is_none();
        let total = (rk && idx.len() > 1).then_some(idx.len());
        let first = self.assertion_for(idx[0], &hs, total, lbk, rk)?;
        self.pending_assertions = idx[1..].iter().map(|&i| self.assertion_for(i, &hs, None, lbk, rk)).collect::<Result<_, _>>()?;
        self.pending_assertions.reverse();
        self.keep_only_lbw();
        Ok(first)
    }

    fn large_blobs(&mut self, p: &Value) -> Res {
        let offset = as_u64(get(p, 3)).ok_or(0x14u8)? as usize;
        if let Some(n) = as_u64(get(p, 1)) {
            let n = n as usize;
            if n > self.max_msg_size - 64 { return Err(0x03); }
            let end = (offset + n).min(self.large_blob.len());
            let part = if offset < self.large_blob.len() { &self.large_blob[offset..end] } else { &[][..] };
            return Ok(imap(vec![(1, cbor::bytes(part))]));
        }
        let chunk = as_bytes(get(p, 2)).ok_or(0x14u8)?.to_vec();
        let mut msg = vec![0xffu8; 32];
        msg.extend_from_slice(&[0x0c, 0x00]);
        msg.extend_from_slice(&(offset as u32).to_le_bytes());
        msg.extend_from_slice(&sha256(&chunk));
        self.verify(get(p, 5), get(p, 6), &msg, perm::LARGE_BLOB_WRITE, None)?;
        if offset == 0 {
            let total = as_u64(get(p, 4)).ok_or(0x14u8)? as usize;
            if total > self.max_large_blob { return Err(0x18); }
            if total < 17 { return Err(0x03); }
            self.pending_blob = Some((Vec::new(), total));
        }
        let (buf, total) = self.pending_blob.as_mut().ok_or(0x03u8)?;
        if buf.len() != offset { return Err(0x03); }
        buf.extend_from_slice(&chunk);
        if buf.len() > *total { return Err(0x03); }
        if buf.len() == *total {
            let done = std::mem::take(buf);
            self.pending_blob = None;
            if largeblob::verify(&done).is_err() { return Err(0x3d); }
            self.large_blob = done;
        }
        Ok(Value::Null)
    }

    fn cred_mgmt(&mut self, p: &Value) -> Res {
        let sub = as_u64(get(p, 1)).ok_or(0x14u8)?;
        if sub != 6 { return Err(0x02); }
        let params = get(p, 2).ok_or(0x14u8)?;
        let mut msg = vec![0x06u8];
        msg.extend(cbor::encode(params));
        self.verify(get(p, 4), get(p, 3), &msg, perm::CRED_MGMT, None)?;
        let id = as_bytes(get(params, 2).and_then(|d| get_t(d, "id"))).ok_or(0x14u8)?.to_vec();
        let before = self.creds.len();
        self.creds.retain(|c| c.id != id);
        if self.creds.len() == before { return Err(0x2e); }
        Ok(Value::Null)
    }

    /// Process one CTAP2 command; returns status byte + CBOR.
    pub fn process(&mut self, cmd: u8, payload: &[u8]) -> Vec<u8> {
        let params = if payload.is_empty() { Ok(Value::Null) } else { cbor::decode(payload).map_err(|_| 0x11u8) };
        let res = params.and_then(|p| match cmd {
            super::CMD_GET_INFO => self.info(),
            super::CMD_CLIENT_PIN => self.client_pin(&p),
            super::CMD_MAKE_CREDENTIAL => self.make_credential(&p),
            super::CMD_GET_ASSERTION => self.get_assertion(&p),
            super::CMD_GET_NEXT_ASSERTION => self.pending_assertions.pop().ok_or(0x30),
            super::CMD_LARGE_BLOBS => self.large_blobs(&p),
            super::CMD_CRED_MGMT => self.cred_mgmt(&p),
            super::CMD_SELECTION => { self.touches += 1; Ok(Value::Null) }
            _ => Err(0x01),
        });
        match res {
            Ok(Value::Null) => vec![0],
            Ok(v) => { let mut out = vec![0]; out.extend(cbor::encode(&v)); out }
            Err(code) => vec![code],
        }
    }
}

impl Transport for MockAuthenticator {
    fn cbor(&mut self, cmd: u8, payload: &[u8], _events: &mut dyn FnMut(Event)) -> R<Vec<u8>> {
        Ok(self.process(cmd, payload))
    }
}

/// The mock behind CTAPHID framing (64-byte reports), sending a keep-alive first.
pub struct HidLoop {
    pub auth: MockAuthenticator,
    inbox: Vec<u8>,
    expect: usize,
    cmd: u8,
    out: std::collections::VecDeque<Vec<u8>>,
    cid: u32,
}

impl HidLoop {
    pub fn new(auth: MockAuthenticator) -> Self {
        HidLoop { auth, inbox: vec![], expect: 0, cmd: 0, out: Default::default(), cid: 0x0102_0304 }
    }

    fn reply(&mut self, cid: u32, cmd: u8, data: &[u8]) {
        let mut rep = vec![0u8; REPORT];
        rep[..4].copy_from_slice(&cid.to_be_bytes());
        rep[4] = cmd;
        rep[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
        let n = data.len().min(REPORT - 7);
        rep[7..7 + n].copy_from_slice(&data[..n]);
        self.out.push_back(rep);
        let mut off = n;
        let mut seq = 0u8;
        while off < data.len() {
            let mut c = vec![0u8; REPORT];
            c[..4].copy_from_slice(&cid.to_be_bytes());
            c[4] = seq;
            let m = (data.len() - off).min(REPORT - 5);
            c[5..5 + m].copy_from_slice(&data[off..off + m]);
            self.out.push_back(c);
            off += m;
            seq += 1;
        }
    }
}

impl HidDevice for HidLoop {
    fn write_report(&mut self, r: &[u8]) -> R<()> {
        if r.len() != REPORT { return Err(Error::Transport("report must be 64 bytes".into())); }
        let cid = u32::from_be_bytes(r[..4].try_into().unwrap());
        if r[4] & 0x80 != 0 {
            self.cmd = r[4];
            self.expect = u16::from_be_bytes([r[5], r[6]]) as usize;
            self.inbox = r[7..].to_vec();
        } else {
            self.inbox.extend_from_slice(&r[5..]);
        }
        if self.inbox.len() >= self.expect {
            let msg: Vec<u8> = self.inbox[..self.expect].to_vec();
            match self.cmd {
                0x86 => {
                    let mut d = msg[..8].to_vec();
                    d.extend_from_slice(&self.cid.to_be_bytes());
                    d.extend_from_slice(&[2, 1, 0, 0, 0x05]);
                    self.reply(cid, 0x86, &d);
                }
                0x90 => {
                    let mut ka = vec![0u8; REPORT];
                    ka[..4].copy_from_slice(&cid.to_be_bytes());
                    ka[4] = 0xbb;
                    ka[5..7].copy_from_slice(&1u16.to_be_bytes());
                    ka[7] = 2; // user presence needed
                    self.out.push_back(ka);
                    let resp = self.auth.process(msg[0], &msg[1..]);
                    self.reply(cid, 0x90, &resp);
                }
                _ => self.reply(cid, 0xbf, &[0x01]),
            }
        }
        Ok(())
    }

    fn read_report(&mut self, _timeout_ms: u32) -> R<Option<Vec<u8>>> {
        Ok(self.out.pop_front())
    }
}

/// The mock behind NFC APDUs: SELECT, command chaining, 61XX + GET RESPONSE.
pub struct NfcLoop {
    pub auth: MockAuthenticator,
    selected: bool,
    chain: Vec<u8>,
    pending: Vec<u8>,
    /// Report "still processing" (9100) once before answering.
    pub busy_once: bool,
    busy_result: Option<Vec<u8>>,
}

impl NfcLoop {
    pub fn new(auth: MockAuthenticator) -> Self {
        NfcLoop { auth, selected: false, chain: vec![], pending: vec![], busy_once: true, busy_result: None }
    }

    fn respond(&mut self, data: Vec<u8>) -> Vec<u8> {
        // Short responses: at most 256 bytes, the rest via 61XX.
        self.pending = data;
        self.next_chunk()
    }

    fn next_chunk(&mut self) -> Vec<u8> {
        let n = self.pending.len().min(256);
        let mut out: Vec<u8> = self.pending.drain(..n).collect();
        let left = self.pending.len();
        if left == 0 { out.extend_from_slice(&[0x90, 0x00]); } else { out.extend_from_slice(&[0x61, left.min(255) as u8]); }
        out
    }
}

impl ApduChannel for NfcLoop {
    fn transmit(&mut self, a: &[u8]) -> R<Vec<u8>> {
        if a.len() < 4 { return Ok(vec![0x67, 0x00]); }
        let (cla, ins) = (a[0], a[1]);
        let body = if a.len() > 5 { &a[5..5 + a[4] as usize] } else { &[][..] };
        Ok(match (cla, ins) {
            (0x00, 0xa4) => { self.selected = true; self.respond(b"FIDO_2_0".to_vec()) }
            (0x00, 0xc0) => self.next_chunk(),
            (0x90, 0x10) if self.selected => { self.chain.extend_from_slice(body); vec![0x90, 0x00] }
            (0x80, 0x10) if self.selected => {
                self.chain.extend_from_slice(body);
                let msg = std::mem::take(&mut self.chain);
                let resp = self.auth.process(msg[0], &msg[1..]);
                if self.busy_once { self.busy_once = false; self.busy_result = Some(resp); vec![0x91, 0x00] } else { self.respond(resp) }
            }
            (0x80, 0x11) => match self.busy_result.take() { Some(r) => self.respond(r), None => vec![0x6a, 0x80] },
            _ => vec![0x6d, 0x00],
        })
    }
}

#[allow(dead_code)]
fn _unused() { let _ = pin::pin_hash; }
