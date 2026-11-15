//! FidoParole for Android and iOS: the core behind a UniFFI interface.
//!
//! The apps provide the wire ([`HidLink`] for USB HID reports, [`NfcLink`]
//! for ISO 7816 APDUs) and the UI. The decrypted vault stays in Rust, inside
//! [`VaultSession`]; the UI asks for entries without passwords and fetches a
//! password only to show or copy it.
//!
//! All calls that talk to the key block until it answers, so the apps call
//! them from a background thread (Android: Dispatchers.IO; iOS: a Task off the
//! main actor, with the NFC callback bridged synchronously).

use std::sync::{Arc, Mutex};

use fidoparole_core::ctap::{self, hid::HidTransport, nfc::NfcTransport, Auth, Device, Event, Transport};
use fidoparole_core::keyops::{self, VaultCredential};
use fidoparole_core::vault::{self, Entry, VaultData};
use zeroize::{Zeroize, Zeroizing};

uniffi::setup_scaffolding!();

// ------------------------------------------------------------------ errors --

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FpError {
    /// The key refused (CTAP status `code`), e.g. wrong PIN (0x31), storage full (0x18).
    #[error("{detail}")]
    Key { code: u8, detail: String },
    /// USB / NFC link lost or failed.
    #[error("{detail}")]
    Link { detail: String },
    #[error("{detail}")]
    Other { detail: String },
}

impl From<ctap::Error> for FpError {
    fn from(e: ctap::Error) -> Self {
        match e {
            ctap::Error::Ctap(code) => FpError::Key { code, detail: e.to_string() },
            ctap::Error::Transport(_) | ctap::Error::Timeout => FpError::Link { detail: e.to_string() },
            _ => FpError::Other { detail: e.to_string() },
        }
    }
}

impl From<String> for FpError {
    fn from(detail: String) -> Self { FpError::Other { detail } }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for FpError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self { FpError::Link { detail: e.reason } }
}

type Res<T> = Result<T, FpError>;

// ------------------------------------------------------------------- links --

/// Raw USB HID I/O to a FIDO key (Android: UsbDeviceConnection interrupt endpoints).
#[uniffi::export(with_foreign)]
pub trait HidLink: Send + Sync {
    /// Write one 64-byte output report.
    fn write_report(&self, report: Vec<u8>) -> Result<(), FpError>;
    /// Read one 64-byte input report, or None after `timeout_ms`.
    fn read_report(&self, timeout_ms: u32) -> Result<Option<Vec<u8>>, FpError>;
}

/// One APDU exchange with an NFC FIDO key (Android IsoDep, iOS NFCISO7816Tag).
#[uniffi::export(with_foreign)]
pub trait NfcLink: Send + Sync {
    fn transmit(&self, apdu: Vec<u8>) -> Result<Vec<u8>, FpError>;
}

/// Progress while the key works.
#[uniffi::export(with_foreign)]
pub trait KeyListener: Send + Sync {
    /// The key blinks and waits for a touch (or fingerprint).
    fn touch_needed(&self);
}

struct HidAdapter(Arc<dyn HidLink>);
impl ctap::hid::HidDevice for HidAdapter {
    fn write_report(&mut self, report: &[u8]) -> ctap::R<()> {
        self.0.write_report(report.to_vec()).map_err(|e| ctap::Error::Transport(e.to_string()))
    }
    fn read_report(&mut self, timeout_ms: u32) -> ctap::R<Option<Vec<u8>>> {
        self.0.read_report(timeout_ms).map_err(|e| ctap::Error::Transport(e.to_string()))
    }
}

struct NfcAdapter(Arc<dyn NfcLink>);
impl ctap::nfc::ApduChannel for NfcAdapter {
    fn transmit(&mut self, apdu: &[u8]) -> ctap::R<Vec<u8>> {
        self.0.transmit(apdu.to_vec()).map_err(|e| ctap::Error::Transport(e.to_string()))
    }
}

/// The demo key: one software authenticator per process, created with a sample vault.
fn demo_key() -> &'static Mutex<ctap::mock::MockAuthenticator> {
    static KEY: std::sync::OnceLock<Mutex<ctap::mock::MockAuthenticator>> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let mut auth = ctap::mock::MockAuthenticator::new(Some(DEMO_PIN));
        auth.max_large_blob = 2048;
        let mut data = VaultData::default();
        for (t, u, url) in [
            ("GitHub", "emin", "https://github.com/login"),
            ("Proton Mail", "emin@example.com", "https://mail.proton.me"),
            ("Swiss e-banking", "123456", "https://ebanking.example.ch"),
            ("Router admin", "admin", "http://192.168.1.1"),
            ("Wi-Fi home", "", ""),
        ] {
            let mut e = Entry::new(t);
            e.username = u.into();
            e.url = url.into();
            e.password = vault::generate_password(&vault::GenOptions::default());
            data.entries.push(e);
        }
        struct Direct<'a>(&'a mut ctap::mock::MockAuthenticator);
        impl Transport for Direct<'_> {
            fn cbor(&mut self, cmd: u8, p: &[u8], _: &mut dyn FnMut(Event)) -> ctap::R<Vec<u8>> { Ok(self.0.process(cmd, p)) }
        }
        // SAFETY: used only on this thread during initialisation.
        unsafe impl Send for Direct<'_> {}
        if let Ok(mut dev) = Device::open(Direct(&mut auth), Box::new(|_| {})) {
            let _ = keyops::create(&mut dev, &Auth::Pin(Zeroizing::new(DEMO_PIN.into())), "Demo vault", &data, &[]);
        }
        auth.touches = 0;
        Mutex::new(auth)
    })
}

/// PIN of the demo key.
pub const DEMO_PIN: &str = "1234";

struct DemoTransport;
impl Transport for DemoTransport {
    fn cbor(&mut self, cmd: u8, payload: &[u8], events: &mut dyn FnMut(Event)) -> ctap::R<Vec<u8>> {
        // Pretend to wait for a touch on the operations that need one.
        if matches!(cmd, ctap::CMD_MAKE_CREDENTIAL | ctap::CMD_GET_ASSERTION) {
            events(Event::TouchNeeded);
            std::thread::sleep(std::time::Duration::from_millis(600));
        }
        Ok(demo_key().lock().map_err(|_| ctap::Error::Transport("demo key poisoned".into()))?.process(cmd, payload))
    }
}

#[uniffi::export]
pub fn demo_pin() -> String { DEMO_PIN.to_string() }

/// An open connection to one key (USB or NFC).
#[derive(uniffi::Object)]
pub struct KeyLink {
    dev: Mutex<Device<Box<dyn Transport>>>,
    nfc: bool,
}

fn events(listener: Option<Arc<dyn KeyListener>>) -> Box<dyn FnMut(Event) + Send> {
    Box::new(move |e| {
        if e == Event::TouchNeeded {
            if let Some(l) = &listener { l.touch_needed(); }
        }
    })
}

#[uniffi::export]
impl KeyLink {
    /// Open a USB key: CTAPHID channel + getInfo.
    #[uniffi::constructor]
    pub fn usb(link: Arc<dyn HidLink>, listener: Option<Arc<dyn KeyListener>>) -> Res<Arc<Self>> {
        let t: Box<dyn Transport> = Box::new(HidTransport::open(HidAdapter(link))?);
        Ok(Arc::new(KeyLink { dev: Mutex::new(Device::open(t, events(listener))?), nfc: false }))
    }

    /// Open an NFC key: SELECT the FIDO applet + getInfo.
    #[uniffi::constructor]
    pub fn nfc(link: Arc<dyn NfcLink>, listener: Option<Arc<dyn KeyListener>>) -> Res<Arc<Self>> {
        let t: Box<dyn Transport> = Box::new(NfcTransport::open(NfcAdapter(link))?);
        Ok(Arc::new(KeyLink { dev: Mutex::new(Device::open(t, events(listener))?), nfc: true }))
    }

    /// Demo mode: a software key inside the app (PIN 1234) with a sample
    /// vault, for trying FidoParole — and for app-store review — without a
    /// security key. Everything stays in memory and is gone when the app quits.
    #[uniffi::constructor]
    pub fn demo(listener: Option<Arc<dyn KeyListener>>) -> Res<Arc<Self>> {
        let t: Box<dyn Transport> = Box::new(DemoTransport);
        Ok(Arc::new(KeyLink { dev: Mutex::new(Device::open(t, events(listener))?), nfc: false }))
    }

    pub fn is_nfc(&self) -> bool { self.nfc }

    pub fn info(&self) -> KeyInfo {
        let mut d = self.dev.lock().unwrap();
        keyops::key_info(&mut d).into()
    }
}

impl KeyLink {
    fn with<T>(&self, f: impl FnOnce(&mut Device<Box<dyn Transport>>) -> ctap::R<T>) -> Res<T> {
        let mut d = self.dev.lock().map_err(|_| FpError::Other { detail: "key link poisoned".into() })?;
        Ok(f(&mut d)?)
    }
}

// ----------------------------------------------------------------- records --

#[derive(uniffi::Record, Clone, Debug)]
pub struct KeyInfo {
    pub hmac_secret: bool,
    pub large_blob: bool,
    pub max_large_blob: u64,
    pub has_pin: bool,
    pub has_fingerprint: bool,
    pub pin_retries: i32,
    pub aaguid: String,
    pub firmware: String,
    /// Why this key cannot hold a vault, if it can't.
    pub problem: Option<String>,
}

impl From<keyops::KeyInfo> for KeyInfo {
    fn from(k: keyops::KeyInfo) -> Self {
        let problem = k.problem();
        KeyInfo {
            hmac_secret: k.hmac_secret, large_blob: k.large_blob, max_large_blob: k.max_large_blob,
            has_pin: k.has_pin, has_fingerprint: k.has_uv, pin_retries: k.pin_retries,
            aaguid: k.aaguid, firmware: k.firmware, problem,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct EntrySummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub modified: i64,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct EntryDetails {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub modified: i64,
    pub has_password: bool,
}

#[derive(uniffi::Enum, Clone, Copy, Debug)]
pub enum EntryField { Title, Username, Password, Url, Notes }

#[derive(uniffi::Record, Clone, Debug)]
pub struct GenOptions {
    pub length: u32,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct VaultStatus {
    pub name: String,
    pub entry_count: u32,
    /// Changes not yet saved to the key.
    pub dirty: bool,
    /// Bytes used in the key's largeBlob storage (all vaults) and its capacity.
    pub used: u64,
    pub max: u64,
    /// Unlocked with the PIN (saving needs no further check). False after a
    /// fingerprint unlock: every write asks for the fingerprint again.
    pub pin_saved: bool,
    /// Set when the key held no data for this vault at unlock.
    pub notice: Option<String>,
    /// Set when the stored data could not be decrypted (the vault can't be used).
    pub problem: Option<String>,
}

// ---------------------------------------------------------------- sessions --

struct State {
    cred: VaultCredential,
    auth: Auth,
    data: VaultData,
    dirty: bool,
    edits: u64,
    used: usize,
    max: usize,
    blob_len: usize,
    blob_hash: Option<[u8; 32]>,
    notice: Option<String>,
    problem: Option<String>,
}

/// One unlocked vault. Dropping it (or [`VaultSession::lock`]) wipes the
/// decrypted entries, the hmac-secret, the largeBlob key and the PIN.
#[derive(uniffi::Object)]
pub struct VaultSession {
    st: Mutex<Option<State>>,
}

fn sha(b: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(b).into()
}

fn auth_from(pin: Option<String>) -> Auth {
    match pin.filter(|p| !p.is_empty()) {
        Some(p) => Auth::Pin(Zeroizing::new(p)),
        None => Auth::Uv,
    }
}

fn session_from(cred: VaultCredential, blob: Option<Vec<u8>>, auth: Auth, used: usize, max: usize) -> Arc<VaultSession> {
    let (data, problem, notice) = match &blob {
        Some(b) => match vault::open(b, &cred.hmac_secret) {
            Ok(d) => (d, None, None),
            Err(e) => (VaultData::default(), Some(e), None),
        },
        None => (VaultData::default(), None, Some(
            "This key holds no saved data for this vault, so it opens empty. If you expected entries here, \
             don't save: restore them from a backup, or open the vault from another key.".to_string())),
    };
    Arc::new(VaultSession { st: Mutex::new(Some(State {
        blob_len: blob.as_ref().map(|b| b.len()).unwrap_or(0),
        blob_hash: blob.as_deref().map(sha),
        cred, auth, data, dirty: false, edits: 0, used, max, notice, problem,
    })) })
}

/// Unlock: every vault found on the key, already decrypted (PIN or
/// fingerprint + one touch). `pin` None or empty = use the fingerprint.
#[uniffi::export]
pub fn unlock(link: Arc<KeyLink>, pin: Option<String>) -> Res<Vec<Arc<VaultSession>>> {
    let auth = auth_from(pin);
    let found = link.with(|d| keyops::unlock(d, &auth))?;
    let (used, max) = (found.used, found.max);
    Ok(found.creds.into_iter().map(|(c, b)| session_from(c, b, auth.clone(), used, max)).collect())
}

/// Create a new, empty vault on the key (two touches).
#[uniffi::export]
pub fn create_vault(link: Arc<KeyLink>, pin: Option<String>, name: String) -> Res<Arc<VaultSession>> {
    let name = name.trim().to_string();
    let auth = auth_from(pin);
    let mut f = link.with(|d| keyops::create(d, &auth, &name, &VaultData::default(), &[]))?;
    let (c, b) = f.creds.remove(0);
    Ok(session_from(c, b, auth, f.used, f.max))
}

#[uniffi::export]
pub fn max_vault_name_bytes() -> u32 { keyops::MAX_NAME_BYTES as u32 }

#[uniffi::export]
pub fn core_version() -> String { env!("CARGO_PKG_VERSION").to_string() }

/// Rough per-entry overhead libfido2-style largeBlob entries add (CBOR map,
/// nonce, tag, origSize, deflate framing).
const ENTRY_OVERHEAD: usize = 64;

impl VaultSession {
    fn with<T>(&self, f: impl FnOnce(&mut State) -> Res<T>) -> Res<T> {
        let mut g = self.st.lock().map_err(|_| FpError::Other { detail: "session poisoned".into() })?;
        let s = g.as_mut().ok_or_else(|| FpError::Other { detail: "the vault is locked".into() })?;
        f(s)
    }

    fn usable(s: &State) -> Res<()> {
        match &s.problem { Some(p) => Err(FpError::Other { detail: p.clone() }), None => Ok(()) }
    }
}

fn entry_mut<'a>(s: &'a mut State, id: &str) -> Res<&'a mut Entry> {
    s.data.entries.iter_mut().find(|e| e.id == id).ok_or_else(|| FpError::Other { detail: "entry not found".into() })
}

fn status(s: &State) -> VaultStatus {
    VaultStatus {
        name: s.cred.name.clone(), entry_count: s.data.entries.len() as u32, dirty: s.dirty,
        used: s.used as u64, max: s.max as u64, pin_saved: matches!(s.auth, Auth::Pin(_)),
        notice: s.notice.clone(), problem: s.problem.clone(),
    }
}

#[uniffi::export]
impl VaultSession {
    pub fn status(&self) -> Res<VaultStatus> { self.with(|s| Ok(status(s))) }

    /// Entries without passwords, sorted by title; `query` filters title/username/URL.
    pub fn entries(&self, query: String) -> Res<Vec<EntrySummary>> {
        let q = query.trim().to_lowercase();
        self.with(|s| {
            let mut v: Vec<EntrySummary> = s.data.entries.iter()
                .filter(|e| q.is_empty() || [&e.title, &e.username, &e.url].iter().any(|f| f.to_lowercase().contains(&q)))
                .map(|e| EntrySummary { id: e.id.clone(), title: e.title.clone(), username: e.username.clone(), url: e.url.clone(), modified: e.modified })
                .collect();
            v.sort_by_key(|e| e.title.to_lowercase());
            Ok(v)
        })
    }

    pub fn entry(&self, id: String) -> Res<EntryDetails> {
        self.with(|s| {
            let e = entry_mut(s, &id)?;
            Ok(EntryDetails { id: e.id.clone(), title: e.title.clone(), username: e.username.clone(), url: e.url.clone(),
                notes: e.notes.clone(), modified: e.modified, has_password: !e.password.is_empty() })
        })
    }

    /// The one call that hands a password to the UI (to show or copy it).
    pub fn password(&self, id: String) -> Res<String> {
        self.with(|s| Ok(entry_mut(s, &id)?.password.clone()))
    }

    pub fn add_entry(&self, title: String) -> Res<String> {
        self.with(|s| {
            Self::usable(s)?;
            let e = Entry::new(if title.trim().is_empty() { "New entry" } else { title.trim() });
            let id = e.id.clone();
            s.data.entries.push(e);
            s.dirty = true;
            s.edits += 1;
            Ok(id)
        })
    }

    pub fn update_entry(&self, id: String, field: EntryField, value: String) -> Res<()> {
        let value = Zeroizing::new(value);
        self.with(|s| {
            Self::usable(s)?;
            let e = entry_mut(s, &id)?;
            let slot = match field {
                EntryField::Title => &mut e.title,
                EntryField::Username => &mut e.username,
                EntryField::Password => &mut e.password,
                EntryField::Url => &mut e.url,
                EntryField::Notes => &mut e.notes,
            };
            if *slot != *value {
                slot.zeroize();
                slot.push_str(&value);
                e.touch();
                s.dirty = true;
                s.edits += 1;
            }
            Ok(())
        })
    }

    pub fn delete_entry(&self, id: String) -> Res<()> {
        self.with(|s| {
            let before = s.data.entries.len();
            s.data.entries.retain(|e| e.id != id);
            if s.data.entries.len() != before { s.dirty = true; s.edits += 1; }
            Ok(())
        })
    }

    /// Generate a new password into the entry (the UI doesn't see it unless it asks).
    pub fn generate_password(&self, id: String, opts: GenOptions) -> Res<()> {
        self.with(|s| {
            Self::usable(s)?;
            let e = entry_mut(s, &id)?;
            e.password.zeroize();
            e.password = vault::generate_password(&vault::GenOptions {
                length: opts.length as usize, upper: opts.upper, lower: opts.lower, digits: opts.digits, symbols: opts.symbols,
            });
            e.touch();
            s.dirty = true;
            s.edits += 1;
            Ok(())
        })
    }

    /// Seal and write the vault to the key. With a PIN unlock no touch is
    /// needed; after a fingerprint unlock the key asks for the fingerprint.
    pub fn save(&self, link: Arc<KeyLink>) -> Res<VaultStatus> {
        let (lbk, auth, blob, edits, cred_id) = self.with(|s| {
            Self::usable(s)?;
            let blob = vault::seal(&s.data, &s.cred.hmac_secret)?;
            let mine = if s.blob_len > 0 { s.blob_len + ENTRY_OVERHEAD } else { 0 };
            if s.max > 0 {
                let budget = s.max.saturating_sub(s.used.saturating_sub(mine));
                if blob.len() + ENTRY_OVERHEAD > budget {
                    return Err(FpError::Key { code: 0x18, detail: format!(
                        "the vault ({} bytes) does not fit: about {} bytes of the key's storage are free for it — remove some entries or notes",
                        blob.len(), budget.saturating_sub(ENTRY_OVERHEAD)) });
                }
            }
            Ok((s.cred.large_blob_key.clone(), s.auth.clone(), blob, s.edits, s.cred.cred_id.clone()))
        })?;
        let used = link.with(|d| keyops::write(d, &auth, &lbk, &blob))?;
        self.with(|s| {
            if s.cred.cred_id != cred_id { return Err(FpError::Other { detail: "the vault changed while saving".into() }); }
            s.used = used;
            s.blob_len = blob.len();
            s.blob_hash = Some(sha(&blob));
            s.notice = None;
            if s.edits == edits { s.dirty = false; }
            Ok(status(s))
        })
    }

    /// Re-attach to the key after the link was lost. Returns true when the
    /// data on the key changed meanwhile (the open vault is then unsaved).
    pub fn reconnect(&self, link: Arc<KeyLink>) -> Res<bool> {
        let (auth, cred_id, secret) = self.with(|s| Ok((s.auth.clone(), s.cred.cred_id.clone(), s.cred.hmac_secret.clone())))?;
        let (cred, blob, used, max) = link.with(|d| keyops::reconnect(d, &auth, &cred_id, &secret))?;
        self.with(|s| {
            let h = blob.as_deref().map(sha);
            let changed = h != s.blob_hash;
            s.cred.large_blob_key = cred.large_blob_key.clone();
            s.used = used;
            s.max = max;
            s.blob_len = blob.as_ref().map(|b| b.len()).unwrap_or(0);
            s.blob_hash = h;
            if changed { s.dirty = true; s.edits += 1; }
            Ok(changed)
        })
    }

    /// Copy the open vault to another key (new credential there, two touches).
    pub fn copy_to_key(&self, target: Arc<KeyLink>, pin: Option<String>, name: String) -> Res<()> {
        let (data, exclude) = self.with(|s| { Self::usable(s)?; Ok((s.data.clone(), s.cred.cred_id.clone())) })?;
        let auth = auth_from(pin);
        let name = name.trim().to_string();
        target.with(|d| keyops::create(d, &auth, &name, &data, &[exclude]))?;
        Ok(())
    }

    /// Delete the vault from the key (data and credential), then lock.
    pub fn delete_from_key(&self, link: Arc<KeyLink>) -> Res<()> {
        let (auth, cred_id, lbk) = self.with(|s| Ok((s.auth.clone(), s.cred.cred_id.clone(), s.cred.large_blob_key.clone())))?;
        link.with(|d| keyops::delete(d, &auth, &cred_id, &lbk))?;
        self.lock();
        Ok(())
    }

    /// Passphrase-protected backup file contents (`.t2vault`).
    pub fn export_backup(&self, passphrase: String) -> Res<Vec<u8>> {
        let pass = Zeroizing::new(passphrase);
        self.with(|s| Ok(vault::export_backup(&s.data, &pass)?))
    }

    /// Merge (or replace with) a backup file; returns a summary line.
    pub fn import_backup(&self, file: Vec<u8>, passphrase: String, replace: bool) -> Res<String> {
        let pass = Zeroizing::new(passphrase);
        let other = vault::import_backup(&file, &pass)?;
        self.with(|s| {
            Self::usable(s)?;
            let msg = if replace {
                let n = other.entries.len();
                s.data = other;
                format!("Replaced the vault with the {n} entries from the backup.")
            } else {
                let (a, u) = s.data.merge(&other);
                format!("Merged the backup: {a} added, {u} updated.")
            };
            s.dirty = true;
            s.edits += 1;
            Ok(msg)
        })
    }

    /// Wipe everything from memory. The session can't be used afterwards.
    pub fn lock(&self) {
        if let Ok(mut g) = self.st.lock() { *g = None; }
    }

    pub fn is_locked(&self) -> bool {
        self.st.lock().map(|g| g.is_none()).unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fidoparole_core::ctap::mock::{HidLoop, MockAuthenticator, NfcLoop};

    /// The mock behind the same callback interfaces the apps implement.
    struct UsbMock(Mutex<HidLoop>);
    impl HidLink for UsbMock {
        fn write_report(&self, r: Vec<u8>) -> Result<(), FpError> {
            ctap::hid::HidDevice::write_report(&mut *self.0.lock().unwrap(), &r).map_err(|e| FpError::Link { detail: e.to_string() })
        }
        fn read_report(&self, t: u32) -> Result<Option<Vec<u8>>, FpError> {
            ctap::hid::HidDevice::read_report(&mut *self.0.lock().unwrap(), t).map_err(|e| FpError::Link { detail: e.to_string() })
        }
    }
    struct NfcMock(Mutex<NfcLoop>);
    impl NfcLink for NfcMock {
        fn transmit(&self, a: Vec<u8>) -> Result<Vec<u8>, FpError> {
            ctap::nfc::ApduChannel::transmit(&mut *self.0.lock().unwrap(), &a).map_err(|e| FpError::Link { detail: e.to_string() })
        }
    }
    struct Touches(std::sync::atomic::AtomicU32);
    impl KeyListener for Touches {
        fn touch_needed(&self) { self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
    }

    #[test]
    fn demo_key_has_a_sample_vault() {
        let link = KeyLink::demo(None).unwrap();
        let v = unlock(link.clone(), Some(demo_pin())).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].status().unwrap().name, "Demo vault");
        assert_eq!(v[0].entries(String::new()).unwrap().len(), 5);
        let id = v[0].add_entry("Added in demo".into()).unwrap();
        v[0].save(link.clone()).unwrap();
        let again = unlock(KeyLink::demo(None).unwrap(), Some(demo_pin())).unwrap();
        assert!(again[0].entry(id).is_ok());
    }

    #[test]
    fn app_flow_over_usb_and_nfc() {
        let touches = Arc::new(Touches(Default::default()));
        let usb = KeyLink::usb(Arc::new(UsbMock(Mutex::new(HidLoop::new(MockAuthenticator::new(Some("1234")))))), Some(touches.clone())).unwrap();
        assert!(usb.info().problem.is_none());
        let pin = Some("1234".to_string());
        let v = create_vault(usb.clone(), pin.clone(), "Phone".into()).unwrap();
        let id = v.add_entry("GitHub".into()).unwrap();
        v.update_entry(id.clone(), EntryField::Username, "emin".into()).unwrap();
        v.generate_password(id.clone(), GenOptions { length: 24, upper: true, lower: true, digits: true, symbols: false }).unwrap();
        assert!(v.status().unwrap().dirty);
        let st = v.save(usb.clone()).unwrap();
        assert!(!st.dirty && st.pin_saved);
        let pw = v.password(id.clone()).unwrap();
        assert_eq!(pw.len(), 24);
        assert!(touches.0.load(std::sync::atomic::Ordering::Relaxed) > 0);

        let again = unlock(usb.clone(), pin.clone()).unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].password(id.clone()).unwrap(), pw);
        assert_eq!(again[0].entries("git".into()).unwrap()[0].username, "emin");

        // Backup round trip.
        let bk = again[0].export_backup("correct horse battery".into()).unwrap();
        let other = create_vault(usb.clone(), pin.clone(), "Empty".into()).unwrap();
        assert!(other.import_backup(bk, "correct horse battery".into(), false).unwrap().contains("1 added"));

        // Copy to an NFC key, open it there.
        let nfc = KeyLink::nfc(Arc::new(NfcMock(Mutex::new(NfcLoop::new(MockAuthenticator::new(Some("5678")))))), None).unwrap();
        again[0].copy_to_key(nfc.clone(), Some("5678".into()), "Phone".into()).unwrap();
        let on_nfc = unlock(nfc.clone(), Some("5678".into())).unwrap();
        assert_eq!(on_nfc[0].password(id.clone()).unwrap(), pw);

        // Wrong PIN surfaces as a key error with the CTAP code.
        match unlock(nfc.clone(), Some("0000".into())) {
            Err(FpError::Key { code: 0x31, .. }) => {}
            other => panic!("unexpected: {:?}", other.map(|v| v.len())),
        }

        // Delete, then lock wipes.
        on_nfc[0].delete_from_key(nfc.clone()).unwrap();
        assert!(on_nfc[0].is_locked());
        assert!(unlock(nfc, Some("5678".into())).is_err());
    }
}
