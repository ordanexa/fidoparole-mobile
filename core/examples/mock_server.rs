//! The mock authenticator as a process, for cross-checking with independent
//! CTAP2 clients (tools/crosscheck.py uses Yubico's python-fido2).
//!
//! stdin:  cmd u8 | len u32 BE | payload      stdout: len u32 BE | response
//! cmd 0x00-0x7f: CTAP2 command → status + CBOR
//! cmd 0xfd: the Rust client creates a vault "RustVault" (JSON reply)
//! cmd 0xfe: the Rust client unlocks with PIN 123456 (JSON reply)

use fidoparole_core::ctap::{mock::MockAuthenticator, Auth, Device, Event, Transport, R};
use fidoparole_core::{keyops, vault};
use std::io::{Read, Write};
use zeroize::Zeroizing;

struct Borrowed<'a>(&'a mut MockAuthenticator);
impl Transport for Borrowed<'_> {
    fn cbor(&mut self, cmd: u8, payload: &[u8], _e: &mut dyn FnMut(Event)) -> R<Vec<u8>> { Ok(self.0.process(cmd, payload)) }
}
// SAFETY of Send: single-threaded tool.
unsafe impl Send for Borrowed<'_> {}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn main() {
    let protocols: Vec<i64> = std::env::args().nth(1).map(|a| a.split(',').map(|p| p.parse().unwrap()).collect()).unwrap_or(vec![2, 1]);
    let mut auth = MockAuthenticator::new(Some("123456"));
    auth.protocols = protocols;
    let pin = Auth::Pin(Zeroizing::new("123456".into()));
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    loop {
        let mut head = [0u8; 5];
        if stdin.read_exact(&mut head).is_err() { break; }
        let n = u32::from_be_bytes(head[1..5].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; n];
        stdin.read_exact(&mut payload).unwrap();
        let resp: Vec<u8> = match head[0] {
            0xfd => {
                let mut dev = Device::open(Borrowed(&mut auth), Box::new(|_| {})).unwrap();
                let mut data = vault::VaultData::default();
                data.entries.push(vault::Entry::new("From Rust"));
                let f = keyops::create(&mut dev, &pin, "RustVault", &data, &[]).unwrap();
                let c = &f.creds[0].0;
                format!(r#"{{"cred_id":"{}","lbk":"{}"}}"#, hex(&c.cred_id), hex(&c.large_blob_key)).into_bytes()
            }
            0xfe => {
                let mut dev = Device::open(Borrowed(&mut auth), Box::new(|_| {})).unwrap();
                match keyops::unlock(&mut dev, &pin) {
                    Ok(f) => {
                        let items: Vec<String> = f.creds.iter().map(|(c, b)| format!(
                            r#"{{"name":"{}","cred_id":"{}","hmac":"{}","blob":"{}"}}"#,
                            c.name, hex(&c.cred_id), hex(&c.hmac_secret[..]), b.as_ref().map(|b| hex(b)).unwrap_or_default())).collect();
                        format!(r#"{{"vaults":[{}]}}"#, items.join(",")).into_bytes()
                    }
                    Err(e) => format!(r#"{{"error":"{e}"}}"#).into_bytes(),
                }
            }
            cmd => auth.process(cmd, &payload),
        };
        stdout.write_all(&(resp.len() as u32).to_be_bytes()).unwrap();
        stdout.write_all(&resp).unwrap();
        stdout.flush().unwrap();
    }
}
