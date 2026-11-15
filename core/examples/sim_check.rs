//! Runs the Rust client against an external CTAP simulator (stdin/stdout hex lines).
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio, Child};
use fidoparole_core::ctap::{hid::{HidDevice, HidTransport}, Auth, Device, R};
use fidoparole_core::{keyops, vault};
use zeroize::Zeroizing;

struct Sim { child: Child, out: BufReader<std::process::ChildStdout>, q: VecDeque<Vec<u8>>, req: Vec<u8>, len: usize, cmd: u8, cid: [u8;4] }
impl HidDevice for Sim {
    fn write_report(&mut self, r: &[u8]) -> R<()> {
        if r[4] & 0x80 != 0 { self.cid.copy_from_slice(&r[..4]); self.cmd = r[4]; self.len = u16::from_be_bytes([r[5], r[6]]) as usize; self.req = r[7..].to_vec(); }
        else { self.req.extend_from_slice(&r[5..]); }
        if self.req.len() >= self.len {
            self.req.truncate(self.len);
            let resp = if self.cmd == 0x86 { let mut v = self.req.clone(); v.extend_from_slice(&[0x12,0x34,0x56,0x78,2,1,0,0,4]); v }
            else {
                let hex: String = self.req.iter().map(|b| format!("{b:02x}")).collect();
                writeln!(self.child.stdin.as_mut().unwrap(), "{hex}").unwrap();
                let mut line = String::new(); self.out.read_line(&mut line).unwrap();
                let l = line.trim(); (0..l.len()/2).map(|i| u8::from_str_radix(&l[2*i..2*i+2],16).unwrap()).collect()
            };
            let cid = if self.cmd == 0x86 { [0xff;4] } else { self.cid };
            let mut k = vec![0u8;64]; k[..4].copy_from_slice(&cid); k[4]=0xbb; k[6]=1; k[7]=2; self.q.push_back(k);
            let mut p = vec![0u8;64]; p[..4].copy_from_slice(&cid); p[4]=self.cmd; p[5..7].copy_from_slice(&(resp.len() as u16).to_be_bytes());
            let n = resp.len().min(57); p[7..7+n].copy_from_slice(&resp[..n]); self.q.push_back(p);
            let (mut off, mut seq) = (n, 0u8);
            while off < resp.len() { let mut c = vec![0u8;64]; c[..4].copy_from_slice(&cid); c[4]=seq; let n=(resp.len()-off).min(59); c[5..5+n].copy_from_slice(&resp[off..off+n]); self.q.push_back(c); off+=n; seq+=1; }
        }
        Ok(())
    }
    fn read_report(&mut self, _t: u32) -> R<Option<Vec<u8>>> { Ok(self.q.pop_front()) }
}

fn run(script: &str, mode: &str) -> Result<String, String> {
    let mut child = Command::new("python3").args(["-I", script, mode]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|e| e.to_string())?;
    let out = BufReader::new(child.stdout.take().unwrap());
    let sim = Sim { child, out, q: VecDeque::new(), req: vec![], len: 0, cmd: 0, cid: [0; 4] };
    let mut dev = Device::open(HidTransport::open(sim).map_err(|e| e.to_string())?, Box::new(|_| {})).map_err(|e| e.to_string())?;
    let found = keyops::unlock(&mut dev, &Auth::Pin(Zeroizing::new("123456".into()))).map_err(|e| e.to_string())?;
    let mut names = vec![];
    for (c, blob) in &found.creds {
        let v = vault::open(blob.as_ref().ok_or("no blob")?, &c.hmac_secret)?;
        if v.entries[0].password != "dummy-copy-password" { return Err("wrong password".into()); }
        names.push(format!("{}:{}", c.name, v.entries[0].title));
    }
    Ok(names.join(", "))
}

fn main() {
    let script = std::env::args().nth(1).expect("path to authenticator.py");
    let mut ok = true;
    for mode in ["v1", "v2", "format1"] {
        match run(&script, mode) { Ok(n) => println!("PASS {mode}: {n}"), Err(e) => { ok = false; println!("FAIL {mode}: {e}") } }
    }
    for mode in ["wrong_pin", "checksum", "no_uv", "vault_tamper", "wrong_secret"] {
        match run(&script, mode) { Err(e) => println!("PASS {mode} rejected: {e}"), Ok(_) => { ok = false; println!("FAIL {mode}: accepted") } }
    }
    std::process::exit(if ok { 0 } else { 1 });
}
