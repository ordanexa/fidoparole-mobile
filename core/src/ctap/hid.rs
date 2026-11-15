//! CTAPHID framing (CTAP 2.1 §11.2) over 64-byte HID reports.
//!
//! The platform only moves raw reports ([`HidDevice`]); channel allocation,
//! packet fragmentation, keep-alives and errors are handled here.

use super::{Error, Event, Transport, R};

pub const REPORT: usize = 64;
const BROADCAST: u32 = 0xffff_ffff;
const CMD_INIT: u8 = 0x86;
const CMD_CBOR: u8 = 0x90;
const CMD_CANCEL: u8 = 0x91;
const CMD_KEEPALIVE: u8 = 0xbb;
const CMD_ERROR: u8 = 0xbf;

/// Raw HID report I/O, provided by the platform (Android USB host, desktop hidraw, …).
pub trait HidDevice: Send {
    /// Send one 64-byte output report (no report-id byte).
    fn write_report(&mut self, report: &[u8]) -> R<()>;
    /// Read one 64-byte input report; `Ok(None)` when nothing arrived within `timeout_ms`.
    fn read_report(&mut self, timeout_ms: u32) -> R<Option<Vec<u8>>>;
}

pub struct HidTransport<D: HidDevice> {
    dev: D,
    cid: u32,
    /// Overall time to wait for an answer (the user may need to touch the key).
    pub timeout_ms: u32,
}

impl<D: HidDevice> HidTransport<D> {
    pub fn open(dev: D) -> R<Self> {
        let mut t = HidTransport { dev, cid: BROADCAST, timeout_ms: 30_000 };
        let mut nonce = [0u8; 8];
        rand::fill(&mut nonce[..]);
        let resp = t.exchange(CMD_INIT, &nonce, &mut |_| {})?;
        if resp.len() < 17 || resp[..8] != nonce {
            return Err(Error::Transport("CTAPHID_INIT: unexpected answer".into()));
        }
        t.cid = u32::from_be_bytes(resp[8..12].try_into().unwrap());
        Ok(t)
    }

    fn send(&mut self, cmd: u8, data: &[u8]) -> R<()> {
        if data.len() > 7609 { return Err(Error::Transport("message too long for CTAPHID".into())); }
        let mut rep = [0u8; REPORT];
        rep[..4].copy_from_slice(&self.cid.to_be_bytes());
        rep[4] = cmd;
        rep[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
        let first = data.len().min(REPORT - 7);
        rep[7..7 + first].copy_from_slice(&data[..first]);
        self.dev.write_report(&rep)?;
        let mut off = first;
        let mut seq = 0u8;
        while off < data.len() {
            let mut rep = [0u8; REPORT];
            rep[..4].copy_from_slice(&self.cid.to_be_bytes());
            rep[4] = seq;
            let n = (data.len() - off).min(REPORT - 5);
            rep[5..5 + n].copy_from_slice(&data[off..off + n]);
            self.dev.write_report(&rep)?;
            off += n;
            seq += 1;
        }
        Ok(())
    }

    fn recv(&mut self, cmd: u8, events: &mut dyn FnMut(Event)) -> R<Vec<u8>> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(self.timeout_ms as u64);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now()).as_millis() as u32;
            if left == 0 { return Err(Error::Timeout); }
            let Some(rep) = self.dev.read_report(left.min(1000))? else { continue };
            if rep.len() < 7 { continue; }
            let cid = u32::from_be_bytes(rep[..4].try_into().unwrap());
            if cid != self.cid { continue; } // another channel's traffic
            match rep[4] {
                CMD_KEEPALIVE => {
                    if rep[7] == 2 { events(Event::TouchNeeded) } else { events(Event::Processing) }
                    continue;
                }
                CMD_ERROR => return Err(Error::Transport(format!("CTAPHID error 0x{:02x}", rep[7]))),
                c if c == cmd => {}
                _ => continue,
            }
            let total = u16::from_be_bytes([rep[5], rep[6]]) as usize;
            let mut data = rep[7..rep.len().min(REPORT)].to_vec();
            let mut seq = 0u8;
            while data.len() < total {
                let left = deadline.saturating_duration_since(std::time::Instant::now()).as_millis() as u32;
                if left == 0 { return Err(Error::Timeout); }
                let Some(c) = self.dev.read_report(left.min(1000))? else { continue };
                if c.len() < 5 || u32::from_be_bytes(c[..4].try_into().unwrap()) != self.cid { continue; }
                if c[4] != seq { return Err(Error::Transport("CTAPHID: packet out of sequence".into())); }
                data.extend_from_slice(&c[5..]);
                seq = seq.wrapping_add(1);
            }
            data.truncate(total);
            return Ok(data);
        }
    }

    fn exchange(&mut self, cmd: u8, data: &[u8], events: &mut dyn FnMut(Event)) -> R<Vec<u8>> {
        self.send(cmd, data)?;
        self.recv(cmd, events)
    }

    /// Ask the key to abandon the running request (e.g. user cancelled).
    pub fn cancel(&mut self) {
        let _ = self.send(CMD_CANCEL, &[]);
    }
}

impl<D: HidDevice> Transport for HidTransport<D> {
    fn cbor(&mut self, cmd: u8, payload: &[u8], events: &mut dyn FnMut(Event)) -> R<Vec<u8>> {
        let mut msg = Vec::with_capacity(payload.len() + 1);
        msg.push(cmd);
        msg.extend_from_slice(payload);
        self.exchange(CMD_CBOR, &msg, events)
    }
}
