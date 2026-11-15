//! CTAP over NFC / ISO 7816 (CTAP 2.1 §11.3): SELECT the FIDO applet, then
//! NFCCTAP_MSG APDUs with command chaining and GET RESPONSE.
//!
//! Short APDUs only (≤ 255 bytes per command, chained), which every reader and
//! both Android IsoDep and iOS CoreNFC handle.

use super::{Error, Event, Transport, R};

const FIDO_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01];

/// One APDU exchange, provided by the platform (Android IsoDep, iOS NFCISO7816Tag, PC/SC).
pub trait ApduChannel: Send {
    /// Send a command APDU, return the response including SW1 SW2.
    fn transmit(&mut self, apdu: &[u8]) -> R<Vec<u8>>;
}

pub struct NfcTransport<C: ApduChannel> {
    ch: C,
}

fn split(resp: Vec<u8>) -> R<(Vec<u8>, u16)> {
    if resp.len() < 2 { return Err(Error::Transport("NFC: response without status word".into())); }
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    let mut data = resp;
    data.truncate(data.len() - 2);
    Ok((data, sw))
}

impl<C: ApduChannel> NfcTransport<C> {
    /// Select the FIDO applet. Fails if the card has no FIDO2 support.
    pub fn open(ch: C) -> R<Self> {
        let mut t = NfcTransport { ch };
        let mut apdu = vec![0x00, 0xa4, 0x04, 0x00, FIDO_AID.len() as u8];
        apdu.extend_from_slice(&FIDO_AID);
        apdu.push(0x00);
        let (data, sw) = t.full_response(apdu)?;
        if sw != 0x9000 { return Err(Error::Transport(format!("this tag has no FIDO applet (SW {sw:04X})"))); }
        if data != b"FIDO_2_0" && data != b"U2F_V2" && !data.starts_with(b"FIDO") {
            return Err(Error::Transport("unexpected FIDO applet version".into()));
        }
        Ok(t)
    }

    /// Transmit and follow 61XX "more data" with GET RESPONSE.
    fn full_response(&mut self, apdu: Vec<u8>) -> R<(Vec<u8>, u16)> {
        let (mut data, mut sw) = split(self.ch.transmit(&apdu)?)?;
        while sw >> 8 == 0x61 {
            let le = (sw & 0xff) as u8;
            let (more, s) = split(self.ch.transmit(&[0x00, 0xc0, 0x00, 0x00, le])?)?;
            data.extend(more);
            sw = s;
        }
        Ok((data, sw))
    }
}

impl<C: ApduChannel> Transport for NfcTransport<C> {
    fn cbor(&mut self, cmd: u8, payload: &[u8], events: &mut dyn FnMut(Event)) -> R<Vec<u8>> {
        let mut msg = Vec::with_capacity(payload.len() + 1);
        msg.push(cmd);
        msg.extend_from_slice(payload);
        // Command chaining: CLA 0x90 on all but the last chunk.
        let chunks: Vec<&[u8]> = msg.chunks(255).collect();
        let mut result = None;
        for (i, c) in chunks.iter().enumerate() {
            let last = i == chunks.len() - 1;
            let mut apdu = vec![if last { 0x80 } else { 0x90 }, 0x10, 0x00, 0x00, c.len() as u8];
            apdu.extend_from_slice(c);
            if last { apdu.push(0x00); }
            let (data, sw) = self.full_response(apdu)?;
            if !last {
                if sw != 0x9000 { return Err(Error::Transport(format!("NFC: chained command refused (SW {sw:04X})"))); }
                continue;
            }
            result = Some((data, sw));
        }
        let (mut data, mut sw) = result.expect("at least one chunk");
        // 9100: still processing (e.g. waiting for the user) — poll with NFCCTAP_GETRESPONSE.
        let mut polls = 0;
        while sw == 0x9100 {
            events(Event::Processing);
            polls += 1;
            if polls > 600 { return Err(Error::Timeout); }
            std::thread::sleep(std::time::Duration::from_millis(100));
            let (d, s) = self.full_response(vec![0x80, 0x11, 0x00, 0x00, 0x00])?;
            data = d;
            sw = s;
        }
        if sw != 0x9000 { return Err(Error::Transport(format!("NFC: the key answered SW {sw:04X}"))); }
        Ok(data)
    }
}
