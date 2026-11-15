//! Small CBOR helpers on top of `ciborium::Value`.
//!
//! CTAP2 requires "CTAP2 canonical CBOR": map keys sorted by the length of
//! their encoding, then bytewise. [`encode`] sorts every map before writing,
//! so callers can build maps in any order.

use ciborium::Value;

use super::{Error, R};

pub fn int(i: i64) -> Value { Value::Integer(i.into()) }
pub fn text(s: &str) -> Value { Value::Text(s.to_string()) }
pub fn bytes(b: &[u8]) -> Value { Value::Bytes(b.to_vec()) }
pub fn bool(b: bool) -> Value { Value::Bool(b) }

/// A map with integer keys.
pub fn imap(entries: Vec<(i64, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (int(k), v)).collect())
}

/// A map with text keys.
pub fn tmap(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
}

fn raw(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("writing CBOR to memory cannot fail");
    out
}

fn canonical(v: &Value) -> Value {
    match v {
        Value::Map(m) => {
            let mut items: Vec<(Vec<u8>, Value, Value)> =
                m.iter().map(|(k, v)| (raw(&canonical(k)), canonical(k), canonical(v))).collect();
            items.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
            Value::Map(items.into_iter().map(|(_, k, v)| (k, v)).collect())
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

/// Encode in CTAP2 canonical form.
pub fn encode(v: &Value) -> Vec<u8> {
    raw(&canonical(v))
}

pub fn decode(b: &[u8]) -> R<Value> {
    ciborium::from_reader(b).map_err(|e| Error::Protocol(format!("invalid CBOR from the key: {e}")))
}

/// Decode one CBOR item from the start of `b`; returns it and the bytes used.
pub fn decode_prefix(b: &[u8]) -> R<(Value, usize)> {
    let mut cur = std::io::Cursor::new(b);
    let v: Value = ciborium::from_reader(&mut cur).map_err(|e| Error::Protocol(format!("invalid CBOR from the key: {e}")))?;
    Ok((v, cur.position() as usize))
}

/// Look up an integer key in a map.
pub fn get<'a>(v: &'a Value, key: i64) -> Option<&'a Value> {
    v.as_map()?.iter().find(|(k, _)| k.as_integer().map(i128::from) == Some(key as i128)).map(|(_, v)| v)
}

/// Look up a text key in a map.
pub fn get_t<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.as_map()?.iter().find(|(k, _)| k.as_text() == Some(key)).map(|(_, v)| v)
}

pub fn as_bytes(v: Option<&Value>) -> Option<&[u8]> { v?.as_bytes().map(|b| b.as_slice()) }
pub fn as_u64(v: Option<&Value>) -> Option<u64> { v?.as_integer().and_then(|i| u64::try_from(i).ok()) }
pub fn as_i64(v: Option<&Value>) -> Option<i64> { v?.as_integer().and_then(|i| i64::try_from(i).ok()) }
pub fn as_bool(v: Option<&Value>) -> Option<bool> { v?.as_bool() }
pub fn as_text(v: Option<&Value>) -> Option<&str> { v?.as_text() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_order() {
        // COSE key: 1, 3, -1, -2, -3 ; text keys by length then bytes.
        let v = imap(vec![(-3, int(0)), (1, int(2)), (-1, int(1)), (3, int(-25)), (-2, int(0))]);
        assert_eq!(&encode(&v)[..2], &[0xa5, 0x01]);
        let enc = encode(&v);
        let keys: Vec<i64> = decode(&enc).unwrap().as_map().unwrap().iter()
            .map(|(k, _)| i64::try_from(k.as_integer().unwrap()).unwrap()).collect();
        assert_eq!(keys, vec![1, 3, -1, -2, -3]);
        let t = tmap(vec![("largeBlobKey", bool(true)), ("hmac-secret", bool(true)), ("credProtect", int(3))]);
        let keys: Vec<String> = decode(&encode(&t)).unwrap().as_map().unwrap().iter()
            .map(|(k, _)| k.as_text().unwrap().to_string()).collect();
        assert_eq!(keys, vec!["credProtect", "hmac-secret", "largeBlobKey"]);
    }
}
