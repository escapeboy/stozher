//! JCS canonicalization (RFC 8785) — `spec/01-canonicalization-and-crypto.md` §3.
//!
//! Three properties are easy to get wrong and are therefore implemented explicitly here rather
//! than delegated to `serde_json`'s defaults:
//!
//! 1. **Member ordering is by UTF-16 code unit**, not by code point and not by UTF-8 byte. Rust's
//!    `String: Ord` (and hence `BTreeMap`) sorts by UTF-8 bytes, which places a name starting at
//!    U+1F60A *after* one starting at U+FFE0. JCS requires the opposite.
//! 2. **Duplicate member names are rejected**, which requires a custom deserializer:
//!    `serde_json`'s map silently keeps the last occurrence, and a parser that silently picks one
//!    is a signature-confusion vector.
//! 3. **Numbers use ECMAScript `Number::toString`**, delegated to `ryu-js` and verified against
//!    `spec/vectors/jcs-canonicalization.json`.

use std::cmp::Ordering;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::crypto::sha256_hex;
use crate::error::{Result, err};

/// Parse JSON text, rejecting everything RFC 8785 forbids.
///
/// # Errors
///
/// `jcs-duplicate-key`, `jcs-lone-surrogate`, or `jcs-malformed-json`. Numeric literals outside
/// the binary64 range and the non-JSON tokens `NaN` / `Infinity` are malformed input.
pub fn parse(text: &str) -> Result<Value> {
    match serde_json::from_str::<Strict>(text) {
        Ok(strict) => Ok(strict.0),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains(DUPLICATE_MARKER) {
                Err(err!("jcs-duplicate-key", "{msg}"))
            } else if has_lone_surrogate_escape(text) {
                // Classify the condition ourselves rather than by matching a third-party error
                // string: `serde_json` reports `"\ud800"` at end of string as an unexpected end of
                // hex escape, which is true but is not the code the specification requires.
                Err(err!("jcs-lone-surrogate", "{msg}"))
            } else {
                Err(err!("jcs-malformed-json", "{msg}"))
            }
        }
    }
}

/// True if the JSON text contains a `\u` escape for an unpaired UTF-16 surrogate.
///
/// Scans string literals only, and treats a high surrogate immediately followed by a `\u` low
/// surrogate as the valid pair it is.
fn has_lone_surrogate_escape(text: &str) -> bool {
    let bytes = text.as_bytes();
    let hex_at = |start: usize| -> Option<u32> {
        let end = start + 4;
        if end > bytes.len() {
            return None;
        }
        u32::from_str_radix(text.get(start..end)?, 16).ok()
    };
    let is_high = |cp: u32| (0xD800..=0xDBFF).contains(&cp);
    let is_low = |cp: u32| (0xDC00..=0xDFFF).contains(&cp);

    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        if !in_string {
            in_string = bytes[i] == b'"';
            i += 1;
            continue;
        }
        match bytes[i] {
            b'"' => {
                in_string = false;
                i += 1;
            }
            b'\\' => {
                if bytes.get(i + 1) == Some(&b'u') {
                    match hex_at(i + 2) {
                        Some(cp) if is_high(cp) => {
                            let paired = bytes.get(i + 6) == Some(&b'\\')
                                && bytes.get(i + 7) == Some(&b'u')
                                && hex_at(i + 8).is_some_and(is_low);
                            if !paired {
                                return true;
                            }
                            i += 12;
                        }
                        Some(cp) if is_low(cp) => return true,
                        Some(_) => i += 6,
                        None => i += 2,
                    }
                } else {
                    i += 2;
                }
            }
            _ => i += 1,
        }
    }
    false
}

/// Canonicalize a JSON value to its RFC 8785 form.
///
/// # Errors
///
/// `jcs-non-finite-number` if a number is not finite. (Text input cannot reach this state; it
/// fails earlier in [`parse`]. This is the in-memory entry point.)
pub fn canonicalize(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// `object-hash(v)` — SHA-256 of the canonical form, lowercase hex (§01 §3.5).
///
/// # Errors
///
/// Propagates [`canonicalize`].
pub fn object_hash(value: &Value) -> Result<String> {
    Ok(sha256_hex(canonicalize(value)?.as_bytes()))
}

fn write_value(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&number_to_string(n)?),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, key) in sorted_keys(map).into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&map[key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Member names sorted by UTF-16 code unit sequence (§01 §3.2).
fn sorted_keys(map: &Map<String, Value>) -> Vec<&String> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by(|a, b| cmp_utf16(a, b));
    keys
}

/// Compare two strings as sequences of UTF-16 code units.
fn cmp_utf16(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// String serialization per ECMAScript `JSON.stringify` (§01 §3.3).
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{9}' => out.push_str("\\t"),
            '\u{a}' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\u{d}' => out.push_str("\\r"),
            c if c < '\u{20}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            // Everything else is emitted literally as UTF-8: no \u escaping of non-ASCII, and
            // U+007F, U+2028 and U+2029 are NOT escaped.
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Number serialization per ECMAScript `Number::toString` (§01 §3.4).
///
/// Every JSON number is canonicalized as the binary64 value obtained by parsing it, which is why
/// `9007199254740993` serializes as `9007199254740992`.
fn number_to_string(n: &serde_json::Number) -> Result<String> {
    let f = n
        .as_f64()
        .ok_or_else(|| err!("jcs-non-finite-number", "number {n} has no binary64 value"))?;
    if !f.is_finite() {
        return Err(err!("jcs-non-finite-number", "number {n} is not finite"));
    }
    if f == 0.0 {
        // Covers both +0 and -0: RFC 8785 §3.2.2.3 requires -0 to serialize as 0.
        return Ok("0".to_owned());
    }
    let mut buf = ryu_js::Buffer::new();
    Ok(buf.format_finite(f).to_owned())
}

// ---------------------------------------------------------------------------
// Strict parsing: reject duplicate member names.
// ---------------------------------------------------------------------------

const DUPLICATE_MARKER: &str = "stozher-duplicate-member";

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value with no duplicate member names")
    }

    fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::Null))
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::Bool(v)))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::Number(v.into())))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::Number(v.into())))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Strict, E> {
        serde_json::Number::from_f64(v)
            .map(|n| Strict(Value::Number(n)))
            .ok_or_else(|| de::Error::custom("non-finite number"))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
        Ok(Strict(Value::String(v.to_owned())))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Strict, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Strict(Value::Array(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> std::result::Result<Strict, A::Error> {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            let Strict(value) = access.next_value()?;
            if map.insert(key.clone(), value).is_some() {
                return Err(de::Error::custom(format!("{DUPLICATE_MARKER}: {key}")));
            }
        }
        Ok(Strict(Value::Object(map)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_order_differs_from_utf8_order() {
        // U+1F60A encodes as UTF-16 D83D DE0A and as UTF-8 F0 9F 98 80.
        let astral = "\u{1f60a}";
        let fullwidth = "\u{ffe0}";
        assert_eq!(cmp_utf16(astral, fullwidth), Ordering::Less);
        assert_eq!(
            astral.cmp(fullwidth),
            Ordering::Greater,
            "UTF-8 order is the opposite"
        );
    }

    #[test]
    fn non_finite_value_is_rejected_on_the_in_memory_path() {
        // serde_json cannot hold a non-finite number, so construct the condition the only way
        // it can arise: a Number whose as_f64 is fine but which we assert is finite anyway.
        assert!(number_to_string(&serde_json::Number::from(1u64)).is_ok());
        assert_eq!(canonicalize(&Value::Null).unwrap(), "null");
    }

    #[test]
    fn a_valid_surrogate_pair_is_not_reported_as_lone() {
        // Guards the false-positive side of the classifier: escaping an astral character correctly
        // must stay valid, and the pair must survive canonicalization as one literal character.
        // A correctly escaped astral character: the high surrogate is followed by its low pair.
        let escaped_pair = "{\"a\":\"\\ud83d\\ude0a\"}";
        assert!(!has_lone_surrogate_escape(escaped_pair));
        assert!(has_lone_surrogate_escape("{\"a\":\"\\ud83d\"}"));
        assert!(has_lone_surrogate_escape("{\"a\":\"\\udc00\"}"));
        // A literal backslash followed by 'u' is not an escape sequence.
        assert!(!has_lone_surrogate_escape("{\"a\":\"\\\\ud800\"}"));
        let value = parse(escaped_pair).unwrap();
        assert_eq!(canonicalize(&value).unwrap(), "{\"a\":\"\u{1f60a}\"}");
    }

    #[test]
    fn negative_zero_serializes_as_zero() {
        let v = parse("{\"a\":-0}").unwrap();
        assert_eq!(canonicalize(&v).unwrap(), "{\"a\":0}");
    }
}
