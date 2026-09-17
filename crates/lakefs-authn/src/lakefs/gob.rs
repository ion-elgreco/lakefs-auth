//! Go `encoding/gob` encoder and decoder for `map[interface{}]interface{}{"token": <string>}`.
//!
//! gorilla sessions serializes `Session.Values` with `gob`, so lakeFS reads exactly
//! this shape. Only the one shape is supported, in both directions, on purpose.
//!
//! Wire facts taken from the Go source and pinned by `fixtures/sessions.json`:
//!
//! * An unsigned integer below 128 is one byte. Larger values are a negated byte
//!   count (`256 - n`) followed by the big-endian minimal bytes.
//! * A signed integer is `i << 1`, or `(!i << 1) | 1` when negative, sent as unsigned.
//! * A struct omits fields that hold the zero value, so the unnamed map type sends
//!   no `CommonType.Name` and the field delta jumps straight to `CommonType.Id`.
//! * An interface value is the concrete type name, the type id, then a
//!   length-prefixed message holding the value.
//! * A top-level value that is not a struct is a singleton: a zero field delta
//!   comes before the value.
//! * The stream is two length-prefixed messages: the map type definition and the value.

/// Type id Go assigns to the first user type in the stream.
pub const MAP_TYPE_ID: i64 = 64;
/// Type id Go 1.20 and older assign, which lakeFS also accepts.
const LEGACY_MAP_TYPE_ID: i64 = 65;
/// Built-in gob type id of `string`.
const STRING_TYPE_ID: i64 = 6;
/// Built-in gob type id of `interface {}`.
const INTERFACE_TYPE_ID: i64 = 8;
/// Field index of `wireType.MapT`.
const WIRE_TYPE_MAP_FIELD: u64 = 3;
/// `reflect.Type.Name()` of the map gorilla serializes, which is empty because the
/// type is unnamed. Go therefore omits the field; a provider of a named map type
/// would send this string instead.
const MAP_TYPE_NAME: &str = "map[interface {}]interface {}";
/// Name Go registers for the `string` concrete type.
const STRING_TYPE_NAME: &str = "string";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GobError {
    #[error("gob stream ended early")]
    Truncated,
    #[error("gob integer is too large")]
    IntegerTooLarge,
    #[error("gob stream has trailing bytes")]
    TrailingBytes,
    #[error("unexpected gob type id {0}")]
    UnexpectedTypeId(i64),
    #[error("unexpected gob type name {0:?}")]
    UnexpectedTypeName(String),
    #[error("unexpected gob structure: {0}")]
    Unexpected(&'static str),
    #[error("gob string is not valid UTF-8")]
    NotUtf8,
}

/// Encodes `map[interface{}]interface{}{"token": token}` exactly as Go does.
pub fn encode_token_map(token: &str) -> Vec<u8> {
    let mut stream = Vec::new();
    stream.extend(message(type_definition(MAP_TYPE_ID)));
    stream.extend(message(map_value(MAP_TYPE_ID, &[("token", token)])));
    stream
}

/// Reads back a stream produced by [`encode_token_map`] and returns the `token` entry.
pub fn decode_token_map(stream: &[u8]) -> Result<String, GobError> {
    let entries = decode_string_map(stream)?;
    entries
        .into_iter()
        .find(|(key, _)| key == "token")
        .map(|(_, value)| value)
        .ok_or(GobError::Unexpected("no token entry in the session map"))
}

/// Strictly decodes the two-message stream into its string key and value pairs.
fn decode_string_map(stream: &[u8]) -> Result<Vec<(String, String)>, GobError> {
    let mut cursor = Cursor::new(stream);
    let definition = cursor.message()?;
    let type_id = read_type_definition(definition)?;
    let value = cursor.message()?;
    let entries = read_map_value(value, type_id)?;
    if !cursor.is_empty() {
        return Err(GobError::TrailingBytes);
    }
    Ok(entries)
}

fn type_definition(type_id: i64) -> Vec<u8> {
    let mut out = Vec::new();
    // A type definition announces itself with the negated type id.
    encode_int(&mut out, -type_id);
    // wireType.MapT, field 3, delta from the initial field number -1.
    encode_uint(&mut out, WIRE_TYPE_MAP_FIELD + 1);
    // mapType.CommonType, field 0.
    encode_uint(&mut out, 1);
    // CommonType.Id, field 1. Field 0, the name, is empty and therefore omitted.
    encode_uint(&mut out, 2);
    encode_int(&mut out, type_id);
    encode_uint(&mut out, 0);
    // mapType.Key, field 1.
    encode_uint(&mut out, 1);
    encode_int(&mut out, INTERFACE_TYPE_ID);
    // mapType.Elem, field 2.
    encode_uint(&mut out, 1);
    encode_int(&mut out, INTERFACE_TYPE_ID);
    encode_uint(&mut out, 0);
    encode_uint(&mut out, 0);
    out
}

fn map_value(type_id: i64, entries: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_int(&mut out, type_id);
    // Singleton values carry a zero field delta before the value itself.
    encode_uint(&mut out, 0);
    encode_uint(&mut out, entries.len() as u64);
    for (key, value) in entries {
        encode_interface_string(&mut out, key);
        encode_interface_string(&mut out, value);
    }
    out
}

fn encode_interface_string(out: &mut Vec<u8>, value: &str) {
    encode_string(out, STRING_TYPE_NAME);
    encode_int(out, STRING_TYPE_ID);
    let mut inner = Vec::new();
    encode_uint(&mut inner, 0);
    encode_string(&mut inner, value);
    out.extend(message(inner));
}

fn message(body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 9);
    encode_uint(&mut out, body.len() as u64);
    out.extend(body);
    out
}

pub(crate) fn encode_uint(out: &mut Vec<u8>, value: u64) {
    if value < 128 {
        out.push(value as u8);
        return;
    }
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len() - 1);
    let significant = &bytes[first..];
    out.push((256 - significant.len()) as u8);
    out.extend_from_slice(significant);
}

pub(crate) fn encode_int(out: &mut Vec<u8>, value: i64) {
    let encoded = if value < 0 {
        ((!value as u64) << 1) | 1
    } else {
        (value as u64) << 1
    };
    encode_uint(out, encoded);
}

fn encode_string(out: &mut Vec<u8>, value: &str) {
    encode_uint(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], GobError> {
        if self.bytes.len() < count {
            return Err(GobError::Truncated);
        }
        let (head, tail) = self.bytes.split_at(count);
        self.bytes = tail;
        Ok(head)
    }

    fn uint(&mut self) -> Result<u64, GobError> {
        let first = *self.take(1)?.first().ok_or(GobError::Truncated)?;
        if first < 128 {
            return Ok(u64::from(first));
        }
        let count = usize::from(256u16 - u16::from(first));
        if count > 8 {
            return Err(GobError::IntegerTooLarge);
        }
        let bytes = self.take(count)?;
        let mut value = 0u64;
        for byte in bytes {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(value)
    }

    fn int(&mut self) -> Result<i64, GobError> {
        let raw = self.uint()?;
        Ok(if raw & 1 == 1 {
            !((raw >> 1) as i64)
        } else {
            (raw >> 1) as i64
        })
    }

    fn string(&mut self) -> Result<String, GobError> {
        let len = usize::try_from(self.uint()?).map_err(|_| GobError::IntegerTooLarge)?;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| GobError::NotUtf8)
    }

    fn message(&mut self) -> Result<&'a [u8], GobError> {
        let len = usize::try_from(self.uint()?).map_err(|_| GobError::IntegerTooLarge)?;
        self.take(len)
    }

    fn expect_uint(&mut self, expected: u64, what: &'static str) -> Result<(), GobError> {
        if self.uint()? == expected {
            Ok(())
        } else {
            Err(GobError::Unexpected(what))
        }
    }
}

fn read_type_definition(body: &[u8]) -> Result<i64, GobError> {
    let mut cursor = Cursor::new(body);
    let announced = cursor.int()?;
    if announced >= 0 {
        return Err(GobError::Unexpected("first message is not a type definition"));
    }
    let type_id = -announced;
    if type_id != MAP_TYPE_ID && type_id != LEGACY_MAP_TYPE_ID {
        return Err(GobError::UnexpectedTypeId(type_id));
    }
    cursor.expect_uint(WIRE_TYPE_MAP_FIELD + 1, "type definition is not a map type")?;
    cursor.expect_uint(1, "map type has no common type")?;
    // Go omits the empty type name, so the delta to `Id` is 2. A named map type
    // would send the name first and then a delta of 1.
    match cursor.uint()? {
        2 => {}
        1 => {
            let name = cursor.string()?;
            if name != MAP_TYPE_NAME {
                return Err(GobError::UnexpectedTypeName(name));
            }
            cursor.expect_uint(1, "map type has no id")?;
        }
        _ => return Err(GobError::Unexpected("map type has no id")),
    }
    if cursor.int()? != type_id {
        return Err(GobError::Unexpected("map type id does not match the definition"));
    }
    cursor.expect_uint(0, "common type is not terminated")?;
    cursor.expect_uint(1, "map type has no key type")?;
    if cursor.int()? != INTERFACE_TYPE_ID {
        return Err(GobError::Unexpected("map key is not an interface"));
    }
    cursor.expect_uint(1, "map type has no element type")?;
    if cursor.int()? != INTERFACE_TYPE_ID {
        return Err(GobError::Unexpected("map element is not an interface"));
    }
    cursor.expect_uint(0, "map type is not terminated")?;
    cursor.expect_uint(0, "wire type is not terminated")?;
    if !cursor.is_empty() {
        return Err(GobError::TrailingBytes);
    }
    Ok(type_id)
}

fn read_map_value(body: &[u8], type_id: i64) -> Result<Vec<(String, String)>, GobError> {
    let mut cursor = Cursor::new(body);
    if cursor.int()? != type_id {
        return Err(GobError::Unexpected("value message has a different type id"));
    }
    cursor.expect_uint(0, "singleton delta is missing")?;
    let count = usize::try_from(cursor.uint()?).map_err(|_| GobError::IntegerTooLarge)?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let key = read_interface_string(&mut cursor)?;
        let value = read_interface_string(&mut cursor)?;
        entries.push((key, value));
    }
    if !cursor.is_empty() {
        return Err(GobError::TrailingBytes);
    }
    Ok(entries)
}

fn read_interface_string(cursor: &mut Cursor<'_>) -> Result<String, GobError> {
    let name = cursor.string()?;
    if name != STRING_TYPE_NAME {
        return Err(GobError::UnexpectedTypeName(name));
    }
    if cursor.int()? != STRING_TYPE_ID {
        return Err(GobError::Unexpected("interface value is not a string"));
    }
    let inner = cursor.message()?;
    let mut inner = Cursor::new(inner);
    inner.expect_uint(0, "interface value has no singleton delta")?;
    let value = inner.string()?;
    if !inner.is_empty() {
        return Err(GobError::TrailingBytes);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn uint(value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        encode_uint(&mut out, value);
        out
    }

    fn int(value: i64) -> Vec<u8> {
        let mut out = Vec::new();
        encode_int(&mut out, value);
        out
    }

    #[test]
    fn unsigned_integers_match_the_go_boundaries() {
        let table: [(u64, &[u8]); 10] = [
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0xff, 0x80]),
            (255, &[0xff, 0xff]),
            (256, &[0xfe, 0x01, 0x00]),
            (65535, &[0xfe, 0xff, 0xff]),
            (65536, &[0xfd, 0x01, 0x00, 0x00]),
            (16777215, &[0xfd, 0xff, 0xff, 0xff]),
            (16777216, &[0xfc, 0x01, 0x00, 0x00, 0x00]),
        ];
        for (value, expected) in table {
            assert_eq!(uint(value), expected, "uint {value}");
        }
        assert_eq!(uint(u64::MAX), [0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn signed_integers_use_the_go_zigzag() {
        let table: [(i64, &[u8]); 6] = [
            (0, &[0x00]),
            (6, &[0x0c]),
            (8, &[0x10]),
            (64, &[0xff, 0x80]),
            (-1, &[0x01]),
            (-64, &[0x7f]),
        ];
        for (value, expected) in table {
            assert_eq!(int(value), expected, "int {value}");
        }
    }

    #[test]
    fn integers_round_trip_through_the_decoder() {
        for value in [0u64, 1, 127, 128, 255, 256, 65535, 65536, u64::MAX] {
            let bytes = uint(value);
            assert_eq!(Cursor::new(&bytes).uint().unwrap(), value);
        }
        for value in [0i64, 1, -1, 64, -64, i64::MAX, i64::MIN] {
            let bytes = int(value);
            assert_eq!(Cursor::new(&bytes).int().unwrap(), value);
        }
    }

    #[test]
    fn short_token_encodes_to_the_expected_bytes() {
        // Byte for byte what Go emits; see fixtures/sessions.json for the generated proof.
        let mut expected: Vec<u8> = vec![
            // Message one, 13 bytes: the definition of the map type.
            0x0d, 0x7f, 0x04, 0x01, 0x02, 0xff, 0x80, 0x00, 0x01, 0x10, 0x01, 0x10, 0x00, 0x00,
            // Message two, 34 bytes: type id 64, singleton delta, map length.
            0x22, 0xff, 0x80, 0x00, 0x01, //
            0x06,
        ];
        expected.extend(b"string");
        expected.extend([0x0c, 0x07, 0x00, 0x05]);
        expected.extend(b"token");
        expected.push(0x06);
        expected.extend(b"string");
        expected.extend([0x0c, 0x05, 0x00, 0x03]);
        expected.extend(b"abc");
        assert_eq!(encode_token_map("abc"), expected);
    }

    #[test]
    fn round_trips_every_interesting_length() {
        for length in [0usize, 1, 5, 100, 127, 128, 129, 200, 255, 256, 257, 1000, 65535, 65536] {
            let token = "x".repeat(length);
            let encoded = encode_token_map(&token);
            assert_eq!(decode_token_map(&encoded).unwrap(), token, "length {length}");
        }
    }

    #[test]
    fn decoder_accepts_the_legacy_map_type_id() {
        let mut stream = Vec::new();
        stream.extend(message(type_definition(LEGACY_MAP_TYPE_ID)));
        stream.extend(message(map_value(LEGACY_MAP_TYPE_ID, &[("token", "jwt")])));
        assert_eq!(decode_token_map(&stream).unwrap(), "jwt");
    }

    #[test]
    fn decoder_rejects_damaged_streams() {
        let encoded = encode_token_map("abc");
        assert_eq!(
            decode_token_map(&encoded[..encoded.len() - 1]),
            Err(GobError::Truncated)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(decode_token_map(&trailing), Err(GobError::TrailingBytes));
        let mut wrong_type = encoded.clone();
        wrong_type[1] = 0x7d; // announces type id 63
        assert_eq!(decode_token_map(&wrong_type), Err(GobError::UnexpectedTypeId(63)));
        assert_eq!(decode_token_map(&[]), Err(GobError::Truncated));
    }

    #[test]
    fn decoder_reports_a_missing_token_entry() {
        let mut stream = Vec::new();
        stream.extend(message(type_definition(MAP_TYPE_ID)));
        stream.extend(message(map_value(MAP_TYPE_ID, &[("other", "value")])));
        assert!(matches!(decode_token_map(&stream), Err(GobError::Unexpected(_))));
        assert_eq!(
            decode_string_map(&stream).unwrap(),
            vec![("other".to_owned(), "value".to_owned())]
        );
    }
}
