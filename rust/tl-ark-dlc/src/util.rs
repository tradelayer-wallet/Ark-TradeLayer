//! Small non-cryptographic helpers: strict hex and bounded text checks.

use crate::error::{Error, Result};

/// Lower-case hex encoding.
pub fn to_hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

fn nib(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::Malformed("non-hex character")),
    }
}

/// Strict hex decoding: even length, hex digits only. (Node `Buffer.from(s, "hex")` silently
/// truncates at the first bad character; this does not.)
pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return Err(Error::Malformed("odd-length hex"));
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Ok(out)
}

/// Decode exactly 32 bytes from hex.
pub fn hex32(s: &str) -> Result<[u8; 32]> {
    let v = from_hex(s)?;
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| Error::Malformed("expected 32 bytes"))
}

/// Identifier text: non-empty, bounded, printable ASCII without spaces or control characters.
pub fn check_ident(s: &str, max: usize, what: &'static str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::Malformed(what));
    }
    if s.len() > max {
        return Err(Error::TooLarge(what));
    }
    if !s.bytes().all(|b| (0x21..0x7f).contains(&b)) {
        return Err(Error::Malformed(what));
    }
    Ok(())
}

/// Free text: bounded, no control characters.
pub fn check_text(s: &str, max: usize, what: &'static str) -> Result<()> {
    if s.len() > max {
        return Err(Error::TooLarge(what));
    }
    if s.chars().any(|c| c.is_control()) {
        return Err(Error::Malformed(what));
    }
    Ok(())
}
