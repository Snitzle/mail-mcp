//! Modified UTF-7 (RFC 3501 §5.1.3), the encoding IMAP uses for non-ASCII mailbox names.

use base64::Engine;
use base64::alphabet::Alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

/// Base64 with `,` in place of `/`, written without padding.
fn engine() -> GeneralPurpose {
    // The alphabet literal is valid by construction, so this cannot fail.
    let alphabet =
        Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,")
            .unwrap_or(base64::alphabet::STANDARD);
    let config = GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent);
    GeneralPurpose::new(&alphabet, config)
}

/// Encode a mailbox name for the wire.
pub fn encode(name: &str) -> String {
    let engine = engine();
    let mut out = String::with_capacity(name.len());
    let mut pending: Vec<u16> = Vec::new();

    let flush = |pending: &mut Vec<u16>, out: &mut String| {
        if pending.is_empty() {
            return;
        }
        let bytes: Vec<u8> = pending.iter().flat_map(|unit| unit.to_be_bytes()).collect();
        out.push('&');
        out.push_str(&engine.encode(bytes));
        out.push('-');
        pending.clear();
    };

    for c in name.chars() {
        if (' '..='~').contains(&c) {
            flush(&mut pending, &mut out);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut buf = [0u16; 2];
            pending.extend_from_slice(c.encode_utf16(&mut buf));
        }
    }
    flush(&mut pending, &mut out);
    out
}

/// Decode a mailbox name from the wire. Sequences that are not valid modified UTF-7 are
/// kept as written, so a strange name is still shown rather than lost.
pub fn decode(wire: &str) -> String {
    let engine = engine();
    let mut out = String::with_capacity(wire.len());
    let mut rest = wire;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('-') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let chunk = &after[..end];
        if chunk.is_empty() {
            out.push('&');
        } else {
            match decode_chunk(&engine, chunk) {
                Some(text) => out.push_str(&text),
                None => out.push_str(&rest[start..start + end + 2]),
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

fn decode_chunk(engine: &GeneralPurpose, chunk: &str) -> Option<String> {
    let bytes = engine.decode(chunk).ok()?;
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_passes_through() {
        assert_eq!(encode("INBOX/Receipts 2026"), "INBOX/Receipts 2026");
        assert_eq!(decode("INBOX/Receipts 2026"), "INBOX/Receipts 2026");
    }

    #[test]
    fn ampersand_is_escaped() {
        assert_eq!(encode("Bills & Tax"), "Bills &- Tax");
        assert_eq!(decode("Bills &- Tax"), "Bills & Tax");
    }

    #[test]
    fn rfc_examples_round_trip() {
        // From RFC 3501 §5.1.3.
        assert_eq!(
            decode("~peter/mail/&U,BTFw-/&ZeVnLIqe-"),
            "~peter/mail/台北/日本語"
        );
        assert_eq!(
            encode("~peter/mail/台北/日本語"),
            "~peter/mail/&U,BTFw-/&ZeVnLIqe-"
        );
    }

    #[test]
    fn non_bmp_round_trips() {
        let name = "Photos 📷/Été";
        assert_eq!(decode(&encode(name)), name);
        assert!(encode(name).is_ascii());
    }

    #[test]
    fn malformed_input_is_preserved() {
        assert_eq!(decode("a&b"), "a&b");
        assert_eq!(decode("a&!!!-b"), "a&!!!-b");
        assert_eq!(decode("a&AA-b"), "a&AA-b");
    }
}
