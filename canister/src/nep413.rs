//! NEP-413 message encoding (off-chain signed messages), as specified in
//! <https://github.com/near/NEPs/blob/master/neps/nep-0413.md>.
//!
//! What gets signed is `sha256(tag || borsh(payload))` where
//!   tag     = u32 2^31 + 413, little-endian
//!   payload = { message: string, nonce: [u8; 32], recipient: string,
//!               callbackUrl: Option<string> }
//! Borsh: strings carry a u32 length prefix, a fixed array has none, an
//! Option is one byte (0 = None, 1 = Some) followed by the value.
//!
//! Pure code, tested natively against signatures made by NEAR's own JS library
//! (`tests/vectors/nep413.json`).

use sha2::{Digest, Sha256};

/// 2^31 + 413. The high bit keeps NEP-413 payloads from ever being valid
/// Borsh transactions (a transaction starts with the signer id's length).
pub const NEP413_TAG: u32 = (1 << 31) + 413;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload<'a> {
    pub message: &'a str,
    pub nonce: &'a [u8; 32],
    pub recipient: &'a str,
    pub callback_url: Option<&'a str>,
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    // Callers bound every string far below 4 GiB (see `policy`).
    out.extend_from_slice(&u32::try_from(s.len()).expect("string longer than u32").to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

impl Payload<'_> {
    /// `tag || borsh(payload)`: the bytes whose SHA-256 is signed.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 4 + self.message.len() + 32 + 4 + self.recipient.len() + 5);
        out.extend_from_slice(&NEP413_TAG.to_le_bytes());
        put_str(&mut out, self.message);
        out.extend_from_slice(self.nonce);
        put_str(&mut out, self.recipient);
        match self.callback_url {
            None => out.push(0),
            Some(url) => {
                out.push(1);
                put_str(&mut out, url);
            }
        }
        out
    }

    /// What the Ed25519 key signs.
    pub fn signing_hash(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout() {
        let nonce = [7u8; 32];
        let p = Payload { message: "hi", nonce: &nonce, recipient: "ab", callback_url: None };
        let mut want = vec![0x9d, 0x01, 0x00, 0x80]; // 2147484061 LE
        want.extend_from_slice(&[2, 0, 0, 0, b'h', b'i']);
        want.extend_from_slice(&nonce);
        want.extend_from_slice(&[2, 0, 0, 0, b'a', b'b']);
        want.push(0);
        assert_eq!(p.encode(), want);

        let with_url = Payload { callback_url: Some("u"), ..p };
        let enc = with_url.encode();
        assert_eq!(&enc[enc.len() - 6..], &[1, 1, 0, 0, 0, b'u']);
    }
}
