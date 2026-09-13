use base64::{Engine, engine::general_purpose::STANDARD};
use std::time::{SystemTime, UNIX_EPOCH};

// Public iNode V7 wire-format compatibility information, not an account secret.
const MIX: &[u8] = b"Oly5D62FaE94W7";

fn mix(data: &mut [u8], key: &[u8]) {
    let len = data.len();
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()] ^ key[(len - 1 - i) % key.len()];
    }
}

pub fn client_private() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut nonce = now.subsec_nanos();
    let encoded = loop {
        let mut data = [0u8; 20];
        data[..13].copy_from_slice(b"EN\x11V7.30-0645");
        let random = nonce.to_le_bytes();
        let key: String = random.iter().map(|b| format!("{b:02x}")).collect();
        mix(&mut data[..16], key.as_bytes());
        data[16..].copy_from_slice(&random);
        mix(&mut data, MIX);
        if !data.contains(&0) {
            break data;
        }
        nonce = nonce.wrapping_add(1);
    };
    let mut tlv = vec![1, 22];
    tlv.extend_from_slice(&encoded);
    STANDARD.encode(tlv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_roundtrip_has_valid_tlv_and_public_version() {
        let bytes = STANDARD.decode(client_private()).unwrap();
        assert_eq!(&bytes[..2], &[1, 22]);
        assert_eq!(bytes.len(), 22);
        let mut data = bytes[2..].to_vec();
        mix(&mut data, MIX);
        let key: String = data[16..].iter().map(|b| format!("{b:02x}")).collect();
        mix(&mut data[..16], key.as_bytes());
        assert_eq!(&data[..13], b"EN\x11V7.30-0645");
    }
}
