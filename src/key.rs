use hkdf::Hkdf;
use sha2::Sha256;

pub const KEY_LEN: usize = 16;

/// Phase 0 stand-in for the MLS exporter: every client derives a sender's key from a shared
/// root and that sender's client id, so only the root changes once MLS lands.
pub fn static_sender_key(root: &[u8], client_id: u64) -> [u8; KEY_LEN] {
    let mut key = [0; KEY_LEN];
    Hkdf::<Sha256>::new(Some(b"pylon frame v1 static"), root)
        .expand(&client_id.to_be_bytes(), &mut key)
        .expect("16 bytes is a valid HKDF-SHA256 output length");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_differ_per_sender_and_root() {
        let a = static_sender_key(b"root", 1);
        assert_eq!(a, static_sender_key(b"root", 1));
        assert_ne!(a, static_sender_key(b"root", 2));
        assert_ne!(a, static_sender_key(b"other", 1));
    }
}
