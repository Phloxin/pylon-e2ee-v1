use hkdf::Hkdf;
use sha2::Sha256;

pub const KEY_LEN: usize = 16;

/// Length of an epoch's frame root, the MLS exporter output (plan section 4).
pub const ROOT_LEN: usize = 32;

/// MLS exporter label for an epoch's frame root.
pub const ROOT_LABEL: &str = "pylon frame root";

/// A sender's frame key for one epoch (plan section 4):
/// `HKDF-SHA256(salt = "pylon frame v1", ikm = root, info = client_id BE, L = 16)`.
///
/// `root` is the epoch's exporter output. Phase 0 passed a shared static text instead, so only
/// the root changed when MLS landed.
pub fn sender_key(root: &[u8], client_id: u64) -> [u8; KEY_LEN] {
    let mut key = [0; KEY_LEN];
    Hkdf::<Sha256>::new(Some(b"pylon frame v1"), root)
        .expand(&client_id.to_be_bytes(), &mut key)
        .expect("16 bytes is a valid HKDF-SHA256 output length");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_differ_per_sender_and_root() {
        let a = sender_key(b"root", 1);
        assert_eq!(a, sender_key(b"root", 1));
        assert_ne!(a, sender_key(b"root", 2));
        assert_ne!(a, sender_key(b"other", 1));
    }
}
