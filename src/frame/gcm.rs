//! AES-128-GCM with a 64-bit tag. RustCrypto's `aes-gcm` only goes down to 96-bit tags, so this
//! is GCM (NIST SP 800-38D) built from its parts and checked against `aes-gcm` in the tests.

use {
    aes::{
        Aes128,
        cipher::{
            BlockEncrypt, InnerIvInit, KeyInit, StreamCipher, StreamCipherCoreWrapper,
            generic_array::GenericArray,
        },
    },
    ghash::{GHash, universal_hash::UniversalHash},
    subtle::ConstantTimeEq,
};

pub(crate) const TAG_LEN: usize = 8;
pub(crate) const NONCE_LEN: usize = 12;

type CtrCore = ctr::CtrCore<Aes128, ctr::flavors::Ctr32BE>;

pub(crate) struct Gcm {
    cipher: Aes128,
    hash_key: [u8; 16],
}

impl Gcm {
    pub(crate) fn new(key: &[u8; 16]) -> Self {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let mut hash_key = GenericArray::default();
        cipher.encrypt_block(&mut hash_key);

        Self {
            cipher,
            hash_key: hash_key.into(),
        }
    }

    pub(crate) fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> [u8; TAG_LEN] {
        self.keystream(nonce, buf);
        self.tag(nonce, aad, buf)
    }

    pub(crate) fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> bool {
        if !bool::from(self.tag(nonce, aad, buf).ct_eq(tag)) {
            return false;
        }

        self.keystream(nonce, buf);
        true
    }

    fn keystream(&self, nonce: &[u8; NONCE_LEN], buf: &mut [u8]) {
        let core = CtrCore::inner_iv_init(self.cipher.clone(), &counter_block(nonce, 2).into());
        StreamCipherCoreWrapper::from_core(core).apply_keystream(buf);
    }

    fn tag(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
        let mut ghash = GHash::new(&self.hash_key.into());
        ghash.update_padded(aad);
        ghash.update_padded(ciphertext);

        let mut lengths = [0; 16];
        lengths[..8].copy_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&(ciphertext.len() as u64 * 8).to_be_bytes());
        ghash.update(&[lengths.into()]);

        let mut mask = GenericArray::from(counter_block(nonce, 1));
        self.cipher.encrypt_block(&mut mask);

        let full = ghash.finalize();
        let mut tag = [0; TAG_LEN];
        for (i, byte) in tag.iter_mut().enumerate() {
            *byte = full[i] ^ mask[i];
        }
        tag
    }
}

fn counter_block(nonce: &[u8; NONCE_LEN], counter: u32) -> [u8; 16] {
    let mut block = [0; 16];
    block[..NONCE_LEN].copy_from_slice(nonce);
    block[NONCE_LEN..].copy_from_slice(&counter.to_be_bytes());
    block
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::frame::tests::Rng,
        aes_gcm::{AeadInPlace, Aes128Gcm},
    };

    #[test]
    fn matches_aes_gcm_truncated() {
        let mut rng = Rng::new(7);
        for len in [0, 1, 15, 16, 17, 31, 32, 33, 100, 1500, 65_536] {
            for aad_len in [0, 1, 8, 16, 37] {
                let key: [u8; 16] = rng.array();
                let nonce: [u8; 12] = rng.array();
                let aad = rng.bytes(aad_len);
                let plain = rng.bytes(len);

                let mut ours = plain.clone();
                let tag = Gcm::new(&key).seal(&nonce, &aad, &mut ours);

                let mut theirs = plain.clone();
                let full = Aes128Gcm::new(&key.into())
                    .encrypt_in_place_detached(&nonce.into(), &aad, &mut theirs)
                    .unwrap();

                assert_eq!(ours, theirs);
                assert_eq!(tag, full[..TAG_LEN]);
            }
        }
    }

    #[test]
    fn open_round_trips_and_rejects_tampering() {
        let mut rng = Rng::new(9);
        let key: [u8; 16] = rng.array();
        let nonce: [u8; 12] = rng.array();
        let gcm = Gcm::new(&key);
        let plain = rng.bytes(300);

        let mut buf = plain.clone();
        let tag = gcm.seal(&nonce, b"aad", &mut buf);
        let sealed = buf.clone();

        assert!(gcm.open(&nonce, b"aad", &mut buf, &tag));
        assert_eq!(buf, plain);

        let mut flipped = sealed.clone();
        flipped[10] ^= 1;
        assert!(!gcm.open(&nonce, b"aad", &mut flipped, &tag));
        assert_eq!(
            flipped[10],
            sealed[10] ^ 1,
            "a rejected open leaves the buffer encrypted"
        );

        assert!(!gcm.open(&nonce, b"aaD", &mut sealed.clone(), &tag));
    }
}
