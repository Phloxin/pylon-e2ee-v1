mod codec;
mod gcm;
mod leb128;
mod trailer;

use {
    crate::key::KEY_LEN,
    gcm::{Gcm, NONCE_LEN},
    trailer::Trailer,
};

const VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Codec {
    Opus = 1,
    Vp8 = 2,
    Vp9 = 3,
    Av1 = 4,
    H264 = 5,
    H265 = 6,
}

impl Codec {
    /// Accepts a bare name or a MIME type, in any case: `opus`, `video/H264`, `video/AV1`.
    pub fn from_name(name: &str) -> Option<Self> {
        let name = name.rsplit_once('/').map_or(name, |(_, subtype)| subtype);

        [
            ("opus", Self::Opus),
            ("vp8", Self::Vp8),
            ("vp9", Self::Vp9),
            ("av1", Self::Av1),
            ("h264", Self::H264),
            ("h265", Self::H265),
            ("hevc", Self::H265),
        ]
        .into_iter()
        .find_map(|(known, codec)| known.eq_ignore_ascii_case(name).then_some(codec))
    }

    pub fn from_id(id: u8) -> Option<Self> {
        [
            Self::Opus,
            Self::Vp8,
            Self::Vp9,
            Self::Av1,
            Self::H264,
            Self::H265,
        ]
        .into_iter()
        .find(|codec| *codec as u8 == id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// No key to encrypt with, or none for the frame's epoch.
    NoKey,
    /// The codec bitstream could not be split into clear and protected parts.
    Malformed,
    /// No trailer at the end of the frame (not encrypted, or cut short).
    NoTrailer,
    /// The tag did not verify: wrong key, wrong codec, or the frame was modified.
    Auth,
    /// The counter is used up. The key must change before this sender can send again.
    CounterExhausted,
}

impl FrameError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoKey => "no-key",
            Self::Malformed => "malformed",
            Self::NoTrailer => "no-trailer",
            Self::Auth => "auth",
            Self::CounterExhausted => "counter-exhausted",
        }
    }
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for FrameError {}

fn nonce(kid: u8, counter: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0; NONCE_LEN];
    nonce[0] = kid;
    nonce[NONCE_LEN - 4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn aad(codec: Codec, kid: u8, epoch: u8, counter: u32, codec_aad: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + codec_aad.len());
    aad.extend_from_slice(&[VERSION, codec as u8, kid, epoch]);
    aad.extend_from_slice(&counter.to_be_bytes());
    aad.extend_from_slice(codec_aad);
    aad
}

/// Encrypts every frame one sender process sends. All of the process's sources share it, so
/// one key and one counter never produce the same nonce twice.
pub struct Encryptor {
    kid: u8,
    counter: u32,
    key: Option<(u8, Gcm)>,
}

impl Encryptor {
    /// `counter` is where this process starts counting. The counter never goes back, not even
    /// across key changes, because the same key can come back (phase 0 has one per root).
    pub fn new(kid: u8, counter: u32) -> Self {
        Self {
            kid,
            counter,
            key: None,
        }
    }

    pub fn set_key(&mut self, epoch: u8, key: &[u8; KEY_LEN]) {
        self.key = Some((epoch, Gcm::new(key)));
    }

    pub fn clear_key(&mut self) {
        self.key = None;
    }

    pub fn encrypt(&mut self, codec: Codec, frame: &[u8]) -> Result<Vec<u8>, FrameError> {
        let (epoch, gcm) = self.key.as_ref().ok_or(FrameError::NoKey)?;
        let epoch = *epoch;
        let kid = self.kid;
        let counter = self.counter;
        self.counter = counter.checked_add(1).ok_or(FrameError::CounterExhausted)?;

        codec::seal(codec, frame, |codec_aad, plain| {
            let aad = aad(codec, kid, epoch, counter, codec_aad);
            let tag = gcm.seal(&nonce(kid, counter), &aad, plain);
            Trailer {
                tag,
                counter,
                kid,
                epoch,
            }
            .to_vec()
        })
    }
}

/// Where a decrypted frame came from: its sender process, key epoch and counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameInfo {
    pub kid: u8,
    pub epoch: u8,
    pub counter: u32,
}

/// Decrypts the frames of one sender.
#[derive(Default)]
pub struct Decryptor {
    keys: Vec<(u8, Gcm)>,
}

impl Decryptor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_key(&mut self, epoch: u8, key: &[u8; KEY_LEN]) {
        self.remove_key(epoch);
        self.keys.push((epoch, Gcm::new(key)));
    }

    pub fn remove_key(&mut self, epoch: u8) {
        self.keys.retain(|(e, _)| *e != epoch);
    }

    pub fn decrypt(&self, codec: Codec, frame: &[u8]) -> Result<Vec<u8>, FrameError> {
        self.decrypt_with_info(codec, frame).map(|(plain, _)| plain)
    }

    /// The info is `None` for a frame with nothing to protect (H26X parameter sets, an AV1
    /// sequence header), which goes through as-is.
    pub fn decrypt_with_info(
        &self,
        codec: Codec,
        frame: &[u8],
    ) -> Result<(Vec<u8>, Option<FrameInfo>), FrameError> {
        let mut info = None;
        let plain = codec::open(codec, frame, |codec_aad, cipher, trailer| {
            let (_, gcm) = self
                .keys
                .iter()
                .find(|(epoch, _)| *epoch == trailer.epoch)
                .ok_or(FrameError::NoKey)?;

            let aad = aad(
                codec,
                trailer.kid,
                trailer.epoch,
                trailer.counter,
                codec_aad,
            );
            gcm.open(
                &nonce(trailer.kid, trailer.counter),
                &aad,
                cipher,
                &trailer.tag,
            )
            .then_some(())
            .ok_or(FrameError::Auth)?;

            info = Some(FrameInfo {
                kid: trailer.kid,
                epoch: trailer.epoch,
                counter: trailer.counter,
            });
            Ok(())
        })?;

        Ok((plain, info))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// xorshift64*, enough to generate test inputs without a dependency.
    pub(crate) struct Rng(u64);

    impl Rng {
        pub(crate) fn new(seed: u64) -> Self {
            Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
        }

        pub(crate) fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        pub(crate) fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        pub(crate) fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| self.next() as u8).collect()
        }

        pub(crate) fn array<const N: usize>(&mut self) -> [u8; N] {
            std::array::from_fn(|_| self.next() as u8)
        }
    }

    pub(crate) fn pair(sender: u64) -> (Encryptor, Decryptor) {
        let key = crate::key::static_sender_key(b"test root", sender);
        let mut encryptor = Encryptor::new(0, 0);
        encryptor.set_key(0, &key);
        let mut decryptor = Decryptor::new();
        decryptor.set_key(0, &key);
        (encryptor, decryptor)
    }

    #[test]
    fn codec_names() {
        assert_eq!(Codec::from_name("audio/opus"), Some(Codec::Opus));
        assert_eq!(Codec::from_name("video/H264"), Some(Codec::H264));
        assert_eq!(Codec::from_name("AV1"), Some(Codec::Av1));
        assert_eq!(Codec::from_name("video/H265"), Some(Codec::H265));
        assert_eq!(Codec::from_name("video/rtx"), None);
        for codec in [
            Codec::Opus,
            Codec::Vp8,
            Codec::Vp9,
            Codec::Av1,
            Codec::H264,
            Codec::H265,
        ] {
            assert_eq!(Codec::from_id(codec as u8), Some(codec));
        }
    }

    #[test]
    fn counter_advances_and_never_reuses_a_nonce() {
        let (mut encryptor, decryptor) = pair(1);
        let a = encryptor.encrypt(Codec::Opus, b"same").unwrap();
        let b = encryptor.encrypt(Codec::Opus, b"same").unwrap();
        assert_ne!(a, b);
        let (plain, info) = decryptor.decrypt_with_info(Codec::Opus, &a).unwrap();
        assert_eq!(
            (plain.as_slice(), info.map(|i| i.counter)),
            (&b"same"[..], Some(0))
        );
        let (plain, info) = decryptor.decrypt_with_info(Codec::Opus, &b).unwrap();
        assert_eq!(
            (plain.as_slice(), info.map(|i| i.counter)),
            (&b"same"[..], Some(1))
        );
    }

    #[test]
    fn counter_exhaustion_stops_encryption() {
        let mut encryptor = Encryptor::new(0, u32::MAX);
        encryptor.set_key(0, &[1; 16]);
        assert_eq!(
            encryptor.encrypt(Codec::Opus, b"x"),
            Err(FrameError::CounterExhausted)
        );
    }

    #[test]
    fn no_key() {
        let mut encryptor = Encryptor::new(0, 0);
        assert_eq!(encryptor.encrypt(Codec::Opus, b"x"), Err(FrameError::NoKey));

        let (mut encryptor, _) = pair(1);
        let sealed = encryptor.encrypt(Codec::Opus, b"x").unwrap();
        assert_eq!(
            Decryptor::new().decrypt(Codec::Opus, &sealed),
            Err(FrameError::NoKey)
        );
    }

    #[test]
    fn wrong_sender_key_codec_or_epoch_fails() {
        let (mut encryptor, _) = pair(1);
        let (_, other) = pair(2);
        let (_, right) = pair(1);
        let sealed = encryptor.encrypt(Codec::Vp9, &[5; 64]).unwrap();

        assert_eq!(other.decrypt(Codec::Vp9, &sealed), Err(FrameError::Auth));
        assert_eq!(right.decrypt(Codec::Opus, &sealed), Err(FrameError::Auth));

        let mut moved = Decryptor::new();
        moved.set_key(1, &crate::key::static_sender_key(b"test root", 1));
        assert_eq!(moved.decrypt(Codec::Vp9, &sealed), Err(FrameError::NoKey));
    }

    #[test]
    fn plaintext_frames_are_rejected() {
        let (_, decryptor) = pair(1);
        for codec in [Codec::Opus, Codec::Vp8, Codec::Vp9] {
            assert_eq!(
                decryptor.decrypt(codec, &[0x10; 40]),
                Err(FrameError::NoTrailer)
            );
        }
    }

    #[test]
    fn garbage_never_panics() {
        let (_, decryptor) = pair(1);
        let mut rng = Rng::new(42);
        for codec in [
            Codec::Opus,
            Codec::Vp8,
            Codec::Vp9,
            Codec::Av1,
            Codec::H264,
            Codec::H265,
        ] {
            for _ in 0..4000 {
                let len = rng.below(96);
                let mut frame = rng.bytes(len);
                if rng.below(2) == 0 {
                    frame.extend_from_slice(&[0, 0, 0, 1, 0x65]);
                    let len = rng.below(40);
                    frame.extend(rng.bytes(len));
                }
                if rng.below(2) == 0 {
                    frame.extend_from_slice(&[12, 0xFA, 0xFA]);
                }
                let _ = decryptor.decrypt(codec, &frame);
            }
        }
    }
}
