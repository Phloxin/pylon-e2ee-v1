mod codec;
mod gcm;
mod leb128;
mod source;
mod trailer;

use {
    crate::key::KEY_LEN,
    gcm::{Gcm, NONCE_LEN},
    trailer::Trailer,
};

pub use {crate::format::Format, source::Source};

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
    /// A counter already seen, or older than the window.
    Replay,
}

impl FrameError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoKey => "no-key",
            Self::Malformed => "malformed",
            Self::NoTrailer => "no-trailer",
            Self::Auth => "auth",
            Self::CounterExhausted => "counter-exhausted",
            Self::Replay => "replay",
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

struct Header<'a> {
    format: Format,
    codec: Codec,
    kid: u8,
    epoch: u8,
    counter: u32,
    source: &'a Source,
}

impl Header<'_> {
    /// `format || codec || kid || epoch || counter_be32 || source || codec AAD` (plan 3.4).
    fn aad(&self, codec_aad: &[u8]) -> Vec<u8> {
        let source = self.source.as_bytes();
        let mut aad = Vec::with_capacity(8 + source.len() + codec_aad.len());
        aad.extend_from_slice(&[self.format as u8, self.codec as u8, self.kid, self.epoch]);
        aad.extend_from_slice(&self.counter.to_be_bytes());
        aad.extend_from_slice(source);
        aad.extend_from_slice(codec_aad);
        aad
    }
}

/// One epoch's key, and the format of the group it came from.
struct EpochKey {
    format: Format,
    epoch: u8,
    gcm: Gcm,
    windows: Vec<(u8, ReplayWindow)>,
}

impl EpochKey {
    fn new(format: Format, epoch: u8, key: &[u8; KEY_LEN]) -> Self {
        Self {
            format,
            epoch,
            gcm: Gcm::new(key),
            windows: Vec::new(),
        }
    }

    fn replay_window(&mut self, kid: u8, window: u32) -> &mut ReplayWindow {
        let at = match self.windows.iter().position(|(k, _)| *k == kid) {
            Some(at) => at,
            None => {
                self.windows.push((kid, ReplayWindow::new(window)));
                self.windows.len() - 1
            }
        };
        &mut self.windows[at].1
    }
}

/// The counters seen within `window` of the highest one, as a ring of bits indexed by counter.
struct ReplayWindow {
    window: u32,
    max: u32,
    seen: Vec<u64>,
    empty: bool,
}

impl ReplayWindow {
    fn new(window: u32) -> Self {
        Self {
            window,
            max: 0,
            seen: vec![0; window.div_ceil(64) as usize],
            empty: true,
        }
    }

    fn bit(&self, counter: u32) -> (usize, u64) {
        let index = counter as usize % (self.seen.len() * 64);
        (index / 64, 1 << (index % 64))
    }

    fn mark(&mut self, counter: u32) {
        let (word, bit) = self.bit(counter);
        self.seen[word] |= bit;
    }

    fn check(&mut self, counter: u32) -> Result<(), FrameError> {
        if self.empty {
            self.empty = false;
        } else if counter > self.max {
            let shift = counter - self.max;
            if shift as usize >= self.seen.len() * 64 {
                self.seen.fill(0);
            } else {
                for exposed in self.max + 1..=counter {
                    let (word, bit) = self.bit(exposed);
                    self.seen[word] &= !bit;
                }
            }
        } else if self.max - counter >= self.window {
            return Err(FrameError::Replay);
        } else {
            let (word, bit) = self.bit(counter);
            if self.seen[word] & bit != 0 {
                return Err(FrameError::Replay);
            }
            self.seen[word] |= bit;
            return Ok(());
        }
        self.max = counter;
        self.mark(counter);
        Ok(())
    }
}

/// Encrypts every frame one sender process sends. All of the process's sources share it, so
/// one key and one counter never produce the same nonce twice.
pub struct Encryptor {
    kid: u8,
    counter: u32,
    key: Option<EpochKey>,
}

impl Encryptor {
    /// `counter` is where this process starts counting. The counter never goes back, not even
    /// across key changes, so a key that comes back can't reuse a nonce.
    pub fn new(kid: u8, counter: u32) -> Self {
        Self {
            kid,
            counter,
            key: None,
        }
    }

    pub fn set_key(&mut self, format: Format, epoch: u8, key: &[u8; KEY_LEN]) {
        self.key = Some(EpochKey::new(format, epoch, key));
    }

    pub fn clear_key(&mut self) {
        self.key = None;
    }

    /// The epoch frames are being sent under, if there's a key.
    pub fn epoch(&self) -> Option<u8> {
        self.key.as_ref().map(|key| key.epoch)
    }

    pub fn encrypt(
        &mut self,
        codec: Codec,
        source: &Source,
        frame: &[u8],
    ) -> Result<Vec<u8>, FrameError> {
        let key = self.key.as_ref().ok_or(FrameError::NoKey)?;
        let header = Header {
            format: key.format,
            codec,
            kid: self.kid,
            epoch: key.epoch,
            counter: self.counter,
            source,
        };
        self.counter = header
            .counter
            .checked_add(1)
            .ok_or(FrameError::CounterExhausted)?;

        codec::seal(codec, frame, |codec_aad, plain| {
            let tag = key.gcm.seal(
                &nonce(header.kid, header.counter),
                &header.aad(codec_aad),
                plain,
            );
            Trailer {
                tag,
                counter: header.counter,
                kid: header.kid,
                epoch: header.epoch,
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

/// Decrypts the frames of one sender. It holds a key per epoch; the trailer's epoch byte picks
/// one, so frames from just before a key change still decrypt.
pub struct Decryptor {
    keys: Vec<EpochKey>,
    window: u32,
}

impl Decryptor {
    /// `window` is how far behind the newest counter of an (epoch, kid) a frame may arrive.
    pub fn new(window: u32) -> Self {
        Self {
            keys: Vec::new(),
            window: window.max(1),
        }
    }

    pub fn set_key(&mut self, format: Format, epoch: u8, key: &[u8; KEY_LEN]) {
        self.remove_key(epoch);
        self.keys.push(EpochKey::new(format, epoch, key));
    }

    pub fn remove_key(&mut self, epoch: u8) {
        self.keys.retain(|key| key.epoch != epoch);
    }

    pub fn has_key(&self, epoch: u8) -> bool {
        self.keys.iter().any(|key| key.epoch == epoch)
    }

    pub fn decrypt(
        &mut self,
        codec: Codec,
        source: &Source,
        frame: &[u8],
    ) -> Result<Vec<u8>, FrameError> {
        self.decrypt_with_info(codec, source, frame)
            .map(|(plain, _)| plain)
    }

    /// The info is `None` for an H26X frame made only of parameter sets and delimiters, which
    /// goes through as-is (plan 3.2).
    pub fn decrypt_with_info(
        &mut self,
        codec: Codec,
        source: &Source,
        frame: &[u8],
    ) -> Result<(Vec<u8>, Option<FrameInfo>), FrameError> {
        let window = self.window;
        let mut info = None;
        let plain = codec::open(codec, frame, |codec_aad, cipher, trailer| {
            let key = self
                .keys
                .iter_mut()
                .find(|key| key.epoch == trailer.epoch)
                .ok_or(FrameError::NoKey)?;

            let header = Header {
                format: key.format,
                codec,
                kid: trailer.kid,
                epoch: trailer.epoch,
                counter: trailer.counter,
                source,
            };
            key.gcm
                .open(
                    &nonce(trailer.kid, trailer.counter),
                    &header.aad(codec_aad),
                    cipher,
                    &trailer.tag,
                )
                .then_some(())
                .ok_or(FrameError::Auth)?;
            // After `open`, so a forged frame can't move the window.
            key.replay_window(trailer.kid, window)
                .check(trailer.counter)?;

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
        let key = crate::key::sender_key(b"test root", sender);
        let mut encryptor = Encryptor::new(0, 0);
        encryptor.set_key(Format::V1, 0, &key);
        let mut decryptor = Decryptor::new(1024);
        decryptor.set_key(Format::V1, 0, &key);
        (encryptor, decryptor)
    }

    pub(crate) fn cam() -> Source {
        Source::webcam()
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
        let (mut encryptor, mut decryptor) = pair(1);
        let a = encryptor.encrypt(Codec::Opus, &cam(), b"same").unwrap();
        let b = encryptor.encrypt(Codec::Opus, &cam(), b"same").unwrap();
        assert_ne!(a, b);
        let (plain, info) = decryptor
            .decrypt_with_info(Codec::Opus, &cam(), &a)
            .unwrap();
        assert_eq!(
            (plain.as_slice(), info.map(|i| i.counter)),
            (&b"same"[..], Some(0))
        );
        let (plain, info) = decryptor
            .decrypt_with_info(Codec::Opus, &cam(), &b)
            .unwrap();
        assert_eq!(
            (plain.as_slice(), info.map(|i| i.counter)),
            (&b"same"[..], Some(1))
        );
    }

    #[test]
    fn counter_exhaustion_stops_encryption() {
        let mut encryptor = Encryptor::new(0, u32::MAX);
        encryptor.set_key(Format::V1, 0, &[1; 16]);
        assert_eq!(
            encryptor.encrypt(Codec::Opus, &cam(), b"x"),
            Err(FrameError::CounterExhausted)
        );
    }

    #[test]
    fn no_key() {
        let mut encryptor = Encryptor::new(0, 0);
        assert_eq!(
            encryptor.encrypt(Codec::Opus, &cam(), b"x"),
            Err(FrameError::NoKey)
        );

        let (mut encryptor, _) = pair(1);
        let sealed = encryptor.encrypt(Codec::Opus, &cam(), b"x").unwrap();
        assert_eq!(
            Decryptor::new(1024).decrypt(Codec::Opus, &cam(), &sealed),
            Err(FrameError::NoKey)
        );
    }

    #[test]
    fn wrong_sender_key_codec_or_epoch_fails() {
        let (mut encryptor, _) = pair(1);
        let (_, mut other) = pair(2);
        let (_, mut right) = pair(1);
        let sealed = encryptor.encrypt(Codec::Vp9, &cam(), &[5; 64]).unwrap();

        assert_eq!(
            other.decrypt(Codec::Vp9, &cam(), &sealed),
            Err(FrameError::Auth)
        );
        assert_eq!(
            right.decrypt(Codec::Opus, &cam(), &sealed),
            Err(FrameError::Auth)
        );

        let mut moved = Decryptor::new(1024);
        moved.set_key(Format::V1, 1, &crate::key::sender_key(b"test root", 1));
        assert_eq!(
            moved.decrypt(Codec::Vp9, &cam(), &sealed),
            Err(FrameError::NoKey)
        );
    }

    #[test]
    fn frames_are_bound_to_their_source() {
        let (mut encryptor, mut decryptor) = pair(1);
        let mic = encryptor
            .encrypt(Codec::Opus, &Source::mic(), &[7; 80])
            .unwrap();
        assert_eq!(
            decryptor.decrypt(Codec::Opus, &Source::stream_audio("1:2:k").unwrap(), &mic),
            Err(FrameError::Auth)
        );
        assert!(decryptor.decrypt(Codec::Opus, &Source::mic(), &mic).is_ok());

        let stream = Source::stream("1:2:k").unwrap();
        let screen = encryptor.encrypt(Codec::Vp9, &stream, &[7; 80]).unwrap();
        for wrong in [Source::webcam(), Source::stream("1:2:other").unwrap()] {
            assert_eq!(
                decryptor.decrypt(Codec::Vp9, &wrong, &screen),
                Err(FrameError::Auth)
            );
        }
        assert!(decryptor.decrypt(Codec::Vp9, &stream, &screen).is_ok());
    }

    #[test]
    fn format_leads_the_aad() {
        assert_eq!(Format::from_id(1), Some(Format::V1));
        assert_eq!(Format::from_id(0), None);
        assert_eq!(Format::from_id(2), None);

        let source = Source::stream("1:2:k").unwrap();
        let header = Header {
            format: Format::V1,
            codec: Codec::Vp8,
            kid: 1,
            epoch: 9,
            counter: 0x0102_0304,
            source: &source,
        };
        assert_eq!(
            header.aad(&[0xAA]),
            [&[1, 2, 1, 9, 1, 2, 3, 4][..], b"\x03\x051:2:k", &[0xAA]].concat()
        );
    }

    #[test]
    fn plaintext_frames_are_rejected() {
        let (_, mut decryptor) = pair(1);
        for codec in [Codec::Opus, Codec::Vp8, Codec::Vp9] {
            assert_eq!(
                decryptor.decrypt(codec, &cam(), &[0x10; 40]),
                Err(FrameError::NoTrailer)
            );
        }
    }

    fn sealed_frames(encryptor: &mut Encryptor, count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| {
                encryptor
                    .encrypt(Codec::Opus, &cam(), &i.to_be_bytes())
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn replay_rejects_duplicates() {
        let (mut encryptor, mut decryptor) = pair(1);
        let sealed = encryptor.encrypt(Codec::Opus, &cam(), b"once").unwrap();
        assert!(decryptor.decrypt(Codec::Opus, &cam(), &sealed).is_ok());
        assert_eq!(
            decryptor.decrypt(Codec::Opus, &cam(), &sealed),
            Err(FrameError::Replay)
        );
    }

    #[test]
    fn replay_rejects_too_old() {
        let (mut encryptor, mut decryptor) = pair(1);
        let frames = sealed_frames(&mut encryptor, 1100);
        assert!(
            decryptor
                .decrypt(Codec::Opus, &cam(), &frames[1099])
                .is_ok()
        );
        assert_eq!(
            decryptor.decrypt(Codec::Opus, &cam(), &frames[0]),
            Err(FrameError::Replay)
        );
        assert!(
            decryptor
                .decrypt(Codec::Opus, &cam(), &frames[1099 - 1023])
                .is_ok()
        );
    }

    #[test]
    fn replay_allows_reordering_inside_the_window() {
        let (mut encryptor, mut decryptor) = pair(1);
        let mut frames = sealed_frames(&mut encryptor, 1024);
        let mut rng = Rng::new(3);
        for i in (1..frames.len()).rev() {
            frames.swap(i, rng.below(i + 1));
        }
        for frame in &frames {
            assert!(decryptor.decrypt(Codec::Opus, &cam(), frame).is_ok());
        }
    }

    #[test]
    fn replay_window_is_per_epoch() {
        let keys = [0, 1].map(|epoch| crate::key::sender_key(&[epoch; 32], 1));
        let mut decryptor = Decryptor::new(1024);
        for (epoch, key) in keys.iter().enumerate() {
            decryptor.set_key(Format::V1, epoch as u8, key);
        }
        for (epoch, key) in keys.iter().enumerate() {
            let mut encryptor = Encryptor::new(0, 7);
            encryptor.set_key(Format::V1, epoch as u8, key);
            let sealed = encryptor.encrypt(Codec::Opus, &cam(), b"x").unwrap();
            let (_, info) = decryptor
                .decrypt_with_info(Codec::Opus, &cam(), &sealed)
                .unwrap();
            assert_eq!(info.map(|i| (i.epoch, i.counter)), Some((epoch as u8, 7)));
        }
    }

    #[test]
    fn forged_frames_do_not_move_the_window() {
        let (mut encryptor, mut decryptor) = pair(1);
        let frames = sealed_frames(&mut encryptor, 5000);
        let mut forged = frames[4999].clone();
        forged[0] ^= 1;
        assert_eq!(
            decryptor.decrypt(Codec::Opus, &cam(), &forged),
            Err(FrameError::Auth)
        );
        assert!(decryptor.decrypt(Codec::Opus, &cam(), &frames[0]).is_ok());
    }

    fn mutation_seeds(rng: &mut Rng) -> Vec<(Codec, Vec<Vec<u8>>)> {
        use codec::{
            av1::tests::obu,
            h26x::tests::{BitWriter, annex_b, h264_frame, zero_heavy},
        };

        let vp8_key = [0x10, 0x02, 0x00, 0x9D, 0x01, 0x2A, 0x80, 0x07, 0x38, 0x04];
        let av1_key = [
            obu(2, None, &[], Some(1)),
            obu(1, None, &rng.bytes(12), Some(1)),
            obu(5, Some(0x08), &rng.bytes(9), Some(1)),
            obu(3, Some(0x08), &rng.bytes(20), Some(1)),
            obu(4, Some(0x08), &rng.bytes(600), Some(2)),
        ]
        .concat();
        let av1_delta = [
            obu(2, None, &[], Some(1)),
            obu(6, Some(0x08), &rng.bytes(200), Some(2)),
        ]
        .concat();
        let h265_idr = BitWriter::new()
            .bit(1)
            .bit(0)
            .ue(0)
            .nal(&[0x26, 0x01], &zero_heavy(rng, 400));
        let h265_trail = BitWriter::new()
            .bit(0)
            .ue(2)
            .nal(&[0x02, 0x01], &zero_heavy(rng, 200));
        let h265 = annex_b(
            &[
                &[0x40, 0x01, 0x0C, 0x01, 0xFF, 0xFF],
                &[0x42, 0x01, 0x01, 0x01, 0x60, 0x90],
                &[0x44, 0x01, 0xC1, 0x72],
                &h265_idr,
                &h265_trail,
            ],
            false,
        );

        vec![
            (Codec::Opus, vec![rng.bytes(60), rng.bytes(160)]),
            (
                Codec::Vp8,
                vec![
                    [&vp8_key[..], &rng.bytes(400)].concat(),
                    [&[0x31][..], &rng.bytes(200)].concat(),
                ],
            ),
            (Codec::Vp9, vec![rng.bytes(300), rng.bytes(900)]),
            (Codec::Av1, vec![av1_key, av1_delta]),
            (Codec::H264, vec![h264_frame(rng).0, h264_frame(rng).0]),
            (Codec::H265, vec![h265]),
        ]
    }

    fn mutate(rng: &mut Rng, frame: &mut Vec<u8>) {
        if frame.is_empty() {
            frame.push(rng.next() as u8);
            return;
        }
        let len = frame.len();
        match rng.below(7) {
            0 => frame[rng.below(len)] ^= 1 << rng.below(8),
            1 => frame[rng.below(len)] = [0x00, 0x01, 0x03, 0x80, 0xFA][rng.below(5)],
            2 => {
                frame.remove(rng.below(len));
            }
            3 => frame.insert(rng.below(len + 1), rng.next() as u8),
            4 => {
                let start = rng.below(len);
                let end = start + 1 + rng.below(len - start);
                let slice = frame[start..end].to_vec();
                let at = rng.below(len + 1);
                frame.splice(at..at, slice);
            }
            5 => frame.truncate(rng.below(len)),
            _ => {
                let mut cuts = [
                    rng.below(len + 1),
                    rng.below(len + 1),
                    rng.below(len + 1),
                    rng.below(len + 1),
                ];
                cuts.sort_unstable();
                let [a, b, c, d] = cuts;
                *frame = [
                    &frame[..a],
                    &frame[c..d],
                    &frame[b..c],
                    &frame[a..b],
                    &frame[d..],
                ]
                .concat();
            }
        }
    }

    #[test]
    fn mutations_never_panic() {
        let (mut encryptor, mut decryptor) = pair(1);
        let mut rng = Rng::new(77);
        for (codec, frames) in mutation_seeds(&mut rng) {
            let sealed: Vec<Vec<u8>> = frames
                .iter()
                .map(|frame| encryptor.encrypt(codec, &cam(), frame).unwrap())
                .collect();
            for _ in 0..20_000 {
                let mut frame = sealed[rng.below(sealed.len())].clone();
                for _ in 0..1 + rng.below(3) {
                    mutate(&mut rng, &mut frame);
                }
                let _ = decryptor.decrypt(codec, &cam(), &frame);
                let _ = decryptor.decrypt_with_info(codec, &cam(), &frame);
            }
        }
    }

    #[test]
    fn garbage_never_panics() {
        let (_, mut decryptor) = pair(1);
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
                let _ = decryptor.decrypt(codec, &cam(), &frame);
            }
        }
    }
}
