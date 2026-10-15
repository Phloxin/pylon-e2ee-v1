//! Splits a frame into the bytes that stay readable (headers the SFU and Chromium parse) and the
//! bytes that get encrypted. Every split is recomputed by the receiver from the clear bytes
//! alone, because Chromium does not hand the receiver the sender's exact bytes.

mod av1;
mod h26x;

use crate::frame::{Codec, FrameError, trailer::Trailer};

/// mediasoup reads the inverse keyframe bit in byte 0; Chromium's depacketizer reads the
/// dimensions in a keyframe's first 10 bytes.
const VP8_KEY_CLEAR: usize = 10;
const VP8_DELTA_CLEAR: usize = 1;

/// `seal(aad, plain)` encrypts `plain` in place and returns the trailer bytes.
pub(super) fn seal<F>(codec: Codec, frame: &[u8], seal: F) -> Result<Vec<u8>, FrameError>
where
    F: FnOnce(&[u8], &mut [u8]) -> Vec<u8>,
{
    match codec {
        Codec::Opus | Codec::Vp9 | Codec::Vp8 => {
            seal_prefixed(clear_len(codec, frame), frame, seal)
        }
        Codec::Av1 => av1::seal(frame, seal),
        Codec::H264 => h26x::seal(h26x::Kind::H264, frame, seal),
        Codec::H265 => h26x::seal(h26x::Kind::H265, frame, seal),
    }
}

/// `open(aad, cipher, trailer)` verifies and decrypts `cipher` in place.
pub(super) fn open<F>(codec: Codec, frame: &[u8], open: F) -> Result<Vec<u8>, FrameError>
where
    F: FnOnce(&[u8], &mut [u8], &Trailer) -> Result<(), FrameError>,
{
    match codec {
        Codec::Opus | Codec::Vp9 | Codec::Vp8 => open_prefixed(codec, frame, open),
        Codec::Av1 => av1::open(frame, open),
        Codec::H264 => h26x::open(h26x::Kind::H264, frame, open),
        Codec::H265 => h26x::open(h26x::Kind::H265, frame, open),
    }
}

fn clear_len(codec: Codec, frame: &[u8]) -> usize {
    let len = match (codec, frame.first()) {
        (Codec::Vp8, Some(byte)) if byte & 0x01 == 0 => VP8_KEY_CLEAR,
        (Codec::Vp8, Some(_)) => VP8_DELTA_CLEAR,
        _ => 0,
    };
    len.min(frame.len())
}

fn seal_prefixed<F>(clear: usize, frame: &[u8], seal: F) -> Result<Vec<u8>, FrameError>
where
    F: FnOnce(&[u8], &mut [u8]) -> Vec<u8>,
{
    let (clear, body) = frame.split_at(clear);
    let mut body = body.to_vec();
    let trailer = seal(clear, &mut body);

    let mut out = Vec::with_capacity(frame.len() + trailer.len());
    out.extend_from_slice(clear);
    out.extend_from_slice(&body);
    out.extend_from_slice(&trailer);
    Ok(out)
}

fn open_prefixed<F>(codec: Codec, frame: &[u8], open: F) -> Result<Vec<u8>, FrameError>
where
    F: FnOnce(&[u8], &mut [u8], &Trailer) -> Result<(), FrameError>,
{
    let (body_len, trailer) = Trailer::split(frame).ok_or(FrameError::NoTrailer)?;
    let body = &frame[..body_len];
    let (clear, cipher) = body.split_at(clear_len(codec, body));

    let mut plain = cipher.to_vec();
    open(clear, &mut plain, &trailer)?;

    let mut out = Vec::with_capacity(body_len);
    out.extend_from_slice(clear);
    out.extend_from_slice(&plain);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use crate::frame::{Codec, FrameError, tests::pair};

    #[test]
    fn opus_and_vp9_encrypt_everything() {
        for codec in [Codec::Opus, Codec::Vp9] {
            let (mut encryptor, decryptor) = pair(1);
            let frame = vec![0xAB; 120];
            let sealed = encryptor.encrypt(codec, &frame).unwrap();
            assert_ne!(sealed[0], 0xAB);
            assert_eq!(decryptor.decrypt(codec, &sealed).unwrap(), frame);
        }
    }

    #[test]
    fn vp8_keeps_the_keyframe_header_readable() {
        let (mut encryptor, decryptor) = pair(1);

        let key = [
            &[0x10u8, 0x02, 0x00, 0x9D, 0x01, 0x2A, 0x80, 0x07, 0x38, 0x04][..],
            &[0x55; 50],
        ]
        .concat();
        let sealed = encryptor.encrypt(Codec::Vp8, &key).unwrap();
        assert_eq!(sealed[..10], key[..10]);
        assert_ne!(sealed[10..60], key[10..]);
        assert_eq!(decryptor.decrypt(Codec::Vp8, &sealed).unwrap(), key);

        let delta = [&[0x31u8][..], &[0x55; 50]].concat();
        let sealed = encryptor.encrypt(Codec::Vp8, &delta).unwrap();
        assert_eq!(sealed[0], 0x31);
        assert_ne!(sealed[1], 0x55);
        assert_eq!(decryptor.decrypt(Codec::Vp8, &sealed).unwrap(), delta);
    }

    #[test]
    fn vp8_clear_bytes_are_authenticated() {
        let (mut encryptor, decryptor) = pair(1);
        let mut sealed = encryptor.encrypt(Codec::Vp8, &[0x10; 40]).unwrap();
        sealed[3] ^= 0x40;
        assert_eq!(
            decryptor.decrypt(Codec::Vp8, &sealed),
            Err(FrameError::Auth)
        );
    }

    #[test]
    fn tiny_frames() {
        let (mut encryptor, decryptor) = pair(1);
        for codec in [Codec::Opus, Codec::Vp8, Codec::Vp9] {
            for frame in [&[][..], &[0x00][..], &[0x01, 0x02][..]] {
                let sealed = encryptor.encrypt(codec, frame).unwrap();
                assert_eq!(decryptor.decrypt(codec, &sealed).unwrap(), frame);
            }
        }
    }
}
