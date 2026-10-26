//! AV1 (plan section 3.3). OBU headers stay clear and every payload is encrypted, the sequence
//! header included. Chromium's packetizer strips `obu_size` and its depacketizer writes it back,
//! possibly at another width, so sizes are rebuilt on both ends and only the header (minus
//! `obu_has_size_field`) is authenticated.
//!
//! Temporal delimiters, tile lists and padding are never sent over RTP. The sender drops them,
//! and the receiver strips any it gets, so nothing unauthenticated reaches the decoder.

use crate::frame::{FrameError, leb128, trailer::Trailer};

#[cfg(test)]
const SEQUENCE_HEADER: u8 = 1;
const TEMPORAL_DELIMITER: u8 = 2;
const TILE_LIST: u8 = 8;
const PADDING: u8 = 15;

const FORBIDDEN: u8 = 0x80;
const HAS_EXTENSION: u8 = 0x04;
const HAS_SIZE: u8 = 0x02;

struct Obu<'a> {
    header: u8,
    extension: Option<u8>,
    payload: &'a [u8],
}

impl Obu<'_> {
    fn kind(&self) -> u8 {
        self.header >> 3 & 0x0F
    }

    /// Never sent over RTP, and never authenticated.
    fn dropped(&self) -> bool {
        matches!(self.kind(), TEMPORAL_DELIMITER | TILE_LIST | PADDING)
    }

    fn write(&self, payload: &[&[u8]], out: &mut Vec<u8>) {
        out.push(self.header | HAS_SIZE);
        out.extend(self.extension);
        leb128::write(payload.iter().map(|part| part.len() as u64).sum(), out);
        for part in payload {
            out.extend_from_slice(part);
        }
    }

    fn push_aad(&self, body_len: usize, aad: &mut Vec<u8>) {
        aad.push(self.header & !HAS_SIZE);
        aad.extend(self.extension);
        aad.extend_from_slice(&(body_len as u32).to_be_bytes());
    }
}

fn obus(mut frame: &[u8]) -> Result<Vec<Obu<'_>>, FrameError> {
    let mut obus = Vec::new();
    while let Some(&header) = frame.first() {
        if header & FORBIDDEN != 0 {
            return Err(FrameError::Malformed);
        }

        let mut at = 1;
        let extension = if header & HAS_EXTENSION != 0 {
            at += 1;
            Some(*frame.get(1).ok_or(FrameError::Malformed)?)
        } else {
            None
        };

        let size = if header & HAS_SIZE != 0 {
            let (size, used) = leb128::read(&frame[at..]).ok_or(FrameError::Malformed)?;
            at += used;
            usize::try_from(size).map_err(|_| FrameError::Malformed)?
        } else {
            frame.len() - at
        };

        let end = at.checked_add(size).ok_or(FrameError::Malformed)?;
        let payload = frame.get(at..end).ok_or(FrameError::Malformed)?;
        obus.push(Obu {
            header,
            extension,
            payload,
        });
        frame = &frame[end..];
    }
    Ok(obus)
}

/// The OBUs that are sent and authenticated: everything but the dropped kinds.
fn protected(frame: &[u8]) -> Result<Vec<Obu<'_>>, FrameError> {
    Ok(obus(frame)?
        .into_iter()
        .filter(|obu| !obu.dropped())
        .collect())
}

pub(super) fn seal<F>(frame: &[u8], seal: F) -> Result<Vec<u8>, FrameError>
where
    F: FnOnce(&[u8], &mut [u8]) -> Vec<u8>,
{
    let obus = protected(frame)?;
    let Some((last, rest)) = obus.split_last() else {
        // Only delimiters or padding: nothing to send. The packetizer drops these anyway.
        return Ok(frame.to_vec());
    };

    let mut aad = Vec::new();
    let mut plain = Vec::with_capacity(frame.len());
    for obu in &obus {
        obu.push_aad(obu.payload.len(), &mut aad);
        plain.extend_from_slice(obu.payload);
    }

    let trailer = seal(&aad, &mut plain);

    let mut out = Vec::with_capacity(frame.len() + trailer.len() + 8);
    let mut cipher = plain.as_slice();
    for obu in rest {
        let (body, tail) = cipher.split_at(obu.payload.len());
        cipher = tail;
        obu.write(&[body], &mut out);
    }
    last.write(&[cipher, &trailer], &mut out);

    Ok(out)
}

pub(super) fn open<F>(frame: &[u8], open: F) -> Result<Vec<u8>, FrameError>
where
    F: FnOnce(&[u8], &mut [u8], &Trailer) -> Result<(), FrameError>,
{
    let obus = protected(frame)?;
    let (last, _) = obus.split_last().ok_or(FrameError::NoTrailer)?;
    let (last_len, trailer) = Trailer::split(last.payload).ok_or(FrameError::NoTrailer)?;

    let lens: Vec<usize> = obus
        .iter()
        .enumerate()
        .map(|(index, obu)| {
            if index + 1 == obus.len() {
                last_len
            } else {
                obu.payload.len()
            }
        })
        .collect();

    let mut aad = Vec::new();
    let mut cipher = Vec::with_capacity(frame.len());
    for (obu, &len) in obus.iter().zip(&lens) {
        obu.push_aad(len, &mut aad);
        cipher.extend_from_slice(&obu.payload[..len]);
    }

    open(&aad, &mut cipher, &trailer)?;

    let mut out = Vec::with_capacity(frame.len());
    let mut plain = cipher.as_slice();
    for (obu, &len) in obus.iter().zip(&lens) {
        let (part, rest) = plain.split_at(len);
        plain = rest;
        obu.write(&[part], &mut out);
    }

    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use {
        super::*,
        crate::frame::{
            Codec,
            tests::{Rng, cam, pair},
        },
    };

    pub(crate) fn obu(
        kind: u8,
        extension: Option<u8>,
        payload: &[u8],
        size_width: Option<usize>,
    ) -> Vec<u8> {
        let mut header = kind << 3;
        if extension.is_some() {
            header |= HAS_EXTENSION;
        }
        if size_width.is_some() {
            header |= HAS_SIZE;
        }

        let mut out = vec![header];
        out.extend(extension);
        if let Some(width) = size_width {
            let mut size = payload.len() as u64;
            for i in 0..width {
                let more = if i + 1 < width { 0x80 } else { 0 };
                out.push((size & 0x7F) as u8 | more);
                size >>= 7;
            }
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn round_trip_through_chromium_size_rewrites() {
        let mut rng = Rng::new(31);
        let (mut encryptor, mut decryptor) = pair(3);

        let sequence = rng.bytes(12);
        let frame_header = rng.bytes(20);
        let tiles = rng.bytes(5000);
        let metadata = rng.bytes(9);

        let frame = [
            obu(TEMPORAL_DELIMITER, None, &[], Some(1)),
            obu(SEQUENCE_HEADER, None, &sequence, Some(1)),
            obu(5, Some(0x08), &metadata, Some(1)),
            obu(3, Some(0x08), &frame_header, Some(1)),
            obu(4, Some(0x08), &tiles, Some(2)),
        ]
        .concat();

        let sealed = encryptor.encrypt(Codec::Av1, &cam(), &frame).unwrap();
        let sealed_obus = obus(&sealed).unwrap();
        assert_eq!(sealed_obus.len(), 4, "the temporal delimiter is dropped");
        assert_eq!(sealed_obus[0].header, SEQUENCE_HEADER << 3 | HAS_SIZE);
        assert_ne!(
            sealed_obus[0].payload, sequence,
            "the sequence header is encrypted"
        );
        assert_eq!(sealed_obus[2].header, 3 << 3 | HAS_EXTENSION | HAS_SIZE);
        assert_ne!(sealed_obus[2].payload, frame_header);

        // The depacketizer re-adds sizes at its own width; the last OBU may come without one.
        let received = [
            obu(SEQUENCE_HEADER, None, sealed_obus[0].payload, Some(4)),
            obu(5, Some(0x08), sealed_obus[1].payload, Some(3)),
            obu(3, Some(0x08), sealed_obus[2].payload, Some(2)),
            obu(4, Some(0x08), sealed_obus[3].payload, None),
        ]
        .concat();

        let opened = decryptor.decrypt(Codec::Av1, &cam(), &received).unwrap();
        let opened = obus(&opened).unwrap();
        let payloads: Vec<&[u8]> = opened.iter().map(|obu| obu.payload).collect();
        assert_eq!(payloads, [&sequence[..], &metadata, &frame_header, &tiles]);
    }

    #[test]
    fn headers_are_authenticated() {
        let (mut encryptor, mut decryptor) = pair(3);
        let frame = [
            obu(3, Some(0x08), &[1; 20], Some(1)),
            obu(4, Some(0x08), &[2; 60], Some(1)),
        ]
        .concat();
        let sealed = encryptor.encrypt(Codec::Av1, &cam(), &frame).unwrap();

        let mut changed = sealed.clone();
        changed[1] ^= 0x20;
        assert_eq!(
            decryptor.decrypt(Codec::Av1, &cam(), &changed),
            Err(FrameError::Auth)
        );
    }

    #[test]
    fn sequence_header_only_frames_are_protected() {
        let (mut encryptor, mut decryptor) = pair(3);
        let frame = obu(SEQUENCE_HEADER, None, &[1; 10], Some(1));
        let sealed = encryptor.encrypt(Codec::Av1, &cam(), &frame).unwrap();
        assert_ne!(sealed, frame);
        assert_eq!(
            decryptor.decrypt(Codec::Av1, &cam(), &sealed).unwrap(),
            frame
        );

        // A clear one is rejected rather than handed to the decoder.
        assert_eq!(
            decryptor.decrypt(Codec::Av1, &cam(), &frame),
            Err(FrameError::NoTrailer)
        );
    }

    #[test]
    fn unauthenticated_obus_never_reach_the_decoder() {
        let (mut encryptor, mut decryptor) = pair(3);
        let tiles = obu(6, None, &[4; 40], Some(1));
        let sealed = encryptor.encrypt(Codec::Av1, &cam(), &tiles).unwrap();

        // Padding and a temporal delimiter slipped in around the protected OBU are stripped.
        let padding = obu(PADDING, None, &[0xEE; 6], Some(1));
        let delimiter = obu(TEMPORAL_DELIMITER, None, &[], Some(1));
        let received = [&delimiter[..], &sealed, &padding].concat();
        assert_eq!(
            decryptor.decrypt(Codec::Av1, &cam(), &received).unwrap(),
            tiles
        );

        // A frame with nothing but those has nothing to authenticate.
        assert_eq!(
            decryptor.decrypt(Codec::Av1, &cam(), &[delimiter, padding].concat()),
            Err(FrameError::NoTrailer)
        );
    }

    #[test]
    fn plaintext_tiles_are_rejected() {
        let (_, mut decryptor) = pair(3);
        let frame = [
            obu(3, None, &[1; 20], Some(1)),
            obu(4, None, &[2; 60], Some(1)),
        ]
        .concat();
        assert_eq!(
            decryptor.decrypt(Codec::Av1, &cam(), &frame),
            Err(FrameError::NoTrailer)
        );
    }
}
