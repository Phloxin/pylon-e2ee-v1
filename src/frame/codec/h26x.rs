//! H264 and H265 (plan section 3.2).
//!
//! - Parameter sets and delimiters pass through clear and unauthenticated. The receiver skips
//!   them, so Chromium inserting or rewriting SPS/PPS can't break verification.
//! - Every other NAL keeps its header clear, and slices also keep the slice header up to the PPS
//!   id clear (what Chromium's depacketizer parses). The rest is encrypted.
//! - Ciphertext is escaped like an EBSP, so it never contains a start code and Chromium's
//!   packetizer finds exactly the original NAL boundaries.
//! - A frame with nothing to protect (only parameter sets and delimiters) goes through as-is.
//! - The sender moves parameter sets ahead of the slices (see `sender_order`).

use crate::frame::{FrameError, trailer::Trailer};

const START_CODE: [u8; 4] = [0, 0, 0, 1];

/// Closes every protected NAL that does not carry the trailer. Without it, ciphertext ending in
/// 0x00 would be read as the leading zero of the next 4-byte start code and lost.
const TERMINATOR: u8 = 0x80;

#[derive(Clone, Copy)]
pub(super) enum Kind {
    H264,
    H265,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Pass,
    /// Protected, with this many leading bytes left clear.
    Protect(usize),
}

pub(super) fn seal<F>(kind: Kind, frame: &[u8], seal: F) -> Result<Vec<u8>, FrameError>
where
    F: FnOnce(&[u8], &mut [u8]) -> Vec<u8>,
{
    let units = units(frame)?;
    let classes = classify_all(kind, &units)?;
    let Some(last) = last_protected(&classes) else {
        return Ok(frame.to_vec());
    };
    let order = sender_order(kind, &units);

    let mut aad = Vec::new();
    let mut plain = Vec::with_capacity(frame.len());
    for (nal, class) in order.iter().map(|&i| (units[i], classes[i])) {
        if let Class::Protect(prefix) = class {
            let (clear, body) = nal.split_at(prefix);
            push_aad(&mut aad, clear, body.len());
            plain.extend_from_slice(body);
        }
    }

    let trailer = seal(&aad, &mut plain);

    let mut out = Vec::with_capacity(frame.len() + trailer.len() + 4 * units.len() + 16);
    let mut cipher = plain.as_slice();
    for (index, nal, class) in order.iter().map(|&i| (i, units[i], classes[i])) {
        out.extend_from_slice(&START_CODE);

        let Class::Protect(prefix) = class else {
            out.extend_from_slice(nal);
            continue;
        };

        let (clear, body_len) = (&nal[..prefix], nal.len() - prefix);
        let (body, rest) = cipher.split_at(body_len);
        cipher = rest;

        out.extend_from_slice(clear);
        let zeros = trailing_zeros(clear);
        if index == last {
            let zeros = escape(body, zeros, &mut out);
            escape(&trailer, zeros, &mut out);
        } else if !body.is_empty() {
            escape(body, zeros, &mut out);
            out.push(TERMINATOR);
        }
    }

    Ok(out)
}

pub(super) fn open<F>(kind: Kind, frame: &[u8], open: F) -> Result<Vec<u8>, FrameError>
where
    F: FnOnce(&[u8], &mut [u8], &Trailer) -> Result<(), FrameError>,
{
    let units = units(frame)?;
    let classes = classify_all(kind, &units)?;
    let Some(last) = last_protected(&classes) else {
        return Ok(frame.to_vec());
    };

    let Class::Protect(last_prefix) = classes[last] else {
        unreachable!("last_protected returned a pass-through NAL");
    };
    let (last_clear, last_region) = units[last].split_at(last_prefix);
    let mut last_body = unescape(last_region, trailing_zeros(last_clear));
    let (body_len, trailer) = Trailer::split(&last_body).ok_or(FrameError::NoTrailer)?;
    last_body.truncate(body_len);

    let mut aad = Vec::new();
    let mut cipher = Vec::with_capacity(frame.len());
    let mut lens = Vec::with_capacity(units.len());
    for (index, (nal, class)) in units.iter().zip(&classes).enumerate() {
        let Class::Protect(prefix) = *class else {
            continue;
        };

        let (clear, region) = nal.split_at(prefix);
        let body = if index == last {
            std::mem::take(&mut last_body)
        } else {
            match region.split_last() {
                None => Vec::new(),
                Some((&TERMINATOR, rest)) => unescape(rest, trailing_zeros(clear)),
                Some(_) => return Err(FrameError::Malformed),
            }
        };

        push_aad(&mut aad, clear, body.len());
        lens.push(body.len());
        cipher.extend_from_slice(&body);
    }

    open(&aad, &mut cipher, &trailer)?;

    let mut out = Vec::with_capacity(frame.len());
    let mut plain = cipher.as_slice();
    let mut lens = lens.into_iter();
    for (nal, class) in units.iter().zip(&classes) {
        out.extend_from_slice(&START_CODE);
        match *class {
            Class::Pass => out.extend_from_slice(nal),
            Class::Protect(prefix) => {
                let len = lens.next().expect("one length per protected NAL");
                let (body, rest) = plain.split_at(len);
                plain = rest;
                out.extend_from_slice(&nal[..prefix]);
                out.extend_from_slice(body);
            }
        }
    }

    Ok(out)
}

fn push_aad(aad: &mut Vec<u8>, clear: &[u8], body_len: usize) {
    aad.extend_from_slice(&(clear.len() as u32).to_be_bytes());
    aad.extend_from_slice(clear);
    aad.extend_from_slice(&(body_len as u32).to_be_bytes());
}

/// `None` when the frame has nothing to protect.
fn last_protected(classes: &[Class]) -> Option<usize> {
    classes
        .iter()
        .rposition(|class| matches!(class, Class::Protect(_)))
}

fn nal_type(kind: Kind, nal: &[u8]) -> Option<u8> {
    match kind {
        Kind::H264 => nal.first().map(|header| header & 0x1F),
        Kind::H265 => nal.first().map(|header| header >> 1 & 0x3F),
    }
}

fn is_delimiter(kind: Kind, nal: &[u8]) -> bool {
    match kind {
        Kind::H264 => nal_type(kind, nal) == Some(9),
        Kind::H265 => nal_type(kind, nal) == Some(35),
    }
}

fn is_parameter_set(kind: Kind, nal: &[u8]) -> bool {
    match kind {
        Kind::H264 => matches!(nal_type(kind, nal), Some(7 | 8 | 13 | 15)),
        Kind::H265 => matches!(nal_type(kind, nal), Some(32..=34)),
    }
}

/// The order the sender emits NALs in: a leading delimiter, then the parameter sets, then the
/// rest as encoded. Some encoders put SPS/PPS after the IDR, but mediasoup starts a new viewer at
/// the first packet holding an SPS and drops the IDR packets before it, so that viewer has to
/// wait for another keyframe. Parameter sets are not authenticated, so moving them is free.
fn sender_order(kind: Kind, units: &[&[u8]]) -> Vec<usize> {
    let lead = units
        .iter()
        .take_while(|nal| is_delimiter(kind, nal))
        .count();
    let (sets, rest): (Vec<usize>, Vec<usize>) =
        (lead..units.len()).partition(|&i| is_parameter_set(kind, units[i]));
    (0..lead).chain(sets).chain(rest).collect()
}

/// NAL payloads of an Annex B stream, without start codes. A 4-byte start code's leading zero
/// belongs to the start code, as in Chromium's `FindNaluIndices`.
fn units(frame: &[u8]) -> Result<Vec<&[u8]>, FrameError> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= frame.len() {
        if frame[i] == 0 && frame[i + 1] == 0 && frame[i + 2] == 1 {
            let begin = if i > 0 && frame[i - 1] == 0 { i - 1 } else { i };
            starts.push((begin, i + 3));
            i += 3;
        } else {
            i += 1;
        }
    }

    if starts.is_empty() {
        return Err(FrameError::Malformed);
    }

    Ok(starts
        .iter()
        .enumerate()
        .map(|(n, &(_, payload))| {
            let end = starts.get(n + 1).map_or(frame.len(), |&(begin, _)| begin);
            &frame[payload..end.max(payload)]
        })
        .collect())
}

fn classify_all(kind: Kind, units: &[&[u8]]) -> Result<Vec<Class>, FrameError> {
    units.iter().map(|nal| classify(kind, nal)).collect()
}

fn classify(kind: Kind, nal: &[u8]) -> Result<Class, FrameError> {
    match kind {
        Kind::H264 => {
            let header = *nal.first().ok_or(FrameError::Malformed)?;
            match header & 0x1F {
                // SPS, PPS, AUD, end of sequence/stream, filler, SPS extension, subset SPS.
                7..=13 | 15 => Ok(Class::Pass),

                // Coded slices (non-IDR, partition A, IDR): first_mb_in_slice, slice_type,
                // pic_parameter_set_id.
                1 | 2 | 5 => slice_prefix(nal, 1, |bits| {
                    bits.ue()?;
                    bits.ue()?;
                    bits.ue()?;
                    Some(())
                }),

                _ => Ok(Class::Protect(1)),
            }
        }

        Kind::H265 => {
            if nal.len() < 2 {
                return Err(FrameError::Malformed);
            }

            match nal[0] >> 1 & 0x3F {
                // VPS, SPS, PPS, AUD, end of sequence/bitstream, filler.
                32..=38 => Ok(Class::Pass),

                // VCL: first_slice_segment_in_pic_flag, no_output_of_prior_pics_flag (IRAP
                // only), slice_pic_parameter_set_id.
                kind @ 0..=31 => slice_prefix(nal, 2, |bits| {
                    bits.bit()?;
                    if (16..=23).contains(&kind) {
                        bits.bit()?;
                    }
                    bits.ue()?;
                    Some(())
                }),

                _ => Ok(Class::Protect(2)),
            }
        }
    }
}

fn slice_prefix(
    nal: &[u8],
    header: usize,
    fields: impl FnOnce(&mut Bits) -> Option<()>,
) -> Result<Class, FrameError> {
    let mut bits = Bits::new(&nal[header..]);
    fields(&mut bits).ok_or(FrameError::Malformed)?;
    Ok(Class::Protect(header + bits.consumed()))
}

/// Reads RBSP bits out of EBSP bytes, skipping emulation prevention bytes.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    zeros: usize,
    byte: u8,
    left: u8,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            zeros: 0,
            byte: 0,
            left: 0,
        }
    }

    fn bit(&mut self) -> Option<u32> {
        if self.left == 0 {
            loop {
                let byte = *self.data.get(self.pos)?;
                self.pos += 1;
                if self.zeros >= 2 && byte == 3 {
                    self.zeros = 0;
                    continue;
                }
                self.zeros = if byte == 0 { self.zeros + 1 } else { 0 };
                self.byte = byte;
                self.left = 8;
                break;
            }
        }

        self.left -= 1;
        Some(u32::from(self.byte >> self.left & 1))
    }

    fn ue(&mut self) -> Option<u32> {
        let mut leading = 0;
        while self.bit()? == 0 {
            leading += 1;
            if leading > 31 {
                return None;
            }
        }

        let mut value = 0u32;
        for _ in 0..leading {
            value = value << 1 | self.bit()?;
        }
        Some(((1u64 << leading) - 1 + u64::from(value)) as u32)
    }

    /// EBSP bytes up to and including the one holding the last bit read.
    fn consumed(&self) -> usize {
        self.pos
    }
}

fn trailing_zeros(clear: &[u8]) -> usize {
    clear
        .iter()
        .rev()
        .take(2)
        .take_while(|&&byte| byte == 0)
        .count()
}

/// Inserts 0x03 wherever two zeros are followed by a byte <= 3, continuing from `zeros` zeros
/// already written. Returns the zero run it ends on.
fn escape(src: &[u8], mut zeros: usize, out: &mut Vec<u8>) -> usize {
    for &byte in src {
        if zeros >= 2 && byte <= 3 {
            out.push(3);
            zeros = 0;
        }
        out.push(byte);
        zeros = if byte == 0 { zeros + 1 } else { 0 };
    }
    zeros
}

fn unescape(src: &[u8], mut zeros: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len());
    for &byte in src {
        if zeros >= 2 && byte == 3 {
            zeros = 0;
            continue;
        }
        out.push(byte);
        zeros = if byte == 0 { zeros + 1 } else { 0 };
    }
    out
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::frame::{
            Codec,
            tests::{Rng, pair},
        },
    };

    struct BitWriter {
        bytes: Vec<u8>,
        used: u8,
    }

    impl BitWriter {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                used: 8,
            }
        }

        fn bit(&mut self, bit: u32) -> &mut Self {
            if self.used == 8 {
                self.bytes.push(0);
                self.used = 0;
            }
            if bit != 0 {
                *self.bytes.last_mut().unwrap() |= 0x80 >> self.used;
            }
            self.used += 1;
            self
        }

        fn ue(&mut self, value: u32) -> &mut Self {
            let code = u64::from(value) + 1;
            let len = 64 - code.leading_zeros();
            for _ in 1..len {
                self.bit(0);
            }
            for i in (0..len).rev() {
                self.bit((code >> i & 1) as u32);
            }
            self
        }

        /// The RBSP so far plus `payload`, escaped into an EBSP behind `header`.
        fn nal(&mut self, header: &[u8], payload: &[u8]) -> Vec<u8> {
            let mut rbsp = std::mem::take(&mut self.bytes);
            rbsp.extend_from_slice(payload);
            rbsp.push(0x80);
            let mut nal = header.to_vec();
            escape(&rbsp, 0, &mut nal);
            nal
        }
    }

    fn annex_b(units: &[&[u8]], long: bool) -> Vec<u8> {
        let mut frame = Vec::new();
        for (i, nal) in units.iter().enumerate() {
            frame.extend_from_slice(if long || i == 0 {
                &[0, 0, 0, 1][..]
            } else {
                &[0, 0, 1]
            });
            frame.extend_from_slice(nal);
        }
        frame
    }

    /// Payload heavy on zeros so it is full of emulation prevention bytes.
    fn zero_heavy(rng: &mut Rng, len: usize) -> Vec<u8> {
        (0..len)
            .map(|_| match rng.below(4) {
                0 | 1 => 0,
                2 => rng.below(4) as u8,
                _ => rng.next() as u8,
            })
            .collect()
    }

    fn h264_frame(rng: &mut Rng) -> (Vec<u8>, Vec<Vec<u8>>) {
        let sps = vec![0x67, 0x42, 0xC0, 0x1F, 0x8C, 0x8D, 0x40, 0x50];
        let pps = vec![0x68, 0xCE, 0x3C, 0x80];
        let aud = vec![0x09, 0xF0];
        let sei = BitWriter::new().nal(&[0x06, 0x05, 0x10], &zero_heavy(rng, 30));
        let slice0 = BitWriter::new()
            .ue(0)
            .ue(7)
            .ue(0)
            .nal(&[0x65], &zero_heavy(rng, 900));
        let slice1 = BitWriter::new()
            .ue(396)
            .ue(7)
            .ue(0)
            .nal(&[0x65], &zero_heavy(rng, 700));
        let units = vec![aud, sps, pps, sei, slice0, slice1];
        let refs: Vec<&[u8]> = units.iter().map(Vec::as_slice).collect();
        (annex_b(&refs, false), units)
    }

    fn types(frame: &[u8]) -> Vec<u8> {
        units(frame).unwrap().iter().map(|nal| nal[0]).collect()
    }

    #[test]
    fn escape_round_trips_and_never_emits_a_start_code() {
        let mut rng = Rng::new(3);
        for _ in 0..500 {
            let len = rng.below(200);
            let src = zero_heavy(&mut rng, len);
            let zeros = rng.below(3);
            let mut out = vec![0; zeros];
            escape(&src, zeros, &mut out);

            assert!(!out.windows(3).any(|w| w[0] == 0 && w[1] == 0 && w[2] <= 2));
            assert_eq!(unescape(&out[zeros..], zeros), src);
        }
    }

    #[test]
    fn slice_prefix_covers_the_pps_id_through_emulation_bytes() {
        // first_mb_in_slice = 2^24 - 1 starts with 24 zero bits, so the EBSP gains a 0x03.
        let nal = BitWriter::new()
            .ue((1 << 24) - 1)
            .ue(5)
            .ue(3)
            .nal(&[0x65], &[0xFF; 8]);
        assert!(nal.windows(3).any(|w| w == [0, 0, 3]));

        let Class::Protect(prefix) = classify(Kind::H264, &nal).unwrap() else {
            panic!("slice should be protected");
        };
        let mut bits = Bits::new(&nal[1..prefix]);
        assert_eq!(bits.ue(), Some((1 << 24) - 1));
        assert_eq!(bits.ue(), Some(5));
        assert_eq!(bits.ue(), Some(3));
    }

    #[test]
    fn h264_round_trip_survives_chromium_receive_changes() {
        let mut rng = Rng::new(11);
        let (mut encryptor, decryptor) = pair(5);

        for _ in 0..50 {
            let (frame, original) = h264_frame(&mut rng);
            let sealed = encryptor.encrypt(Codec::H264, &frame).unwrap();

            assert_eq!(
                types(&sealed),
                types(&frame),
                "escaping must keep NAL boundaries"
            );
            let sealed_units = units(&sealed).unwrap();
            assert_eq!(sealed_units[1], original[1], "SPS stays as-is");
            assert_eq!(
                sealed_units[4][..3],
                original[4][..3],
                "slice header stays readable"
            );
            assert_ne!(sealed_units[4][20..40], original[4][20..40]);
            assert_ne!(
                sealed_units[3][3..20],
                original[3][3..20],
                "SEI payload is encrypted"
            );

            // What Chromium may hand the receiver: AUD dropped, VUI-rewritten SPS, an extra
            // SPS/PPS pair in front of the IDR, every start code four bytes.
            let mut rewritten_sps = original[1].clone();
            *rewritten_sps.last_mut().unwrap() ^= 0x04;
            let received = annex_b(
                &[
                    &rewritten_sps,
                    sealed_units[2],
                    sealed_units[3],
                    &original[1],
                    &original[2],
                    sealed_units[4],
                    sealed_units[5],
                ],
                true,
            );

            let opened = decryptor.decrypt(Codec::H264, &received).unwrap();
            let expected = annex_b(
                &[
                    &rewritten_sps,
                    &original[2],
                    &original[3],
                    &original[1],
                    &original[2],
                    &original[4],
                    &original[5],
                ],
                true,
            );
            assert_eq!(opened, expected);
        }
    }

    #[test]
    fn h264_protected_structure_is_authenticated() {
        let mut rng = Rng::new(12);
        let (mut encryptor, decryptor) = pair(5);
        let (frame, _) = h264_frame(&mut rng);
        let sealed = encryptor.encrypt(Codec::H264, &frame).unwrap();
        let sealed_units = units(&sealed).unwrap();

        let without_first_slice = annex_b(
            &[
                sealed_units[1],
                sealed_units[2],
                sealed_units[3],
                sealed_units[5],
            ],
            true,
        );
        assert!(
            decryptor
                .decrypt(Codec::H264, &without_first_slice)
                .is_err()
        );

        let mut header_changed = sealed.clone();
        let at = sealed
            .windows(5)
            .position(|w| w == [0, 0, 0, 1, 0x65])
            .unwrap()
            + 5;
        header_changed[at] ^= 0x01;
        assert_eq!(
            decryptor.decrypt(Codec::H264, &header_changed),
            Err(FrameError::Auth)
        );
    }

    #[test]
    fn h264_plaintext_is_rejected() {
        let mut rng = Rng::new(13);
        let (_, decryptor) = pair(5);
        let (frame, _) = h264_frame(&mut rng);
        assert_eq!(
            decryptor.decrypt(Codec::H264, &frame),
            Err(FrameError::NoTrailer)
        );
    }

    #[test]
    fn parameter_set_only_frames_pass_through() {
        let (mut encryptor, decryptor) = pair(5);
        let units: [&[u8]; 3] = [
            &[0x09, 0xF0],
            &[0x67, 0x42, 0xC0, 0x1F],
            &[0x68, 0xCE, 0x3C, 0x80],
        ];
        let frame = annex_b(&units, false);
        assert_eq!(encryptor.encrypt(Codec::H264, &frame).unwrap(), frame);
        assert_eq!(decryptor.decrypt(Codec::H264, &frame).unwrap(), frame);
    }

    #[test]
    fn parameter_sets_move_ahead_of_the_idr() {
        let mut rng = Rng::new(15);
        let (mut encryptor, decryptor) = pair(5);
        let aud = [0x09, 0xF0];
        let sps = [0x67, 0x42, 0xC0, 0x28, 0x88];
        let pps = [0x68, 0xCE, 0x3C, 0x80];
        let idr = BitWriter::new()
            .ue(0)
            .ue(7)
            .ue(0)
            .nal(&[0x65], &zero_heavy(&mut rng, 500));

        // The order the phase 0 capture showed this encoder writing keyframes in.
        let frame = annex_b(&[&idr, &sps, &pps], true);
        let sealed = encryptor.encrypt(Codec::H264, &frame).unwrap();
        assert_eq!(types(&sealed), [0x67, 0x68, 0x65]);
        assert_eq!(
            decryptor.decrypt(Codec::H264, &sealed).unwrap(),
            annex_b(&[&sps, &pps, &idr], true)
        );

        let frame = annex_b(&[&aud, &idr, &sps, &pps], true);
        let sealed = encryptor.encrypt(Codec::H264, &frame).unwrap();
        assert_eq!(types(&sealed), [0x09, 0x67, 0x68, 0x65]);

        let already = annex_b(&[&sps, &pps, &idr], true);
        let sealed = encryptor.encrypt(Codec::H264, &already).unwrap();
        assert_eq!(decryptor.decrypt(Codec::H264, &sealed).unwrap(), already);
    }

    #[test]
    fn h264_random_payloads_keep_boundaries() {
        let mut rng = Rng::new(14);
        let (mut encryptor, decryptor) = pair(5);
        for _ in 0..300 {
            let slices = 1 + rng.below(4);
            let mut nals: Vec<Vec<u8>> = vec![vec![0x67, 0x42, 0xC0, 0x1F]];
            for _ in 0..slices {
                let len = rng.below(64);
                nals.push(
                    BitWriter::new()
                        .ue(0)
                        .ue(5)
                        .ue(0)
                        .nal(&[0x41], &zero_heavy(&mut rng, len)),
                );
            }
            let refs: Vec<&[u8]> = nals.iter().map(Vec::as_slice).collect();
            let frame = annex_b(&refs, rng.below(2) == 0);

            let sealed = encryptor.encrypt(Codec::H264, &frame).unwrap();
            assert_eq!(types(&sealed), types(&frame));
            assert_eq!(
                decryptor.decrypt(Codec::H264, &sealed).unwrap(),
                annex_b(&refs, true)
            );
        }
    }

    #[test]
    fn h265_round_trip() {
        let mut rng = Rng::new(21);
        let (mut encryptor, decryptor) = pair(9);

        let vps = [0x40, 0x01, 0x0C, 0x01, 0xFF, 0xFF];
        let sps = vec![0x42, 0x01, 0x01, 0x01, 0x60, 0x90];
        let pps = vec![0x44, 0x01, 0xC1, 0x72];
        // IDR_W_RADL (19): first_slice_segment_in_pic_flag, no_output_of_prior_pics_flag, pps id.
        let idr = BitWriter::new()
            .bit(1)
            .bit(0)
            .ue(0)
            .nal(&[0x26, 0x01], &zero_heavy(&mut rng, 800));
        // TRAIL_R (1): no no_output_of_prior_pics_flag.
        let trail = BitWriter::new()
            .bit(0)
            .ue(2)
            .nal(&[0x02, 0x01], &zero_heavy(&mut rng, 300));
        let sei = BitWriter::new().nal(&[0x4E, 0x01, 0x05], &zero_heavy(&mut rng, 20));
        let nals = [&vps[..], &sps, &pps, &sei, &idr, &trail];
        // Parameter sets last, as some encoders emit them; the sender moves them up front.
        let frame = annex_b(&[&sei[..], &idr, &trail, &vps, &sps, &pps], false);

        let Class::Protect(prefix) = classify(Kind::H265, &idr).unwrap() else {
            panic!("IDR should be protected");
        };
        assert_eq!(prefix, 3);

        let sealed = encryptor.encrypt(Codec::H265, &frame).unwrap();
        assert_eq!(types(&sealed), types(&annex_b(&nals, true)));
        assert_eq!(units(&sealed).unwrap()[..3], nals[..3]);
        assert_eq!(
            decryptor.decrypt(Codec::H265, &sealed).unwrap(),
            annex_b(&nals, true)
        );
    }
}
