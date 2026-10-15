//! The source binding in the AAD (plan section 3.4). A sender's key covers all of its sources, so
//! without it the node could play a sender's mic frames into its stream-audio sink, or show its
//! webcam as its screenshare. The sender passes the source it published under; the receiver takes
//! it from `ChannelSource.kind`.

use crate::frame::leb128;

const MIC: u8 = 1;
const WEBCAM: u8 = 2;
const STREAM: u8 = 3;
const STREAM_AUDIO: u8 = 4;

/// Stream keys are at most 64 ASCII bytes on the server; this only bounds what we'll encode.
const MAX_STREAM_KEY: usize = 255;

/// A source, already encoded the way it goes into the AAD: `tag`, then for streams
/// `uleb128(len) || stream_key`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Source(Box<[u8]>);

impl Source {
    pub fn mic() -> Self {
        Self(Box::new([MIC]))
    }

    pub fn webcam() -> Self {
        Self(Box::new([WEBCAM]))
    }

    pub fn stream(stream_key: &str) -> Option<Self> {
        Self::keyed(STREAM, stream_key)
    }

    pub fn stream_audio(stream_key: &str) -> Option<Self> {
        Self::keyed(STREAM_AUDIO, stream_key)
    }

    /// `tag` is 1 mic, 2 webcam, 3 stream, 4 stream audio. Streams need a non-empty key, and the
    /// others must not have one.
    pub fn new(tag: u8, stream_key: Option<&str>) -> Option<Self> {
        match (tag, stream_key) {
            (MIC, None) => Some(Self::mic()),
            (WEBCAM, None) => Some(Self::webcam()),
            (STREAM | STREAM_AUDIO, Some(key)) => Self::keyed(tag, key),
            _ => None,
        }
    }

    fn keyed(tag: u8, stream_key: &str) -> Option<Self> {
        if stream_key.is_empty() || stream_key.len() > MAX_STREAM_KEY {
            return None;
        }

        let mut bytes = vec![tag];
        leb128::write(stream_key.len() as u64, &mut bytes);
        bytes.extend_from_slice(stream_key.as_bytes());
        Some(Self(bytes.into()))
    }

    /// Reads back what `as_bytes` wrote, e.g. from a capture file.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (&tag, rest) = bytes.split_first()?;
        let stream_key = match tag {
            MIC | WEBCAM if rest.is_empty() => None,
            STREAM | STREAM_AUDIO => {
                let (len, used) = leb128::read(rest)?;
                let key = rest.get(used..)?;
                (key.len() as u64 == len).then_some(std::str::from_utf8(key).ok()?)
            }
            _ => return None,
        };
        Self::new(tag, stream_key)
    }

    pub fn tag(&self) -> u8 {
        self.0[0]
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings() {
        assert_eq!(Source::mic().as_bytes(), [1]);
        assert_eq!(Source::webcam().as_bytes(), [2]);
        assert_eq!(Source::stream("a:b").unwrap().as_bytes(), b"\x03\x03a:b");
        assert_eq!(
            Source::stream_audio("a:b").unwrap().as_bytes(),
            b"\x04\x03a:b"
        );
    }

    #[test]
    fn rejects_mismatched_keys() {
        assert_eq!(Source::new(1, Some("x")), None);
        assert_eq!(Source::new(2, Some("x")), None);
        assert_eq!(Source::new(3, None), None);
        assert_eq!(Source::new(4, Some("")), None);
        assert_eq!(Source::new(5, None), None);
        assert_eq!(Source::stream(&"k".repeat(256)), None);
    }

    #[test]
    fn bytes_round_trip() {
        for source in [
            Source::mic(),
            Source::webcam(),
            Source::stream("1:2:abc").unwrap(),
            Source::stream_audio(&"k".repeat(200)).unwrap(),
        ] {
            assert_eq!(Source::from_bytes(source.as_bytes()), Some(source));
        }
        assert_eq!(Source::from_bytes(&[]), None);
        assert_eq!(Source::from_bytes(&[1, 0]), None);
        assert_eq!(Source::from_bytes(b"\x03\x05abc"), None);
    }
}
