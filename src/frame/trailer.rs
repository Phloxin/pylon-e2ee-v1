use crate::frame::{gcm::TAG_LEN, leb128};

pub(crate) const MAGIC: [u8; 2] = [0xFA, 0xFA];

/// tag, counter (1-5 bytes), kid, epoch and the size byte itself.
const MIN_SIZE: usize = TAG_LEN + 1 + 1 + 1 + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Trailer {
    pub(crate) tag: [u8; TAG_LEN],
    pub(crate) counter: u32,
    pub(crate) kid: u8,
    pub(crate) epoch: u8,
}

impl Trailer {
    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.extend_from_slice(&self.tag);
        leb128::write(u64::from(self.counter), out);
        out.push(self.kid);
        out.push(self.epoch);

        let size = out.len() - start + 1;
        out.push(size as u8);
        out.extend_from_slice(&MAGIC);
    }

    pub(crate) fn to_vec(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MIN_SIZE + 6);
        self.write(&mut out);
        out
    }

    /// Splits a trailer off the end of `buf`. Returns where the trailer starts.
    pub(crate) fn split(buf: &[u8]) -> Option<(usize, Self)> {
        let magic_at = buf.len().checked_sub(MAGIC.len())?;
        if buf[magic_at..] != MAGIC {
            return None;
        }

        let size = usize::from(*buf.get(magic_at.checked_sub(1)?)?);
        if size < MIN_SIZE {
            return None;
        }

        let start = magic_at.checked_sub(size)?;
        let fields = &buf[start..magic_at - 1];

        let tag = fields[..TAG_LEN].try_into().ok()?;
        let (counter, used) = leb128::read(&fields[TAG_LEN..])?;
        let [kid, epoch] = fields[TAG_LEN + used..] else {
            return None;
        };

        Some((
            start,
            Self {
                tag,
                counter: counter.try_into().ok()?,
                kid,
                epoch,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_behind_a_body() {
        for counter in [0, 1, 127, 128, 1 << 20, u32::MAX] {
            let trailer = Trailer {
                tag: [9; TAG_LEN],
                counter,
                kid: 1,
                epoch: 200,
            };
            let mut buf = b"body".to_vec();
            trailer.write(&mut buf);

            assert_eq!(Trailer::split(&buf), Some((4, trailer)));
        }
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(Trailer::split(&[]), None);
        assert_eq!(Trailer::split(&[0xFA, 0xFA]), None);
        assert_eq!(Trailer::split(&[1, 2, 3, 200, 0xFA, 0xFA]), None);
        assert_eq!(Trailer::split(&[0; 32]), None);
    }
}
