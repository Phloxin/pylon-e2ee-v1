const MAX_LEN: usize = 8;

pub(crate) fn write(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Returns the value and how many bytes it took.
pub(crate) fn read(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, &byte) in buf.iter().take(MAX_LEN).enumerate() {
        value |= u64::from(byte & 0x7F) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for value in [
            0,
            1,
            127,
            128,
            300,
            16_383,
            16_384,
            u32::MAX as u64,
            (1 << 56) - 1,
        ] {
            let mut buf = Vec::new();
            write(value, &mut buf);
            assert_eq!(read(&buf), Some((value, buf.len())));
        }
    }

    #[test]
    fn padded_encoding_reads_the_same() {
        assert_eq!(read(&[0x85, 0x80, 0x80, 0x00]), Some((5, 4)));
    }

    #[test]
    fn rejects_unterminated() {
        assert_eq!(read(&[0x80, 0x80]), None);
        assert_eq!(read(&[0x80; 9]), None);
    }
}
