use bytes::{Buf, BufMut};

use crate::error::Error;

/// Maximum value representable as a QUIC variable-length integer.
pub const MAX_VALUE: u64 = 4_611_686_018_427_387_903;

/// Returns the encoded byte length for a given value.
///
/// Panics if `value` exceeds `MAX_VALUE`.
pub fn encoded_len(value: u64) -> usize {
    if value <= 63 {
        1
    } else if value <= 16_383 {
        2
    } else if value <= 1_073_741_823 {
        4
    } else if value <= MAX_VALUE {
        8
    } else {
        panic!("varint value {value} exceeds maximum {MAX_VALUE}");
    }
}

/// Encode a variable-length integer into the buffer.
///
/// Panics if `value` exceeds `MAX_VALUE`.
pub fn encode(value: u64, buf: &mut impl BufMut) {
    match encoded_len(value) {
        1 => buf.put_u8(value as u8),
        2 => buf.put_u16(0x4000 | value as u16),
        4 => buf.put_u32(0x8000_0000 | value as u32),
        8 => buf.put_u64(0xC000_0000_0000_0000 | value),
        _ => unreachable!(),
    }
}

/// Decode a variable-length integer from the buffer.
///
/// Advances the buffer past the consumed bytes.
/// Returns `Error::InvalidVarint` if the buffer is too short.
pub fn decode(buf: &mut impl Buf) -> Result<u64, Error> {
    if !buf.has_remaining() {
        return Err(Error::InvalidVarint);
    }

    let first = buf.chunk()[0];
    let prefix = first >> 6;
    let len = 1 << prefix; // 1, 2, 4, or 8

    if buf.remaining() < len {
        return Err(Error::InvalidVarint);
    }

    let value = match len {
        1 => buf.get_u8() as u64,
        2 => (buf.get_u16() & 0x3FFF) as u64,
        4 => (buf.get_u32() & 0x3FFF_FFFF) as u64,
        8 => buf.get_u64() & 0x3FFF_FFFF_FFFF_FFFF,
        _ => unreachable!(),
    };

    Ok(value)
}
