use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::Error;
use crate::varint;

/// A raw capsule with type and undecoded payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCapsule {
    pub capsule_type: u64,
    pub payload: Bytes,
}

/// Encode a capsule into the buffer (type + length + payload).
pub fn encode_capsule(capsule: &RawCapsule, buf: &mut BytesMut) {
    varint::encode(capsule.capsule_type, buf);
    varint::encode(capsule.payload.len() as u64, buf);
    buf.put_slice(&capsule.payload);
}

/// Attempt to decode one capsule from the buffer.
///
/// Returns:
/// - `Ok(Some(capsule))` if a complete capsule was decoded (buffer is advanced)
/// - `Ok(None)` if the buffer is empty (no more capsules)
/// - `Err(...)` if the data is malformed or the buffer has a partial capsule
pub fn decode_capsule(buf: &mut Bytes) -> Result<Option<RawCapsule>, Error> {
    if !buf.has_remaining() {
        return Ok(None);
    }

    let mut peek = buf.clone();

    let capsule_type = match varint::decode(&mut peek) {
        Ok(v) => v,
        Err(_) => return Err(Error::UnexpectedEof),
    };

    let length = match varint::decode(&mut peek) {
        Ok(v) => v,
        Err(_) => return Err(Error::UnexpectedEof),
    };

    let length = length as usize;
    if peek.remaining() < length {
        return Err(Error::UnexpectedEof);
    }

    let payload = peek.split_to(length);

    // Commit the read
    *buf = peek;

    Ok(Some(RawCapsule {
        capsule_type,
        payload,
    }))
}
