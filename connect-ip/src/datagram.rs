use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::Error;
use crate::varint;

/// Context ID for IP packets (RFC 9484 §6).
pub const CONTEXT_ID_IP_PACKET: u64 = 0;

/// Encode an IP packet as an HTTP Datagram payload with Context ID 0.
///
/// Format: Context ID (varint) || IP Packet
pub fn encode_ip_datagram(ip_packet: &[u8], buf: &mut BytesMut) {
    varint::encode(CONTEXT_ID_IP_PACKET, buf);
    buf.put_slice(ip_packet);
}

/// Decode an HTTP Datagram payload into (Context ID, payload).
///
/// For Context ID 0, payload is a full IP packet.
/// For other Context IDs, payload is extension data.
pub fn decode_ip_datagram(buf: &mut Bytes) -> Result<(u64, Bytes), Error> {
    if !buf.has_remaining() {
        return Err(Error::UnexpectedEof);
    }

    let context_id = varint::decode(buf)?;
    let payload = buf.split_to(buf.remaining());
    Ok((context_id, payload))
}

/// Calculate the overhead added by datagram framing (Context ID varint).
pub fn framing_overhead(context_id: u64) -> usize {
    varint::encoded_len(context_id)
}
