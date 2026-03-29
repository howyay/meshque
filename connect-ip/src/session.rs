use bytes::{Bytes, BytesMut};
use h3::quic::{self, StreamId};
use h3_datagram::datagram_handler::{DatagramReader, DatagramSender};
use h3_datagram::quic_traits::DatagramConnectionExt;

use crate::datagram;
use crate::error::Error;

/// An established CONNECT-IP session.
///
/// Provides methods to send/receive IP packets (via HTTP datagrams)
/// and exchange capsules (via the HTTP request stream).
pub struct ConnectIpSession<C>
where
    C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
{
    stream_id: StreamId,
    dg_sender: DatagramSender<C::SendDatagramHandler, Bytes>,
    dg_reader: DatagramReader<C::RecvDatagramHandler>,
}

impl<C> ConnectIpSession<C>
where
    C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
    <C::RecvDatagramHandler as h3_datagram::quic_traits::RecvDatagram>::Buffer: Into<Bytes>,
{
    /// Create a new session from datagram handlers.
    ///
    /// This is called internally by `ConnectIpProxy` and `ConnectIpClient`.
    pub(crate) fn new(
        stream_id: StreamId,
        dg_sender: DatagramSender<C::SendDatagramHandler, Bytes>,
        dg_reader: DatagramReader<C::RecvDatagramHandler>,
    ) -> Self {
        Self {
            stream_id,
            dg_sender,
            dg_reader,
        }
    }

    /// Send an IP packet through the tunnel as an HTTP datagram.
    ///
    /// The packet is prefixed with Context ID 0 (IP packet) as per RFC 9484 §6.
    pub fn send_ip_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        let mut buf = BytesMut::with_capacity(1 + packet.len());
        datagram::encode_ip_datagram(packet, &mut buf);
        self.dg_sender
            .send_datagram(buf.freeze())
            .map_err(|e| Error::DatagramSend(e.to_string()))
    }

    /// Receive an IP packet from the tunnel.
    ///
    /// Blocks until a datagram with Context ID 0 arrives. Datagrams with
    /// other Context IDs are silently discarded.
    pub async fn recv_ip_packet(&mut self) -> Result<Bytes, Error> {
        loop {
            let dg = self
                .dg_reader
                .read_datagram()
                .await
                .map_err(|e| Error::ProtocolViolation(format!("datagram read error: {e}")))?;

            let payload: Bytes = dg.into_payload().into();
            let mut payload = payload;
            let (context_id, ip_packet) = datagram::decode_ip_datagram(&mut payload)?;

            if context_id == datagram::CONTEXT_ID_IP_PACKET {
                return Ok(ip_packet);
            }
            // Non-zero context IDs are silently discarded (extension mechanism)
        }
    }

    /// The stream ID of this session's CONNECT-IP request stream.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }
}
