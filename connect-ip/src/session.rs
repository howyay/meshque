use bytes::{Buf, Bytes, BytesMut};
use h3::quic::{self, RecvStream, SendStream, StreamId};
use h3_datagram::datagram_handler::{DatagramReader, DatagramSender};
use h3_datagram::quic_traits::DatagramConnectionExt;

use crate::capsule::address::{
    decode_address_assign, decode_address_request, encode_address_assign, encode_address_request,
    AddressAssign, AddressRequest,
};
use crate::capsule::capsule_type;
use crate::capsule::codec::{decode_capsule, encode_capsule, RawCapsule};
use crate::capsule::route::{
    decode_route_advertisement, encode_route_advertisement, RouteAdvertisement,
};
use crate::datagram;
use crate::error::Error;

/// Received capsule from the peer, decoded into a known type or left raw.
#[derive(Debug)]
pub enum Capsule {
    AddressAssign(AddressAssign),
    AddressRequest(AddressRequest),
    RouteAdvertisement(RouteAdvertisement),
    Unknown { capsule_type: u64, payload: Bytes },
}

/// Holds either a server or client request stream for capsule I/O.
///
/// Both types have identical `send_data`/`recv_data`/`finish` methods.
pub(crate) enum StreamHolder<S> {
    Server(h3::server::RequestStream<S, Bytes>),
    Client(h3::client::RequestStream<S, Bytes>),
}

impl<S: SendStream<Bytes> + RecvStream> StreamHolder<S> {
    pub(crate) async fn send_data(&mut self, data: Bytes) -> Result<(), Error> {
        match self {
            StreamHolder::Server(s) => s.send_data(data).await.map_err(|e| e.into()),
            StreamHolder::Client(s) => s.send_data(data).await.map_err(|e| e.into()),
        }
    }

    pub(crate) async fn recv_data(&mut self) -> Result<Option<Bytes>, Error> {
        match self {
            StreamHolder::Server(s) => match s.recv_data().await? {
                Some(buf) => Ok(Some(buf_to_bytes(buf))),
                None => Ok(None),
            },
            StreamHolder::Client(s) => match s.recv_data().await? {
                Some(buf) => Ok(Some(buf_to_bytes(buf))),
                None => Ok(None),
            },
        }
    }

    pub(crate) async fn finish(&mut self) -> Result<(), Error> {
        match self {
            StreamHolder::Server(s) => s.finish().await.map_err(|e| e.into()),
            StreamHolder::Client(s) => s.finish().await.map_err(|e| e.into()),
        }
    }
}

fn buf_to_bytes(mut buf: impl Buf) -> Bytes {
    let mut out = BytesMut::with_capacity(buf.remaining());
    while buf.has_remaining() {
        let chunk = buf.chunk();
        out.extend_from_slice(chunk);
        let len = chunk.len();
        buf.advance(len);
    }
    out.freeze()
}

/// An established CONNECT-IP session.
///
/// Provides methods to send/receive IP packets (via HTTP datagrams)
/// and exchange capsules (via the HTTP request stream).
pub struct ConnectIpSession<C>
where
    C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
{
    stream: StreamHolder<C::BidiStream>,
    stream_id: StreamId,
    dg_sender: DatagramSender<C::SendDatagramHandler, Bytes>,
    dg_reader: DatagramReader<C::RecvDatagramHandler>,
    max_datagram_size: Option<usize>,
    /// Buffer for partially-read capsule data from the stream.
    capsule_buf: BytesMut,
}

impl<C> ConnectIpSession<C>
where
    C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
    <C::RecvDatagramHandler as h3_datagram::quic_traits::RecvDatagram>::Buffer: Into<Bytes>,
{
    /// Create a new session (internal constructor).
    pub(crate) fn new(
        stream: StreamHolder<C::BidiStream>,
        stream_id: StreamId,
        dg_sender: DatagramSender<C::SendDatagramHandler, Bytes>,
        dg_reader: DatagramReader<C::RecvDatagramHandler>,
        max_datagram_size: Option<usize>,
    ) -> Self {
        Self {
            stream,
            stream_id,
            dg_sender,
            dg_reader,
            max_datagram_size,
            capsule_buf: BytesMut::new(),
        }
    }

    // ── Datagram I/O (IP packets) ───────────────────────────────────────

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
    /// other Context IDs are silently discarded per RFC 9484 §6.
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
        }
    }

    // ── Capsule I/O (control plane) ─────────────────────────────────────

    /// Send a raw capsule on the request stream.
    pub async fn send_raw_capsule(&mut self, capsule: &RawCapsule) -> Result<(), Error> {
        let mut buf = BytesMut::new();
        encode_capsule(capsule, &mut buf);
        self.stream.send_data(buf.freeze()).await
    }

    /// Receive the next capsule from the request stream.
    ///
    /// Unknown capsule types are silently skipped per RFC 9297 §3.2.
    /// Returns `None` when the stream is finished (peer sent FIN).
    pub async fn recv_capsule(&mut self) -> Result<Option<Capsule>, Error> {
        loop {
            // Try to decode from buffered data first
            if !self.capsule_buf.is_empty() {
                let mut data = self.capsule_buf.clone().freeze();
                match decode_capsule(&mut data) {
                    Ok(Some(raw)) => {
                        let consumed = self.capsule_buf.len() - data.remaining();
                        self.capsule_buf.advance(consumed);
                        match parse_capsule(raw) {
                            Some(capsule) => return Ok(Some(capsule)),
                            None => continue, // unknown type, skip silently
                        }
                    }
                    Ok(None) => {} // need more data
                    Err(Error::UnexpectedEof) => {} // need more data
                    Err(e) => return Err(e),
                }
            }

            // Read more data from the stream
            match self.stream.recv_data().await? {
                Some(data) => {
                    self.capsule_buf.extend_from_slice(&data);
                }
                None => {
                    if self.capsule_buf.is_empty() {
                        return Ok(None);
                    } else {
                        return Err(Error::UnexpectedEof);
                    }
                }
            }
        }
    }

    /// Send an ADDRESS_ASSIGN capsule.
    pub async fn send_address_assign(&mut self, assign: &AddressAssign) -> Result<(), Error> {
        let mut payload = BytesMut::new();
        encode_address_assign(assign, &mut payload);
        self.send_raw_capsule(&RawCapsule {
            capsule_type: capsule_type::ADDRESS_ASSIGN,
            payload: payload.freeze(),
        })
        .await
    }

    /// Send an ADDRESS_REQUEST capsule.
    pub async fn send_address_request(&mut self, request: &AddressRequest) -> Result<(), Error> {
        let mut payload = BytesMut::new();
        encode_address_request(request, &mut payload);
        self.send_raw_capsule(&RawCapsule {
            capsule_type: capsule_type::ADDRESS_REQUEST,
            payload: payload.freeze(),
        })
        .await
    }

    /// Send a ROUTE_ADVERTISEMENT capsule.
    pub async fn send_route_advertisement(
        &mut self,
        routes: &RouteAdvertisement,
    ) -> Result<(), Error> {
        let mut payload = BytesMut::new();
        encode_route_advertisement(routes, &mut payload);
        self.send_raw_capsule(&RawCapsule {
            capsule_type: capsule_type::ROUTE_ADVERTISEMENT,
            payload: payload.freeze(),
        })
        .await
    }

    // ── MTU ─────────────────────────────────────────────────────────────

    /// Get the effective tunnel MTU (maximum IP packet size).
    ///
    /// Computed as: QUIC max datagram size - HTTP/3 datagram framing overhead
    /// (quarter stream ID varint) - Context ID overhead (1 byte for ID 0).
    ///
    /// Returns `None` if the QUIC connection doesn't support datagrams or
    /// the MTU was not provided at session creation time.
    pub fn tunnel_mtu(&self) -> Option<usize> {
        self.max_datagram_size.map(|max_dg| {
            // HTTP/3 Datagram framing: quarter stream ID varint
            let quarter_id = self.stream_id.into_inner() / 4;
            let h3_overhead = crate::varint::encoded_len(quarter_id);
            // CONNECT-IP framing: Context ID 0 = 1 byte
            let cip_overhead = datagram::framing_overhead(datagram::CONTEXT_ID_IP_PACKET);
            max_dg.saturating_sub(h3_overhead + cip_overhead)
        })
    }

    // ── Lifecycle ───────────────────────────────────────────────────────

    /// Close the session gracefully.
    ///
    /// Sends a FIN on the request stream and drops datagram handlers.
    pub async fn close(mut self) -> Result<(), Error> {
        self.stream.finish().await
    }

    /// The stream ID of this session's CONNECT-IP request stream.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }
}

/// Parse a raw capsule into a known type, or return None for unknown types
/// (which should be silently skipped per RFC 9297 §3.2).
fn parse_capsule(raw: RawCapsule) -> Option<Capsule> {
    let payload = raw.payload;
    match raw.capsule_type {
        capsule_type::ADDRESS_ASSIGN => {
            let mut p = payload.clone();
            match decode_address_assign(&mut p) {
                Ok(assign) => Some(Capsule::AddressAssign(assign)),
                Err(_) => Some(Capsule::Unknown {
                    capsule_type: capsule_type::ADDRESS_ASSIGN,
                    payload,
                }),
            }
        }
        capsule_type::ADDRESS_REQUEST => {
            let mut p = payload.clone();
            match decode_address_request(&mut p) {
                Ok(request) => Some(Capsule::AddressRequest(request)),
                Err(_) => Some(Capsule::Unknown {
                    capsule_type: capsule_type::ADDRESS_REQUEST,
                    payload,
                }),
            }
        }
        capsule_type::ROUTE_ADVERTISEMENT => {
            let mut p = payload.clone();
            match decode_route_advertisement(&mut p) {
                Ok(routes) => Some(Capsule::RouteAdvertisement(routes)),
                Err(_) => Some(Capsule::Unknown {
                    capsule_type: capsule_type::ROUTE_ADVERTISEMENT,
                    payload,
                }),
            }
        }
        _ => None,
    }
}
