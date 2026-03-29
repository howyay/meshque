use bytes::{Buf, Bytes, BytesMut};
use h3::quic::{self, BidiStream, RecvStream, SendStream, StreamId};
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

/// Send half of a split stream.
pub(crate) enum SendStreamHolder<S> {
    Server(h3::server::RequestStream<S, Bytes>),
    Client(h3::client::RequestStream<S, Bytes>),
}

impl<S: SendStream<Bytes>> SendStreamHolder<S> {
    pub(crate) async fn send_data(&mut self, data: Bytes) -> Result<(), Error> {
        match self {
            SendStreamHolder::Server(s) => s.send_data(data).await.map_err(|e| e.into()),
            SendStreamHolder::Client(s) => s.send_data(data).await.map_err(|e| e.into()),
        }
    }

    pub(crate) async fn finish(&mut self) -> Result<(), Error> {
        match self {
            SendStreamHolder::Server(s) => s.finish().await.map_err(|e| e.into()),
            SendStreamHolder::Client(s) => s.finish().await.map_err(|e| e.into()),
        }
    }
}

/// Receive half of a split stream.
pub(crate) enum RecvStreamHolder<S> {
    Server(h3::server::RequestStream<S, Bytes>),
    Client(h3::client::RequestStream<S, Bytes>),
}

impl<S: RecvStream> RecvStreamHolder<S> {
    pub(crate) async fn recv_data(&mut self) -> Result<Option<Bytes>, Error> {
        match self {
            RecvStreamHolder::Server(s) => match s.recv_data().await? {
                Some(buf) => Ok(Some(buf_to_bytes(buf))),
                None => Ok(None),
            },
            RecvStreamHolder::Client(s) => match s.recv_data().await? {
                Some(buf) => Ok(Some(buf_to_bytes(buf))),
                None => Ok(None),
            },
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

// ═══════════════════════════════════════════════════════════════════════
// ConnectIpSession — unified API (simple usage)
// ═══════════════════════════════════════════════════════════════════════

/// An established CONNECT-IP session.
///
/// Provides methods to send/receive IP packets (via HTTP datagrams)
/// and exchange capsules (via the HTTP request stream).
///
/// For concurrent datagram + capsule I/O (e.g. `tokio::select!`),
/// call [`into_parts()`](ConnectIpSession::into_parts) to split the session into
/// independently-ownable handles.
pub struct ConnectIpSession<C>
where
    C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
{
    stream: StreamHolder<C::BidiStream>,
    stream_id: StreamId,
    dg_sender: DatagramSender<C::SendDatagramHandler, Bytes>,
    dg_reader: DatagramReader<C::RecvDatagramHandler>,
    max_datagram_size: Option<usize>,
    capsule_buf: BytesMut,
}

impl<C> ConnectIpSession<C>
where
    C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
    <C::RecvDatagramHandler as h3_datagram::quic_traits::RecvDatagram>::Buffer: Into<Bytes>,
{
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

    // ── Datagram I/O ────────────────────────────────────────────────────

    /// Send an IP packet through the tunnel as an HTTP datagram.
    pub fn send_ip_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        let mut buf = BytesMut::with_capacity(1 + packet.len());
        datagram::encode_ip_datagram(packet, &mut buf);
        self.dg_sender
            .send_datagram(buf.freeze())
            .map_err(|e| Error::DatagramSend(e.to_string()))
    }

    /// Receive an IP packet from the tunnel.
    pub async fn recv_ip_packet(&mut self) -> Result<Bytes, Error> {
        recv_ip_packet_impl(&mut self.dg_reader).await
    }

    // ── Capsule I/O ─────────────────────────────────────────────────────

    /// Send a raw capsule on the request stream.
    pub async fn send_raw_capsule(&mut self, capsule: &RawCapsule) -> Result<(), Error> {
        send_raw_capsule_impl(&mut self.stream, capsule).await
    }

    /// Receive the next capsule from the request stream.
    /// Unknown capsule types are silently skipped per RFC 9297 §3.2.
    pub async fn recv_capsule(&mut self) -> Result<Option<Capsule>, Error> {
        recv_capsule_stream(&mut self.stream, &mut self.capsule_buf).await
    }

    /// Send an ADDRESS_ASSIGN capsule.
    pub async fn send_address_assign(&mut self, assign: &AddressAssign) -> Result<(), Error> {
        send_address_assign_impl(&mut self.stream, assign).await
    }

    /// Send an ADDRESS_REQUEST capsule.
    pub async fn send_address_request(&mut self, request: &AddressRequest) -> Result<(), Error> {
        send_address_request_impl(&mut self.stream, request).await
    }

    /// Send a ROUTE_ADVERTISEMENT capsule.
    pub async fn send_route_advertisement(
        &mut self,
        routes: &RouteAdvertisement,
    ) -> Result<(), Error> {
        send_route_advertisement_impl(&mut self.stream, routes).await
    }

    // ── MTU ─────────────────────────────────────────────────────────────

    /// Get the effective tunnel MTU (maximum IP packet size).
    pub fn tunnel_mtu(&self) -> Option<usize> {
        compute_tunnel_mtu(self.max_datagram_size, self.stream_id)
    }

    // ── Lifecycle ───────────────────────────────────────────────────────

    /// Close the session gracefully.
    pub async fn close(mut self) -> Result<(), Error> {
        self.stream.finish().await
    }

    /// The stream ID of this session's CONNECT-IP request stream.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Split the session into independently-ownable parts for concurrent I/O.
    ///
    /// This enables patterns like:
    /// ```ignore
    /// let parts = session.into_parts();
    /// tokio::select! {
    ///     pkt = parts.datagram_recv.recv_ip_packet() => { /* ... */ }
    ///     cap = parts.capsule_recv.recv_capsule() => { /* ... */ }
    /// }
    /// ```
    ///
    /// Requires the underlying QUIC stream to support `BidiStream` (all h3-quinn
    /// connections satisfy this).
    pub fn into_parts(self) -> SessionParts<C>
    where
        C::BidiStream: BidiStream<Bytes>,
    {
        let (send_stream, recv_stream) = match self.stream {
            StreamHolder::Server(s) => {
                let (send, recv) = s.split();
                (
                    SendStreamHolder::Server(send),
                    RecvStreamHolder::Server(recv),
                )
            }
            StreamHolder::Client(s) => {
                let (send, recv) = s.split();
                (
                    SendStreamHolder::Client(send),
                    RecvStreamHolder::Client(recv),
                )
            }
        };

        SessionParts {
            datagram_send: IpDatagramSender {
                dg_sender: self.dg_sender,
            },
            datagram_recv: IpDatagramReceiver {
                dg_reader: self.dg_reader,
            },
            capsule_send: CapsuleWriter {
                stream: send_stream,
            },
            capsule_recv: CapsuleReader {
                stream: recv_stream,
                capsule_buf: self.capsule_buf,
            },
            stream_id: self.stream_id,
            max_datagram_size: self.max_datagram_size,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Split parts — for concurrent I/O
// ═══════════════════════════════════════════════════════════════════════

/// The result of [`ConnectIpSession::into_parts()`].
///
/// Four independent handles that can be used concurrently:
/// - `datagram_send` / `datagram_recv` for IP packet tunneling
/// - `capsule_send` / `capsule_recv` for control plane capsules
pub struct SessionParts<C>
where
    C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
    C::BidiStream: BidiStream<Bytes>,
{
    /// Send IP packets through the tunnel.
    pub datagram_send: IpDatagramSender<C>,
    /// Receive IP packets from the tunnel.
    pub datagram_recv: IpDatagramReceiver<C>,
    /// Send capsules (address assignments, route advertisements).
    pub capsule_send: CapsuleWriter<<C::BidiStream as BidiStream<Bytes>>::SendStream>,
    /// Receive capsules from the peer.
    pub capsule_recv: CapsuleReader<<C::BidiStream as BidiStream<Bytes>>::RecvStream>,
    /// The stream ID of this session.
    pub stream_id: StreamId,
    /// The QUIC max datagram size (for MTU calculation).
    pub max_datagram_size: Option<usize>,
}

/// Sends IP packets as HTTP datagrams with Context ID 0.
pub struct IpDatagramSender<C>
where
    C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
{
    dg_sender: DatagramSender<C::SendDatagramHandler, Bytes>,
}

impl<C> IpDatagramSender<C>
where
    C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
{
    /// Send an IP packet through the tunnel.
    pub fn send_ip_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        let mut buf = BytesMut::with_capacity(1 + packet.len());
        datagram::encode_ip_datagram(packet, &mut buf);
        self.dg_sender
            .send_datagram(buf.freeze())
            .map_err(|e| Error::DatagramSend(e.to_string()))
    }
}

/// Receives IP packets from HTTP datagrams.
pub struct IpDatagramReceiver<C>
where
    C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
{
    dg_reader: DatagramReader<C::RecvDatagramHandler>,
}

impl<C> IpDatagramReceiver<C>
where
    C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
    <C::RecvDatagramHandler as h3_datagram::quic_traits::RecvDatagram>::Buffer: Into<Bytes>,
{
    /// Receive an IP packet from the tunnel.
    pub async fn recv_ip_packet(&mut self) -> Result<Bytes, Error> {
        recv_ip_packet_impl(&mut self.dg_reader).await
    }
}

/// Sends capsules on the HTTP request stream.
pub struct CapsuleWriter<S>
where
    S: SendStream<Bytes>,
{
    stream: SendStreamHolder<S>,
}

impl<S: SendStream<Bytes>> CapsuleWriter<S> {
    /// Send a raw capsule.
    pub async fn send_raw_capsule(&mut self, capsule: &RawCapsule) -> Result<(), Error> {
        send_raw_capsule_on_send_stream(&mut self.stream, capsule).await
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

    /// Close the capsule stream (sends FIN).
    pub async fn finish(&mut self) -> Result<(), Error> {
        self.stream.finish().await
    }
}

/// Receives capsules from the HTTP request stream.
pub struct CapsuleReader<S>
where
    S: RecvStream,
{
    stream: RecvStreamHolder<S>,
    capsule_buf: BytesMut,
}

impl<S: RecvStream> CapsuleReader<S> {
    /// Receive the next capsule. Unknown types are silently skipped.
    pub async fn recv_capsule(&mut self) -> Result<Option<Capsule>, Error> {
        recv_capsule_recv_stream(&mut self.stream, &mut self.capsule_buf).await
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Shared implementation helpers
// ═══════════════════════════════════════════════════════════════════════

fn compute_tunnel_mtu(max_datagram_size: Option<usize>, stream_id: StreamId) -> Option<usize> {
    max_datagram_size.map(|max_dg| {
        let quarter_id = stream_id.into_inner() / 4;
        let h3_overhead = crate::varint::encoded_len(quarter_id);
        let cip_overhead = datagram::framing_overhead(datagram::CONTEXT_ID_IP_PACKET);
        max_dg.saturating_sub(h3_overhead + cip_overhead)
    })
}

async fn recv_ip_packet_impl<R>(dg_reader: &mut DatagramReader<R>) -> Result<Bytes, Error>
where
    R: h3_datagram::quic_traits::RecvDatagram,
    R::Buffer: Into<Bytes>,
{
    loop {
        let dg = dg_reader
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

async fn send_raw_capsule_impl<S: SendStream<Bytes> + RecvStream>(
    stream: &mut StreamHolder<S>,
    capsule: &RawCapsule,
) -> Result<(), Error> {
    let mut buf = BytesMut::new();
    encode_capsule(capsule, &mut buf);
    stream.send_data(buf.freeze()).await
}

async fn send_raw_capsule_on_send_stream<S: SendStream<Bytes>>(
    stream: &mut SendStreamHolder<S>,
    capsule: &RawCapsule,
) -> Result<(), Error> {
    let mut buf = BytesMut::new();
    encode_capsule(capsule, &mut buf);
    stream.send_data(buf.freeze()).await
}

async fn send_address_assign_impl<S: SendStream<Bytes> + RecvStream>(
    stream: &mut StreamHolder<S>,
    assign: &AddressAssign,
) -> Result<(), Error> {
    let mut payload = BytesMut::new();
    encode_address_assign(assign, &mut payload);
    send_raw_capsule_impl(
        stream,
        &RawCapsule {
            capsule_type: capsule_type::ADDRESS_ASSIGN,
            payload: payload.freeze(),
        },
    )
    .await
}

async fn send_address_request_impl<S: SendStream<Bytes> + RecvStream>(
    stream: &mut StreamHolder<S>,
    request: &AddressRequest,
) -> Result<(), Error> {
    let mut payload = BytesMut::new();
    encode_address_request(request, &mut payload);
    send_raw_capsule_impl(
        stream,
        &RawCapsule {
            capsule_type: capsule_type::ADDRESS_REQUEST,
            payload: payload.freeze(),
        },
    )
    .await
}

async fn send_route_advertisement_impl<S: SendStream<Bytes> + RecvStream>(
    stream: &mut StreamHolder<S>,
    routes: &RouteAdvertisement,
) -> Result<(), Error> {
    let mut payload = BytesMut::new();
    encode_route_advertisement(routes, &mut payload);
    send_raw_capsule_impl(
        stream,
        &RawCapsule {
            capsule_type: capsule_type::ROUTE_ADVERTISEMENT,
            payload: payload.freeze(),
        },
    )
    .await
}

async fn recv_capsule_stream<S: SendStream<Bytes> + RecvStream>(
    stream: &mut StreamHolder<S>,
    capsule_buf: &mut BytesMut,
) -> Result<Option<Capsule>, Error> {
    loop {
        if !capsule_buf.is_empty() {
            let mut data = capsule_buf.clone().freeze();
            match decode_capsule(&mut data) {
                Ok(Some(raw)) => {
                    let consumed = capsule_buf.len() - data.remaining();
                    capsule_buf.advance(consumed);
                    match parse_capsule(raw) {
                        Some(capsule) => return Ok(Some(capsule)),
                        None => continue,
                    }
                }
                Ok(None) => {}
                Err(Error::UnexpectedEof) => {}
                Err(e) => return Err(e),
            }
        }

        match stream.recv_data().await? {
            Some(data) => capsule_buf.extend_from_slice(&data),
            None => {
                if capsule_buf.is_empty() {
                    return Ok(None);
                } else {
                    return Err(Error::UnexpectedEof);
                }
            }
        }
    }
}

async fn recv_capsule_recv_stream<S: RecvStream>(
    stream: &mut RecvStreamHolder<S>,
    capsule_buf: &mut BytesMut,
) -> Result<Option<Capsule>, Error> {
    loop {
        if !capsule_buf.is_empty() {
            let mut data = capsule_buf.clone().freeze();
            match decode_capsule(&mut data) {
                Ok(Some(raw)) => {
                    let consumed = capsule_buf.len() - data.remaining();
                    capsule_buf.advance(consumed);
                    match parse_capsule(raw) {
                        Some(capsule) => return Ok(Some(capsule)),
                        None => continue,
                    }
                }
                Ok(None) => {}
                Err(Error::UnexpectedEof) => {}
                Err(e) => return Err(e),
            }
        }

        match stream.recv_data().await? {
            Some(data) => capsule_buf.extend_from_slice(&data),
            None => {
                if capsule_buf.is_empty() {
                    return Ok(None);
                } else {
                    return Err(Error::UnexpectedEof);
                }
            }
        }
    }
}

/// Parse a raw capsule into a known type, or return None for unknown types.
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
