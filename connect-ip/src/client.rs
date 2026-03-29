use bytes::Bytes;
use h3::ext::Protocol;
use h3::quic;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use h3_datagram::quic_traits::DatagramConnectionExt;
use http::{Method, Request, StatusCode};

use crate::error::Error;
use crate::session::{ConnectIpSession, StreamHolder};
use crate::types;

/// Client for initiating CONNECT-IP connections to a proxy.
pub struct ConnectIpClient;

impl ConnectIpClient {
    /// Connect to a CONNECT-IP proxy and establish a tunnel session.
    ///
    /// `target` is the scope of the tunnel: a hostname, IP prefix, or "*" for wildcard.
    /// `ip_protocol` is the IP protocol scope: a number 0-255 or "*" for all.
    /// `max_datagram_size` is the value of `quinn::Connection::max_datagram_size()` if known,
    /// used to compute `tunnel_mtu()`. Pass `None` if unavailable.
    ///
    /// Returns the session and a client handle bundle. The h3 driver must be polled in a
    /// background task, and the send_request handle must be kept alive.
    pub async fn connect<C>(
        quic_conn: C,
        target: &str,
        ip_protocol: &str,
        max_datagram_size: Option<usize>,
    ) -> Result<ConnectIpClientSession<C>, Error>
    where
        C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
        <C::RecvDatagramHandler as h3_datagram::quic_traits::RecvDatagram>::Buffer: Into<Bytes>,
        h3::client::Connection<C, Bytes>: HandleDatagramsExt<C, Bytes>,
        C::OpenStreams: Clone,
    {
        let (h3_conn, mut send_request) = h3::client::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(quic_conn)
            .await?;

        let uri = format!(
            "https://localhost{}",
            types::DEFAULT_URI_TEMPLATE
                .replace("{target}", target)
                .replace("{ipproto}", ip_protocol)
        );

        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .extension(Protocol::CONNECT_IP)
            .body(())
            .map_err(|e| Error::ProtocolViolation(format!("failed to build request: {e}")))?;

        let mut stream = send_request.send_request(req).await?;

        let resp = stream
            .recv_response()
            .await
            .map_err(|e| Error::ProtocolViolation(format!("failed to receive response: {e}")))?;

        if resp.status() != StatusCode::OK {
            return Err(Error::ProtocolViolation(format!(
                "proxy rejected CONNECT-IP with status {}",
                resp.status()
            )));
        }

        let stream_id = stream.id();
        let dg_sender = h3_conn.get_datagram_sender(stream_id);
        let dg_reader = h3_conn.get_datagram_reader();

        let session = ConnectIpSession::new(
            StreamHolder::Client(stream),
            stream_id,
            dg_sender,
            dg_reader,
            max_datagram_size,
        );

        Ok(ConnectIpClientSession {
            session,
            driver: h3_conn,
            _send_request: send_request,
        })
    }
}

/// The result of a successful CONNECT-IP client connection.
///
/// Holds the session, the h3 driver (must be polled), and the send_request handle
/// (must be kept alive for the session's lifetime).
pub struct ConnectIpClientSession<C>
where
    C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
{
    /// The CONNECT-IP session for IP packet and capsule exchange.
    pub session: ConnectIpSession<C>,
    /// The h3 client connection driver. Must be polled via `driver.wait_idle().await`
    /// in a background task.
    pub driver: h3::client::Connection<C, Bytes>,
    /// Keep alive handle — dropping this closes the h3 connection.
    _send_request: h3::client::SendRequest<C::OpenStreams, Bytes>,
}
