use bytes::Bytes;
use h3::ext::Protocol;
use h3::quic;
use h3::server::RequestStream;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use h3_datagram::quic_traits::DatagramConnectionExt;
use http::{Method, Response, StatusCode};

use crate::error::Error;
use crate::session::{ConnectIpSession, StreamHolder};

/// Accepts incoming CONNECT-IP requests from an h3 server connection.
pub struct ConnectIpProxy;

impl ConnectIpProxy {
    /// Accept the next CONNECT-IP request from the h3 server connection.
    ///
    /// Loops over incoming requests, rejecting non-CONNECT-IP requests with 400,
    /// until a valid CONNECT-IP Extended CONNECT request arrives.
    ///
    /// Returns `None` when the connection is closed gracefully.
    pub async fn accept<C>(
        conn: &mut h3::server::Connection<C, Bytes>,
    ) -> Result<Option<ConnectIpRequest<C>>, Error>
    where
        C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
    {
        loop {
            let resolver = match conn.accept().await? {
                Some(r) => r,
                None => return Ok(None),
            };

            let (request, stream) = resolver.resolve_request().await?;

            let is_connect_ip = request.method() == Method::CONNECT
                && request
                    .extensions()
                    .get::<Protocol>()
                    .is_some_and(|p| *p == Protocol::CONNECT_IP);

            if !is_connect_ip {
                let mut stream = stream;
                let resp = Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(())
                    .unwrap();
                let _ = stream.send_response(resp).await;
                let _ = stream.finish().await;
                continue;
            }

            let path = request.uri().path().to_string();
            let (target, ip_protocol) = parse_connect_ip_path(&path);

            return Ok(Some(ConnectIpRequest {
                target,
                ip_protocol,
                stream,
            }));
        }
    }
}

/// A pending CONNECT-IP request that can be accepted or rejected.
pub struct ConnectIpRequest<C>
where
    C: quic::Connection<Bytes>,
{
    /// The requested target (hostname, IP, or "*").
    pub target: String,
    /// The requested IP protocol scope ("*" or a number).
    pub ip_protocol: String,
    stream: RequestStream<C::BidiStream, Bytes>,
}

impl<C> ConnectIpRequest<C>
where
    C: quic::Connection<Bytes> + DatagramConnectionExt<Bytes>,
    <C::RecvDatagramHandler as h3_datagram::quic_traits::RecvDatagram>::Buffer: Into<Bytes>,
    h3::server::Connection<C, Bytes>: HandleDatagramsExt<C, Bytes>,
{
    /// Accept the CONNECT-IP request and create a session.
    ///
    /// Sends a 200 OK response and returns a session for IP packet and capsule exchange.
    /// The `conn` parameter is the h3 server connection, needed to set up datagram handlers.
    ///
    /// `max_datagram_size` is the value of `quinn::Connection::max_datagram_size()` if known,
    /// used to compute `tunnel_mtu()`. Pass `None` if unavailable.
    pub async fn accept(
        self,
        conn: &h3::server::Connection<C, Bytes>,
        max_datagram_size: Option<usize>,
    ) -> Result<ConnectIpSession<C>, Error> {
        let mut stream = self.stream;
        let resp = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap();
        stream
            .send_response(resp)
            .await
            .map_err(|e| Error::ProtocolViolation(format!("failed to send 200 OK: {e}")))?;

        let stream_id = stream.send_id();
        let dg_sender = conn.get_datagram_sender(stream_id);
        let dg_reader = conn.get_datagram_reader();

        Ok(ConnectIpSession::new(
            StreamHolder::Server(stream),
            stream_id,
            dg_sender,
            dg_reader,
            max_datagram_size,
        ))
    }

    /// Reject the CONNECT-IP request with a given status code.
    pub async fn reject(mut self, status: StatusCode) -> Result<(), Error> {
        let resp = Response::builder().status(status).body(()).unwrap();
        self.stream
            .send_response(resp)
            .await
            .map_err(|e| Error::ProtocolViolation(format!("failed to send rejection: {e}")))?;
        self.stream
            .finish()
            .await
            .map_err(|e| Error::ProtocolViolation(format!("failed to finish stream: {e}")))?;
        Ok(())
    }
}

/// Parse the CONNECT-IP URI path to extract target and ip_protocol.
fn parse_connect_ip_path(path: &str) -> (String, String) {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segments.len() >= 5
        && segments[0] == ".well-known"
        && segments[1] == "masque"
        && segments[2] == "ip"
    {
        (segments[3].to_string(), segments[4].to_string())
    } else if segments.len() >= 2 {
        (
            segments[segments.len() - 2].to_string(),
            segments[segments.len() - 1].to_string(),
        )
    } else {
        ("*".to_string(), "*".to_string())
    }
}
