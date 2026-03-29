use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("QUIC connection error: {0}")]
    Quic(#[from] quinn::ConnectionError),

    #[error("HTTP/3 error: {0}")]
    H3(#[from] h3::error::ConnectionError),

    #[error("HTTP/3 stream error: {0}")]
    H3Stream(#[from] h3::error::StreamError),

    #[error("malformed capsule (type {capsule_type:#x}): {detail}")]
    MalformedCapsule { capsule_type: u64, detail: String },

    #[error("protocol violation: {0}")]
    ProtocolViolation(String),

    #[error("stream aborted by peer")]
    StreamAborted,

    #[error("MTU too low for IPv6 minimum: {available} bytes available, 1280 required")]
    MtuTooLow { available: usize },

    #[error("session closed")]
    SessionClosed,

    #[error("invalid varint encoding")]
    InvalidVarint,

    #[error("datagram send error: {0}")]
    DatagramSend(String),

    #[error("unexpected end of data")]
    UnexpectedEof,
}
