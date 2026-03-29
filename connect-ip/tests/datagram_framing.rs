use bytes::{Bytes, BytesMut};
use connect_ip::datagram::{decode_ip_datagram, encode_ip_datagram};

#[test]
fn roundtrip_ipv4_packet() {
    let mut packet = vec![0x45u8; 20];
    packet[0] = 0x45;

    let mut buf = BytesMut::new();
    encode_ip_datagram(&packet, &mut buf);

    let (context_id, payload) = decode_ip_datagram(&mut buf.freeze()).unwrap();
    assert_eq!(context_id, 0);
    assert_eq!(payload.as_ref(), packet.as_slice());
}

#[test]
fn roundtrip_ipv6_packet() {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x60;

    let mut buf = BytesMut::new();
    encode_ip_datagram(&packet, &mut buf);

    let (context_id, payload) = decode_ip_datagram(&mut buf.freeze()).unwrap();
    assert_eq!(context_id, 0);
    assert_eq!(payload.as_ref(), packet.as_slice());
}

#[test]
fn context_id_zero_is_one_byte() {
    let packet = vec![0x45u8; 20];
    let mut buf = BytesMut::new();
    encode_ip_datagram(&packet, &mut buf);
    assert_eq!(buf.len(), 1 + packet.len());
}

#[test]
fn decode_non_zero_context_id() {
    let mut buf = BytesMut::new();
    connect_ip::varint::encode(5, &mut buf);
    buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

    let (context_id, payload) = decode_ip_datagram(&mut buf.freeze()).unwrap();
    assert_eq!(context_id, 5);
    assert_eq!(payload.as_ref(), &[0xAA, 0xBB, 0xCC]);
}

#[test]
fn decode_empty_is_error() {
    let result = decode_ip_datagram(&mut Bytes::new());
    assert!(result.is_err());
}
