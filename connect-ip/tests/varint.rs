use bytes::{BytesMut};
use connect_ip::varint;

#[test]
fn encode_decode_single_byte() {
    let mut buf = BytesMut::new();
    varint::encode(0, &mut buf);
    assert_eq!(buf.as_ref(), &[0x00]);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 0);

    let mut buf = BytesMut::new();
    varint::encode(37, &mut buf);
    assert_eq!(buf.as_ref(), &[0x25]);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 37);

    let mut buf = BytesMut::new();
    varint::encode(63, &mut buf);
    assert_eq!(buf.as_ref(), &[0x3f]);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 63);
}

#[test]
fn encode_decode_two_byte() {
    let mut buf = BytesMut::new();
    varint::encode(64, &mut buf);
    assert_eq!(buf.len(), 2);
    assert_eq!(buf[0] >> 6, 0b01);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 64);

    let mut buf = BytesMut::new();
    varint::encode(16383, &mut buf);
    assert_eq!(buf.len(), 2);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 16383);
}

#[test]
fn encode_decode_four_byte() {
    let mut buf = BytesMut::new();
    varint::encode(16384, &mut buf);
    assert_eq!(buf.len(), 4);
    assert_eq!(buf[0] >> 6, 0b10);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 16384);

    let mut buf = BytesMut::new();
    varint::encode(1_073_741_823, &mut buf);
    assert_eq!(buf.len(), 4);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 1_073_741_823);
}

#[test]
fn encode_decode_eight_byte() {
    let mut buf = BytesMut::new();
    varint::encode(1_073_741_824, &mut buf);
    assert_eq!(buf.len(), 8);
    assert_eq!(buf[0] >> 6, 0b11);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 1_073_741_824);

    let mut buf = BytesMut::new();
    let max = 4_611_686_018_427_387_903u64;
    varint::encode(max, &mut buf);
    assert_eq!(buf.len(), 8);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), max);
}

#[test]
fn decode_empty_buffer_returns_error() {
    let mut buf = bytes::Bytes::new();
    assert!(varint::decode(&mut buf).is_err());
}

#[test]
fn decode_truncated_buffer_returns_error() {
    let mut buf = bytes::Bytes::from_static(&[0x40]);
    assert!(varint::decode(&mut buf).is_err());
}

#[test]
fn encoded_length_matches_spec() {
    assert_eq!(varint::encoded_len(0), 1);
    assert_eq!(varint::encoded_len(63), 1);
    assert_eq!(varint::encoded_len(64), 2);
    assert_eq!(varint::encoded_len(16383), 2);
    assert_eq!(varint::encoded_len(16384), 4);
    assert_eq!(varint::encoded_len(1_073_741_823), 4);
    assert_eq!(varint::encoded_len(1_073_741_824), 8);
}
