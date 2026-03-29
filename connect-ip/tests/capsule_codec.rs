use bytes::{Bytes, BytesMut};
use connect_ip::capsule::codec::{decode_capsule, encode_capsule, RawCapsule};

#[test]
fn roundtrip_empty_payload() {
    let capsule = RawCapsule {
        capsule_type: 0x01,
        payload: Bytes::new(),
    };
    let mut buf = BytesMut::new();
    encode_capsule(&capsule, &mut buf);

    let decoded = decode_capsule(&mut buf.freeze()).unwrap().unwrap();
    assert_eq!(decoded.capsule_type, 0x01);
    assert!(decoded.payload.is_empty());
}

#[test]
fn roundtrip_with_payload() {
    let payload = Bytes::from_static(b"hello");
    let capsule = RawCapsule {
        capsule_type: 0x03,
        payload: payload.clone(),
    };
    let mut buf = BytesMut::new();
    encode_capsule(&capsule, &mut buf);

    let decoded = decode_capsule(&mut buf.freeze()).unwrap().unwrap();
    assert_eq!(decoded.capsule_type, 0x03);
    assert_eq!(decoded.payload, payload);
}

#[test]
fn roundtrip_large_type() {
    let capsule = RawCapsule {
        capsule_type: 0x00100000,
        payload: Bytes::from_static(&[0xAA; 100]),
    };
    let mut buf = BytesMut::new();
    encode_capsule(&capsule, &mut buf);

    let decoded = decode_capsule(&mut buf.freeze()).unwrap().unwrap();
    assert_eq!(decoded.capsule_type, 0x00100000);
    assert_eq!(decoded.payload.len(), 100);
}

#[test]
fn decode_empty_returns_none() {
    let mut buf = Bytes::new();
    assert!(decode_capsule(&mut buf).unwrap().is_none());
}

#[test]
fn decode_truncated_type_returns_error() {
    let mut buf = Bytes::from_static(&[0x40]);
    assert!(decode_capsule(&mut buf).is_err());
}

#[test]
fn decode_truncated_payload_returns_error() {
    let mut buf = Bytes::from_static(&[0x01, 0x0A, 0xAA, 0xBB, 0xCC]);
    assert!(decode_capsule(&mut buf).is_err());
}

#[test]
fn multiple_capsules_in_sequence() {
    let c1 = RawCapsule {
        capsule_type: 0x01,
        payload: Bytes::from_static(b"abc"),
    };
    let c2 = RawCapsule {
        capsule_type: 0x02,
        payload: Bytes::from_static(b"de"),
    };

    let mut buf = BytesMut::new();
    encode_capsule(&c1, &mut buf);
    encode_capsule(&c2, &mut buf);
    let mut data = buf.freeze();

    let d1 = decode_capsule(&mut data).unwrap().unwrap();
    assert_eq!(d1.capsule_type, 0x01);
    assert_eq!(d1.payload, Bytes::from_static(b"abc"));

    let d2 = decode_capsule(&mut data).unwrap().unwrap();
    assert_eq!(d2.capsule_type, 0x02);
    assert_eq!(d2.payload, Bytes::from_static(b"de"));

    assert!(decode_capsule(&mut data).unwrap().is_none());
}
