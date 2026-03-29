use bytes::BytesMut;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use connect_ip::capsule::address::{
    decode_address_assign, decode_address_request, encode_address_assign, encode_address_request,
    AddressAssign, AddressRequest, AssignedAddress, RequestedAddress,
};
use connect_ip::types::IpVersion;

#[test]
fn roundtrip_address_assign_ipv4() {
    let assign = AddressAssign {
        addresses: vec![AssignedAddress {
            request_id: 1,
            ip_version: IpVersion::V4,
            address: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            prefix_length: 32,
        }],
    };

    let mut buf = BytesMut::new();
    encode_address_assign(&assign, &mut buf);
    let decoded = decode_address_assign(&mut buf.freeze()).unwrap();

    assert_eq!(decoded.addresses.len(), 1);
    assert_eq!(decoded.addresses[0].request_id, 1);
    assert_eq!(decoded.addresses[0].ip_version, IpVersion::V4);
    assert_eq!(
        decoded.addresses[0].address,
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
    );
    assert_eq!(decoded.addresses[0].prefix_length, 32);
}

#[test]
fn roundtrip_address_assign_ipv6() {
    let assign = AddressAssign {
        addresses: vec![AssignedAddress {
            request_id: 0,
            ip_version: IpVersion::V6,
            address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            prefix_length: 128,
        }],
    };

    let mut buf = BytesMut::new();
    encode_address_assign(&assign, &mut buf);
    let decoded = decode_address_assign(&mut buf.freeze()).unwrap();

    assert_eq!(decoded.addresses.len(), 1);
    assert_eq!(decoded.addresses[0].request_id, 0);
    assert_eq!(decoded.addresses[0].ip_version, IpVersion::V6);
    assert_eq!(decoded.addresses[0].prefix_length, 128);
}

#[test]
fn roundtrip_address_assign_multiple() {
    let assign = AddressAssign {
        addresses: vec![
            AssignedAddress {
                request_id: 1,
                ip_version: IpVersion::V4,
                address: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
                prefix_length: 32,
            },
            AssignedAddress {
                request_id: 2,
                ip_version: IpVersion::V6,
                address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                prefix_length: 128,
            },
        ],
    };

    let mut buf = BytesMut::new();
    encode_address_assign(&assign, &mut buf);
    let decoded = decode_address_assign(&mut buf.freeze()).unwrap();
    assert_eq!(decoded.addresses.len(), 2);
    assert_eq!(decoded.addresses[0].request_id, 1);
    assert_eq!(decoded.addresses[1].request_id, 2);
}

#[test]
fn roundtrip_address_assign_empty() {
    let assign = AddressAssign {
        addresses: vec![],
    };
    let mut buf = BytesMut::new();
    encode_address_assign(&assign, &mut buf);
    let decoded = decode_address_assign(&mut buf.freeze()).unwrap();
    assert!(decoded.addresses.is_empty());
}

#[test]
fn roundtrip_address_request() {
    let request = AddressRequest {
        addresses: vec![RequestedAddress {
            request_id: 42,
            ip_version: IpVersion::V4,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_length: 32,
        }],
    };

    let mut buf = BytesMut::new();
    encode_address_request(&request, &mut buf);
    let decoded = decode_address_request(&mut buf.freeze()).unwrap();

    assert_eq!(decoded.addresses.len(), 1);
    assert_eq!(decoded.addresses[0].request_id, 42);
    assert_eq!(
        decoded.addresses[0].address,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    );
}

#[test]
fn address_request_empty_is_error() {
    let request = AddressRequest {
        addresses: vec![],
    };
    let mut buf = BytesMut::new();
    encode_address_request(&request, &mut buf);
    let result = decode_address_request(&mut buf.freeze());
    assert!(result.is_err());
}

#[test]
fn address_request_zero_request_id_is_error() {
    let request = AddressRequest {
        addresses: vec![RequestedAddress {
            request_id: 0,
            ip_version: IpVersion::V4,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_length: 32,
        }],
    };
    let mut buf = BytesMut::new();
    encode_address_request(&request, &mut buf);
    let result = decode_address_request(&mut buf.freeze());
    assert!(result.is_err());
}

#[test]
fn address_assign_prefix_validation() {
    let assign = AddressAssign {
        addresses: vec![AssignedAddress {
            request_id: 1,
            ip_version: IpVersion::V4,
            address: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            prefix_length: 24,
        }],
    };
    let mut buf = BytesMut::new();
    encode_address_assign(&assign, &mut buf);
    let result = decode_address_assign(&mut buf.freeze());
    assert!(result.is_err());
}
