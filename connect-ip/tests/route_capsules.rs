use bytes::BytesMut;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use connect_ip::capsule::route::{
    decode_route_advertisement, encode_ip_address_range, encode_route_advertisement,
    IpAddressRange, RouteAdvertisement,
};
use connect_ip::types::IpVersion;

#[test]
fn roundtrip_single_ipv4_range() {
    let routes = RouteAdvertisement {
        ranges: vec![IpAddressRange {
            ip_version: IpVersion::V4,
            start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)),
            ip_protocol: 0,
        }],
    };

    let mut buf = BytesMut::new();
    encode_route_advertisement(&routes, &mut buf);
    let decoded = decode_route_advertisement(&mut buf.freeze()).unwrap();

    assert_eq!(decoded.ranges.len(), 1);
    assert_eq!(
        decoded.ranges[0].start,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))
    );
    assert_eq!(
        decoded.ranges[0].end,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255))
    );
    assert_eq!(decoded.ranges[0].ip_protocol, 0);
}

#[test]
fn roundtrip_multiple_ranges_sorted() {
    let routes = RouteAdvertisement {
        ranges: vec![
            IpAddressRange {
                ip_version: IpVersion::V4,
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)),
                ip_protocol: 0,
            },
            IpAddressRange {
                ip_version: IpVersion::V4,
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 0)),
                end: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 255)),
                ip_protocol: 0,
            },
            IpAddressRange {
                ip_version: IpVersion::V6,
                start: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                end: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xFFFF)),
                ip_protocol: 0,
            },
        ],
    };

    let mut buf = BytesMut::new();
    encode_route_advertisement(&routes, &mut buf);
    let decoded = decode_route_advertisement(&mut buf.freeze()).unwrap();
    assert_eq!(decoded.ranges.len(), 3);
}

#[test]
fn decode_unsorted_ranges_is_error() {
    let routes = RouteAdvertisement {
        ranges: vec![
            IpAddressRange {
                ip_version: IpVersion::V6,
                start: IpAddr::V6(Ipv6Addr::LOCALHOST),
                end: IpAddr::V6(Ipv6Addr::LOCALHOST),
                ip_protocol: 0,
            },
            IpAddressRange {
                ip_version: IpVersion::V4,
                start: IpAddr::V4(Ipv4Addr::LOCALHOST),
                end: IpAddr::V4(Ipv4Addr::LOCALHOST),
                ip_protocol: 0,
            },
        ],
    };

    // Encode without sorting for negative test
    let mut buf = BytesMut::new();
    for range in &routes.ranges {
        encode_ip_address_range(range, &mut buf);
    }
    let result = decode_route_advertisement(&mut buf.freeze());
    assert!(result.is_err());
}

#[test]
fn decode_overlapping_ranges_is_error() {
    let routes = RouteAdvertisement {
        ranges: vec![
            IpAddressRange {
                ip_version: IpVersion::V4,
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 200)),
                ip_protocol: 0,
            },
            IpAddressRange {
                ip_version: IpVersion::V4,
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)),
                end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)),
                ip_protocol: 0,
            },
        ],
    };

    // Encode without sorting
    let mut buf = BytesMut::new();
    for range in &routes.ranges {
        encode_ip_address_range(range, &mut buf);
    }
    let result = decode_route_advertisement(&mut buf.freeze());
    assert!(result.is_err());
}

#[test]
fn roundtrip_empty_routes() {
    let routes = RouteAdvertisement { ranges: vec![] };
    let mut buf = BytesMut::new();
    encode_route_advertisement(&routes, &mut buf);
    let decoded = decode_route_advertisement(&mut buf.freeze()).unwrap();
    assert!(decoded.ranges.is_empty());
}

#[test]
fn encode_sorts_ranges() {
    let routes = RouteAdvertisement {
        ranges: vec![
            IpAddressRange {
                ip_version: IpVersion::V6,
                start: IpAddr::V6(Ipv6Addr::LOCALHOST),
                end: IpAddr::V6(Ipv6Addr::LOCALHOST),
                ip_protocol: 0,
            },
            IpAddressRange {
                ip_version: IpVersion::V4,
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)),
                ip_protocol: 0,
            },
        ],
    };

    let mut buf = BytesMut::new();
    encode_route_advertisement(&routes, &mut buf);
    let decoded = decode_route_advertisement(&mut buf.freeze()).unwrap();
    assert_eq!(decoded.ranges[0].ip_version, IpVersion::V4);
    assert_eq!(decoded.ranges[1].ip_version, IpVersion::V6);
}
