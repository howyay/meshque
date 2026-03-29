use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::Error;
use crate::types::IpVersion;

/// ROUTE_ADVERTISEMENT capsule payload (RFC 9484 §4.7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAdvertisement {
    pub ranges: Vec<IpAddressRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAddressRange {
    pub ip_version: IpVersion,
    pub start: IpAddr,
    pub end: IpAddr,
    pub ip_protocol: u8,
}

/// Encode a ROUTE_ADVERTISEMENT payload. Sorts ranges per RFC ordering requirements.
pub fn encode_route_advertisement(routes: &RouteAdvertisement, buf: &mut BytesMut) {
    let mut sorted = routes.ranges.clone();
    sorted.sort_by(|a, b| {
        let va = a.ip_version as u8;
        let vb = b.ip_version as u8;
        va.cmp(&vb)
            .then(a.ip_protocol.cmp(&b.ip_protocol))
            .then(cmp_ip_addr(&a.start, &b.start))
    });

    for range in &sorted {
        encode_ip_address_range(range, buf);
    }
}

/// Encode a single IP address range entry. Public for test helpers.
pub fn encode_ip_address_range(range: &IpAddressRange, buf: &mut BytesMut) {
    buf.put_u8(range.ip_version as u8);
    encode_ip_addr(&range.start, buf);
    encode_ip_addr(&range.end, buf);
    buf.put_u8(range.ip_protocol);
}

/// Decode a ROUTE_ADVERTISEMENT payload. Validates sorting and non-overlap per RFC.
pub fn decode_route_advertisement(buf: &mut Bytes) -> Result<RouteAdvertisement, Error> {
    let mut ranges = Vec::new();

    while buf.has_remaining() {
        let ip_version = IpVersion::from_u8(buf_get_u8(buf)?).ok_or_else(|| {
            Error::MalformedCapsule {
                capsule_type: 0x03,
                detail: "invalid IP version".into(),
            }
        })?;
        let start = decode_ip_addr(ip_version, buf)?;
        let end = decode_ip_addr(ip_version, buf)?;
        let ip_protocol = buf_get_u8(buf)?;

        if cmp_ip_addr(&start, &end) == std::cmp::Ordering::Greater {
            return Err(Error::ProtocolViolation(
                "ROUTE_ADVERTISEMENT range start > end".into(),
            ));
        }

        let range = IpAddressRange {
            ip_version,
            start,
            end,
            ip_protocol,
        };

        if let Some(prev) = ranges.last() {
            validate_range_order(prev, &range)?;
        }

        ranges.push(range);
    }

    Ok(RouteAdvertisement { ranges })
}

fn validate_range_order(prev: &IpAddressRange, curr: &IpAddressRange) -> Result<(), Error> {
    let pv = prev.ip_version as u8;
    let cv = curr.ip_version as u8;

    if pv > cv {
        return Err(Error::ProtocolViolation(
            "ROUTE_ADVERTISEMENT ranges not sorted by IP version".into(),
        ));
    }

    if pv == cv {
        if prev.ip_protocol > curr.ip_protocol {
            return Err(Error::ProtocolViolation(
                "ROUTE_ADVERTISEMENT ranges not sorted by IP protocol".into(),
            ));
        }

        if prev.ip_protocol == curr.ip_protocol
            && cmp_ip_addr(&prev.end, &curr.start) != std::cmp::Ordering::Less
        {
            return Err(Error::ProtocolViolation(
                "ROUTE_ADVERTISEMENT ranges overlap".into(),
            ));
        }
    }

    Ok(())
}

fn cmp_ip_addr(a: &IpAddr, b: &IpAddr) -> std::cmp::Ordering {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets().cmp(&b.octets()),
        (IpAddr::V6(a), IpAddr::V6(b)) => a.octets().cmp(&b.octets()),
        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
    }
}

fn encode_ip_addr(addr: &IpAddr, buf: &mut BytesMut) {
    match addr {
        IpAddr::V4(v4) => buf.put_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.put_slice(&v6.octets()),
    }
}

fn decode_ip_addr(version: IpVersion, buf: &mut Bytes) -> Result<IpAddr, Error> {
    let len = version.addr_len();
    if buf.remaining() < len {
        return Err(Error::UnexpectedEof);
    }
    match version {
        IpVersion::V4 => {
            let mut octets = [0u8; 4];
            buf.copy_to_slice(&mut octets);
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        IpVersion::V6 => {
            let mut octets = [0u8; 16];
            buf.copy_to_slice(&mut octets);
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
    }
}

fn buf_get_u8(buf: &mut Bytes) -> Result<u8, Error> {
    if !buf.has_remaining() {
        return Err(Error::UnexpectedEof);
    }
    Ok(buf.get_u8())
}
