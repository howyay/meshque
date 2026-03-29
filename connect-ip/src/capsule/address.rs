use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::Error;
use crate::types::IpVersion;
use crate::varint;

/// ADDRESS_ASSIGN capsule payload (RFC 9484 §4.7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressAssign {
    pub addresses: Vec<AssignedAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedAddress {
    pub request_id: u64,
    pub ip_version: IpVersion,
    pub address: IpAddr,
    pub prefix_length: u8,
}

/// ADDRESS_REQUEST capsule payload (RFC 9484 §4.7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRequest {
    pub addresses: Vec<RequestedAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedAddress {
    pub request_id: u64,
    pub ip_version: IpVersion,
    pub address: IpAddr,
    pub prefix_length: u8,
}

/// Encode an ADDRESS_ASSIGN payload (not including the capsule TLV header).
pub fn encode_address_assign(assign: &AddressAssign, buf: &mut BytesMut) {
    for addr in &assign.addresses {
        varint::encode(addr.request_id, buf);
        buf.put_u8(addr.ip_version as u8);
        encode_ip_addr(&addr.address, buf);
        buf.put_u8(addr.prefix_length);
    }
}

/// Decode an ADDRESS_ASSIGN payload.
pub fn decode_address_assign(buf: &mut Bytes) -> Result<AddressAssign, Error> {
    let mut addresses = Vec::new();
    while buf.has_remaining() {
        let request_id = varint::decode(buf)?;
        let ip_version = IpVersion::from_u8(buf_get_u8(buf)?).ok_or_else(|| {
            Error::MalformedCapsule {
                capsule_type: 0x01,
                detail: "invalid IP version".into(),
            }
        })?;
        let address = decode_ip_addr(ip_version, buf)?;
        let prefix_length = buf_get_u8(buf)?;

        if prefix_length > ip_version.max_prefix_len() {
            return Err(Error::MalformedCapsule {
                capsule_type: 0x01,
                detail: format!(
                    "prefix length {prefix_length} exceeds max {} for {:?}",
                    ip_version.max_prefix_len(),
                    ip_version
                ),
            });
        }

        validate_prefix_bits(&address, prefix_length, ip_version)?;

        addresses.push(AssignedAddress {
            request_id,
            ip_version,
            address,
            prefix_length,
        });
    }
    Ok(AddressAssign { addresses })
}

/// Encode an ADDRESS_REQUEST payload (not including the capsule TLV header).
pub fn encode_address_request(request: &AddressRequest, buf: &mut BytesMut) {
    for addr in &request.addresses {
        varint::encode(addr.request_id, buf);
        buf.put_u8(addr.ip_version as u8);
        encode_ip_addr(&addr.address, buf);
        buf.put_u8(addr.prefix_length);
    }
}

/// Decode an ADDRESS_REQUEST payload.
pub fn decode_address_request(buf: &mut Bytes) -> Result<AddressRequest, Error> {
    let mut addresses = Vec::new();
    while buf.has_remaining() {
        let request_id = varint::decode(buf)?;
        if request_id == 0 {
            return Err(Error::ProtocolViolation(
                "ADDRESS_REQUEST request_id must be non-zero".into(),
            ));
        }
        let ip_version = IpVersion::from_u8(buf_get_u8(buf)?).ok_or_else(|| {
            Error::MalformedCapsule {
                capsule_type: 0x02,
                detail: "invalid IP version".into(),
            }
        })?;
        let address = decode_ip_addr(ip_version, buf)?;
        let prefix_length = buf_get_u8(buf)?;

        if prefix_length > ip_version.max_prefix_len() {
            return Err(Error::MalformedCapsule {
                capsule_type: 0x02,
                detail: format!(
                    "prefix length {prefix_length} exceeds max {} for {:?}",
                    ip_version.max_prefix_len(),
                    ip_version
                ),
            });
        }

        addresses.push(RequestedAddress {
            request_id,
            ip_version,
            address,
            prefix_length,
        });
    }

    if addresses.is_empty() {
        return Err(Error::ProtocolViolation(
            "ADDRESS_REQUEST must contain at least one entry".into(),
        ));
    }

    Ok(AddressRequest { addresses })
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

fn validate_prefix_bits(
    addr: &IpAddr,
    prefix_length: u8,
    version: IpVersion,
) -> Result<(), Error> {
    let max = version.max_prefix_len();
    if prefix_length >= max {
        return Ok(());
    }
    let host_bits = (max - prefix_length) as u32;
    let has_lower_bits = match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(*v4);
            let mask = (1u32 << host_bits) - 1;
            bits & mask != 0
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(*v6);
            let mask = (1u128 << host_bits) - 1;
            bits & mask != 0
        }
    };
    if has_lower_bits {
        return Err(Error::MalformedCapsule {
            capsule_type: 0x01,
            detail: format!(
                "address {addr} has non-zero bits below prefix length {prefix_length}"
            ),
        });
    }
    Ok(())
}
