#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = Bytes::copy_from_slice(data);

    // Fuzz the raw capsule decoder — must never panic
    while buf.has_remaining() {
        match connect_ip::capsule::codec::decode_capsule(&mut buf) {
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => break,
        }
    }

    // Fuzz address capsule decoders
    let mut buf = Bytes::copy_from_slice(data);
    let _ = connect_ip::capsule::address::decode_address_assign(&mut buf);

    let mut buf = Bytes::copy_from_slice(data);
    let _ = connect_ip::capsule::address::decode_address_request(&mut buf);

    // Fuzz route capsule decoder
    let mut buf = Bytes::copy_from_slice(data);
    let _ = connect_ip::capsule::route::decode_route_advertisement(&mut buf);
});

use bytes::Buf;
