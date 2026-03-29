#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = Bytes::copy_from_slice(data);

    // Fuzz the datagram decoder — must never panic
    let _ = connect_ip::datagram::decode_ip_datagram(&mut buf);

    // Fuzz the varint decoder
    let mut buf = Bytes::copy_from_slice(data);
    let _ = connect_ip::varint::decode(&mut buf);
});
