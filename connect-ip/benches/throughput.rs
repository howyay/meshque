use bytes::{Bytes, BytesMut};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use connect_ip::capsule::codec::{decode_capsule, encode_capsule, RawCapsule};
use connect_ip::datagram::{decode_ip_datagram, encode_ip_datagram};
use connect_ip::varint;

fn bench_varint(c: &mut Criterion) {
    let mut group = c.benchmark_group("varint");

    group.bench_function("encode_1byte", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(8);
            varint::encode(42, &mut buf);
        })
    });

    group.bench_function("encode_8byte", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(8);
            varint::encode(4_000_000_000u64, &mut buf);
        })
    });

    group.bench_function("decode_1byte", |b| {
        let data = Bytes::from_static(&[0x25]);
        b.iter(|| {
            let mut buf = data.clone();
            varint::decode(&mut buf).unwrap()
        })
    });

    group.bench_function("decode_8byte", |b| {
        let mut encoded = BytesMut::new();
        varint::encode(4_000_000_000u64, &mut encoded);
        let data = encoded.freeze();
        b.iter(|| {
            let mut buf = data.clone();
            varint::decode(&mut buf).unwrap()
        })
    });

    group.finish();
}

fn bench_capsule(c: &mut Criterion) {
    let mut group = c.benchmark_group("capsule");

    let payload_1k = Bytes::from(vec![0xAA; 1024]);
    group.throughput(Throughput::Bytes(1024));

    group.bench_function("encode_1k", |b| {
        let capsule = RawCapsule {
            capsule_type: 0x01,
            payload: payload_1k.clone(),
        };
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(1040);
            encode_capsule(&capsule, &mut buf);
        })
    });

    group.bench_function("decode_1k", |b| {
        let capsule = RawCapsule {
            capsule_type: 0x01,
            payload: payload_1k.clone(),
        };
        let mut encoded = BytesMut::new();
        encode_capsule(&capsule, &mut encoded);
        let data = encoded.freeze();
        b.iter(|| {
            let mut buf = data.clone();
            decode_capsule(&mut buf).unwrap()
        })
    });

    group.finish();
}

fn bench_datagram(c: &mut Criterion) {
    let mut group = c.benchmark_group("datagram");

    // Simulate a 1280-byte IPv6 packet (minimum MTU)
    let packet = vec![0x60u8; 1280];
    group.throughput(Throughput::Bytes(1280));

    group.bench_function("encode_1280", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(1290);
            encode_ip_datagram(&packet, &mut buf);
        })
    });

    group.bench_function("decode_1280", |b| {
        let mut encoded = BytesMut::new();
        encode_ip_datagram(&packet, &mut encoded);
        let data = encoded.freeze();
        b.iter(|| {
            let mut buf = data.clone();
            decode_ip_datagram(&mut buf).unwrap()
        })
    });

    group.finish();
}

criterion_group!(benches, bench_varint, bench_capsule, bench_datagram);
criterion_main!(benches);
