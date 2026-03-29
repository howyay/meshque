//! Interop test: our Rust client ↔ connect-ip-go proxy.
//!
//! Requires: Go runtime (via nix-shell -p go).
//! Run: cargo test --features interop --test go_proxy
#![cfg(feature = "interop")]

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use connect_ip::session::Capsule;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;

/// Generate a self-signed cert and write cert.pem + key.pem to the given dir.
fn generate_certs(dir: &std::path::Path) -> Vec<CertificateDer<'static>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    std::fs::write(dir.join("cert.pem"), &cert_pem).unwrap();
    std::fs::write(dir.join("key.pem"), &key_pem).unwrap();

    let cert_der = CertificateDer::from(cert.cert);
    vec![cert_der]
}

/// Start the Go proxy and wait for its "LISTENING <addr>" line.
fn start_go_proxy(cert_dir: &std::path::Path) -> (Child, SocketAddr) {
    let go_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/interop/go_programs");

    let mut child = Command::new("nix-shell")
        .args([
            "-p",
            "go",
            "--run",
            &format!(
                "cd {} && go run proxy.go 127.0.0.1:0 {}/cert.pem {}/key.pem",
                go_dir.display(),
                cert_dir.display(),
                cert_dir.display(),
            ),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start Go proxy (is Go available via nix-shell?)");

    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);

    let mut addr = None;
    for line in reader.lines() {
        let line = line.unwrap();
        eprintln!("[go-proxy] {}", line);
        if let Some(rest) = line.strip_prefix("LISTENING ") {
            addr = Some(rest.parse::<SocketAddr>().unwrap());
            break;
        }
    }

    let addr = addr.expect("Go proxy did not print LISTENING line");
    (child, addr)
}

#[tokio::test]
async fn rust_client_to_go_proxy() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let certs = generate_certs(tmp_dir.path());

    let (mut go_proc, proxy_addr) = start_go_proxy(tmp_dir.path());

    // Give proxy a moment to be fully ready
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Build quinn client
    let mut roots = rustls::RootCertStore::empty();
    for cert in &certs {
        roots.add(cert.clone()).unwrap();
    }
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(transport);

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);

    let quic_conn = endpoint
        .connect(proxy_addr, "localhost")
        .unwrap()
        .await
        .expect("QUIC connection to Go proxy failed");

    let h3_conn = h3_quinn::Connection::new(quic_conn);

    // Build h3 client connection
    let (h3_client, mut send_request) = h3::client::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build::<_, _, Bytes>(h3_conn)
        .await
        .unwrap();

    // Get datagram handlers BEFORE moving h3_client to driver
    // Build the CONNECT request
    let req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("https://localhost:{}/vpn", proxy_addr.port()))
        .extension(h3::ext::Protocol::CONNECT_IP)
        .header("Capsule-Protocol", "?1")
        .body(())
        .unwrap();

    let mut stream = send_request.send_request(req).await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "Go proxy should accept our CONNECT-IP request"
    );

    eprintln!("[rust] Got 200 OK from Go proxy");

    // Get datagram handlers scoped to this stream
    let stream_id = stream.id();
    let mut dg_sender = h3_client.get_datagram_sender(stream_id);
    let mut dg_reader = h3_client.get_datagram_reader();

    // Drive h3 in background
    let driver_handle = tokio::spawn(async move {
        let mut driver = h3_client;
        driver.wait_idle().await;
    });

    // ── Step 1: Receive ADDRESS_ASSIGN capsule from Go proxy ─────────
    // The Go proxy sends ADDRESS_ASSIGN after accepting.
    // Read capsule data from the stream.
    let capsule_data = stream.recv_data().await.unwrap();
    if let Some(mut data) = capsule_data {
        use bytes::Buf;
        let mut buf = bytes::BytesMut::with_capacity(data.remaining());
        while data.has_remaining() {
            let chunk = data.chunk();
            buf.extend_from_slice(chunk);
            let len = chunk.len();
            data.advance(len);
        }
        let mut frozen = buf.freeze();
        let capsule = connect_ip::capsule::codec::decode_capsule(&mut frozen).unwrap();
        if let Some(raw) = capsule {
            eprintln!(
                "[rust] Received capsule type={:#x}, payload_len={}",
                raw.capsule_type,
                raw.payload.len()
            );
            assert_eq!(raw.capsule_type, 0x01, "first capsule should be ADDRESS_ASSIGN");

            let mut payload = raw.payload;
            let assign =
                connect_ip::capsule::address::decode_address_assign(&mut payload).unwrap();
            eprintln!("[rust] ADDRESS_ASSIGN: {:?}", assign);
            assert_eq!(assign.addresses.len(), 1);
            assert_eq!(
                assign.addresses[0].address,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 1))
            );
            assert_eq!(assign.addresses[0].prefix_length, 32);
        }
    }

    // ── Step 2: Receive ROUTE_ADVERTISEMENT capsule ──────────────────
    let route_data = stream.recv_data().await.unwrap();
    if let Some(mut data) = route_data {
        use bytes::Buf;
        let mut buf = bytes::BytesMut::with_capacity(data.remaining());
        while data.has_remaining() {
            let chunk = data.chunk();
            buf.extend_from_slice(chunk);
            let len = chunk.len();
            data.advance(len);
        }
        let mut frozen = buf.freeze();
        let capsule = connect_ip::capsule::codec::decode_capsule(&mut frozen).unwrap();
        if let Some(raw) = capsule {
            eprintln!(
                "[rust] Received capsule type={:#x}, payload_len={}",
                raw.capsule_type,
                raw.payload.len()
            );
            assert_eq!(
                raw.capsule_type, 0x03,
                "second capsule should be ROUTE_ADVERTISEMENT"
            );

            let mut payload = raw.payload;
            let routes =
                connect_ip::capsule::route::decode_route_advertisement(&mut payload).unwrap();
            eprintln!("[rust] ROUTE_ADVERTISEMENT: {:?}", routes);
            assert_eq!(routes.ranges.len(), 1);
            assert_eq!(
                routes.ranges[0].start,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 0))
            );
            assert_eq!(
                routes.ranges[0].end,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 255))
            );
        }
    }

    // ── Step 3: Send IP packets and receive echoes ───────────────────
    // Build a minimal IPv4 packet (version=4, IHL=5, total_length=20, src=100.64.0.1, dst=10.0.0.1)
    let mut ipv4_packet = [0u8; 20];
    ipv4_packet[0] = 0x45; // version=4, IHL=5
    ipv4_packet[2] = 0x00; // total length high
    ipv4_packet[3] = 0x14; // total length = 20
    ipv4_packet[8] = 64; // TTL
    ipv4_packet[9] = 6; // protocol = TCP
    // src = 100.64.0.1
    ipv4_packet[12] = 100;
    ipv4_packet[13] = 64;
    ipv4_packet[14] = 0;
    ipv4_packet[15] = 1;
    // dst = 10.0.0.1
    ipv4_packet[16] = 10;
    ipv4_packet[17] = 0;
    ipv4_packet[18] = 0;
    ipv4_packet[19] = 1;

    for i in 0..3 {
        // Encode: Context ID 0 (varint) + IP packet
        let mut dg_buf = bytes::BytesMut::with_capacity(1 + ipv4_packet.len());
        connect_ip::varint::encode(0, &mut dg_buf); // context ID 0
        dg_buf.extend_from_slice(&ipv4_packet);

        dg_sender
            .send_datagram(dg_buf.freeze())
            .expect("failed to send datagram");
        eprintln!("[rust] Sent IP packet #{}", i + 1);

        // Receive echo
        let dg = dg_reader.read_datagram().await.unwrap();
        let mut payload: Bytes = dg.into_payload();
        let (ctx_id, echoed_packet) =
            connect_ip::datagram::decode_ip_datagram(&mut payload).unwrap();
        assert_eq!(ctx_id, 0, "echo should have context ID 0");
        assert_eq!(echoed_packet.len(), 20);
        eprintln!("[rust] Received echo #{} ({} bytes)", i + 1, echoed_packet.len());
    }

    eprintln!("[rust] All 3 packets echoed successfully — interop verified!");

    // Clean up
    drop(send_request);
    drop(stream);
    driver_handle.abort();
    go_proc.kill().ok();
    go_proc.wait().ok();
}
