mod helpers;

use connect_ip::client::ConnectIpClient;
use connect_ip::proxy::ConnectIpProxy;
use http::{Request, StatusCode};

#[tokio::test]
async fn client_connects_to_proxy_and_exchanges_packets() {
    let (certs, key) = helpers::generate_test_certs();
    let (server_endpoint, server_addr) = helpers::make_server_endpoint(certs.clone(), key);
    let client_endpoint = helpers::make_client_endpoint(&certs);

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawn proxy
    let proxy_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let quic_conn = incoming.await.unwrap();
        let h3_conn = h3_quinn::Connection::new(quic_conn);

        let mut conn = h3::server::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(h3_conn)
            .await
            .unwrap();

        let request = ConnectIpProxy::accept(&mut conn).await.unwrap().unwrap();
        assert_eq!(request.target, "*");
        assert_eq!(request.ip_protocol, "*");

        let mut session = request.accept(&conn, None).await.unwrap();

        // Proxy receives an IP packet from client
        let packet = session.recv_ip_packet().await.unwrap();
        assert_eq!(packet.as_ref(), &[0x45u8; 20]);

        // Proxy echoes it back
        session.send_ip_packet(&packet).unwrap();

        // Wait for client to signal completion before dropping the connection
        let _ = done_rx.await;
    });

    // Client connects
    let quic_conn = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    let h3_conn = h3_quinn::Connection::new(quic_conn);

    let mut client_session =
        ConnectIpClient::connect(h3_conn, "*", "*", None).await.unwrap();

    // Drive h3 connection in background
    let driver_handle = tokio::spawn(async move {
        let mut driver = client_session.driver;
        driver.wait_idle().await;
    });

    // Send a fake IPv4 packet
    let test_packet = vec![0x45u8; 20];
    client_session.session.send_ip_packet(&test_packet).unwrap();

    // Receive echo
    let echoed = client_session.session.recv_ip_packet().await.unwrap();
    assert_eq!(echoed.as_ref(), test_packet.as_slice());

    // Signal proxy that we're done
    let _ = done_tx.send(());

    // Wait for proxy to finish
    proxy_handle.await.unwrap();

    drop(client_session.session);
    driver_handle.abort();
}

#[tokio::test]
async fn multiple_packets_roundtrip() {
    let (certs, key) = helpers::generate_test_certs();
    let (server_endpoint, server_addr) = helpers::make_server_endpoint(certs.clone(), key);
    let client_endpoint = helpers::make_client_endpoint(&certs);

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let proxy_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let quic_conn = incoming.await.unwrap();
        let h3_conn = h3_quinn::Connection::new(quic_conn);

        let mut conn = h3::server::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(h3_conn)
            .await
            .unwrap();

        let request = ConnectIpProxy::accept(&mut conn).await.unwrap().unwrap();
        let mut session = request.accept(&conn, None).await.unwrap();

        // Echo 10 packets
        for _ in 0..10 {
            let packet = session.recv_ip_packet().await.unwrap();
            session.send_ip_packet(&packet).unwrap();
        }

        // Keep connection alive until client is done
        let _ = done_rx.await;
    });

    let quic_conn = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    let h3_conn = h3_quinn::Connection::new(quic_conn);
    let mut client_session = ConnectIpClient::connect(h3_conn, "*", "*", None).await.unwrap();

    let driver_handle = tokio::spawn(async move {
        let mut driver = client_session.driver;
        driver.wait_idle().await;
    });

    for i in 0u8..10 {
        let mut packet = vec![0x45u8; 20];
        packet[1] = i;
        client_session.session.send_ip_packet(&packet).unwrap();

        let echoed = client_session.session.recv_ip_packet().await.unwrap();
        assert_eq!(echoed.as_ref(), packet.as_slice());
    }

    let _ = done_tx.send(());
    proxy_handle.await.unwrap();
    drop(client_session.session);
    driver_handle.abort();
}

/// Verify that a non-CONNECT-IP request gets 400 and the proxy continues
/// to accept the next valid CONNECT-IP request.
#[tokio::test]
async fn non_connect_ip_request_rejected_with_400() {
    let (certs, key) = helpers::generate_test_certs();
    let (server_endpoint, server_addr) = helpers::make_server_endpoint(certs.clone(), key);
    let client_endpoint = helpers::make_client_endpoint(&certs);

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawn proxy — it loops rejecting bad requests until a valid CONNECT-IP arrives
    let proxy_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let quic_conn = incoming.await.unwrap();
        let h3_conn = h3_quinn::Connection::new(quic_conn);

        let mut conn = h3::server::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(h3_conn)
            .await
            .unwrap();

        // This will reject the GET, then accept the CONNECT-IP
        let request = ConnectIpProxy::accept(&mut conn).await.unwrap().unwrap();
        let _session = request.accept(&conn, None).await.unwrap();

        // Just hold the session alive — no packet exchange needed for this test
        let _ = done_rx.await;
    });

    // Client side: build h3 connection manually
    let quic_conn = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    let h3_conn = h3_quinn::Connection::new(quic_conn);
    let (h3_client_conn, mut send_request) = h3::client::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build::<_, _, bytes::Bytes>(h3_conn)
        .await
        .unwrap();

    // Drive h3 in background
    let driver_handle = tokio::spawn(async move {
        let mut driver = h3_client_conn;
        driver.wait_idle().await;
    });

    // Step 1: Send a plain GET request (not CONNECT-IP) — proxy should reject with 400
    let get_req = Request::get("https://localhost/hello").body(()).unwrap();
    let mut get_stream = send_request.send_request(get_req).await.unwrap();
    get_stream.finish().await.unwrap();
    let get_resp = get_stream.recv_response().await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::BAD_REQUEST);

    // Step 2: Send valid CONNECT-IP — proxy should accept with 200
    let uri = "https://localhost/.well-known/masque/ip/*/*/";
    let connect_req = Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri)
        .extension(h3::ext::Protocol::CONNECT_IP)
        .body(())
        .unwrap();
    let mut connect_stream = send_request.send_request(connect_req).await.unwrap();
    let connect_resp = connect_stream.recv_response().await.unwrap();
    assert_eq!(connect_resp.status(), StatusCode::OK);

    let _ = done_tx.send(());
    proxy_handle.await.unwrap();
    driver_handle.abort();
}

/// Test concurrent capsule + datagram I/O using session.into_parts().
/// The proxy sends a ROUTE_ADVERTISEMENT capsule AND IP packets simultaneously.
/// The client receives both using tokio::select! on independent handles.
#[tokio::test]
async fn concurrent_capsule_and_datagram_io() {
    use connect_ip::capsule::route::{IpAddressRange, RouteAdvertisement};
    use connect_ip::session::Capsule;
    use connect_ip::types::IpVersion;
    use std::net::{IpAddr, Ipv4Addr};

    let (certs, key) = helpers::generate_test_certs();
    let (server_endpoint, server_addr) = helpers::make_server_endpoint(certs.clone(), key);
    let client_endpoint = helpers::make_client_endpoint(&certs);

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let proxy_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let quic_conn = incoming.await.unwrap();
        let h3_conn = h3_quinn::Connection::new(quic_conn);

        let mut conn = h3::server::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(h3_conn)
            .await
            .unwrap();

        let request = ConnectIpProxy::accept(&mut conn).await.unwrap().unwrap();
        let session = request.accept(&conn, None).await.unwrap();

        // Split into parts for concurrent I/O
        let mut parts = session.into_parts();

        // Send a route advertisement capsule
        let routes = RouteAdvertisement {
            ranges: vec![IpAddressRange {
                ip_version: IpVersion::V4,
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)),
                ip_protocol: 0,
            }],
        };
        parts.capsule_send.send_route_advertisement(&routes).await.unwrap();

        // Also send an IP packet
        let packet = vec![0x45u8; 20];
        parts.datagram_send.send_ip_packet(&packet).unwrap();

        let _ = done_rx.await;
    });

    let quic_conn = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    let h3_conn = h3_quinn::Connection::new(quic_conn);
    let mut client_session =
        ConnectIpClient::connect(h3_conn, "*", "*", None).await.unwrap();

    let driver_handle = tokio::spawn(async move {
        let mut driver = client_session.driver;
        driver.wait_idle().await;
    });

    // Split the client session for concurrent recv
    let mut parts = client_session.session.into_parts();

    // Use tokio::select! to receive both capsule and datagram concurrently
    let mut got_capsule = false;
    let mut got_packet = false;

    // We need to receive both — order is non-deterministic
    for _ in 0..2 {
        tokio::select! {
            result = parts.datagram_recv.recv_ip_packet() => {
                let packet = result.unwrap();
                assert_eq!(packet.len(), 20);
                assert_eq!(packet[0], 0x45);
                got_packet = true;
            }
            result = parts.capsule_recv.recv_capsule() => {
                let capsule = result.unwrap().unwrap();
                match capsule {
                    Capsule::RouteAdvertisement(routes) => {
                        assert_eq!(routes.ranges.len(), 1);
                        got_capsule = true;
                    }
                    other => panic!("unexpected capsule: {:?}", other),
                }
            }
        }
    }

    assert!(got_capsule, "should have received route advertisement");
    assert!(got_packet, "should have received IP packet");

    let _ = done_tx.send(());
    proxy_handle.await.unwrap();
    driver_handle.abort();
}
