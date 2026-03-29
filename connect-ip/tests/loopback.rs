mod helpers;

use connect_ip::client::ConnectIpClient;
use connect_ip::proxy::ConnectIpProxy;

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

        let mut session = request.accept(&conn).await.unwrap();

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
        ConnectIpClient::connect(h3_conn, "*", "*").await.unwrap();

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
        let mut session = request.accept(&conn).await.unwrap();

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
    let mut client_session = ConnectIpClient::connect(h3_conn, "*", "*").await.unwrap();

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
