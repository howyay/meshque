//! Integration tests for address negotiation and route exchange over loopback.

mod helpers;

use std::net::{IpAddr, Ipv4Addr};

use connect_ip::capsule::address::{AddressAssign, AddressRequest, AssignedAddress, RequestedAddress};
use connect_ip::capsule::route::{IpAddressRange, RouteAdvertisement};
use connect_ip::client::ConnectIpClient;
use connect_ip::proxy::ConnectIpProxy;
use connect_ip::session::Capsule;
use connect_ip::types::IpVersion;

#[tokio::test]
async fn proxy_assigns_address_to_client() {
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

        // Proxy sends ADDRESS_ASSIGN to client (unsolicited)
        let assign = AddressAssign {
            addresses: vec![AssignedAddress {
                request_id: 0, // unsolicited
                ip_version: IpVersion::V4,
                address: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
                prefix_length: 32,
            }],
        };
        session.send_address_assign(&assign).await.unwrap();

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

    // Client receives ADDRESS_ASSIGN capsule
    let capsule = client_session.session.recv_capsule().await.unwrap().unwrap();
    match capsule {
        Capsule::AddressAssign(assign) => {
            assert_eq!(assign.addresses.len(), 1);
            assert_eq!(assign.addresses[0].request_id, 0);
            assert_eq!(
                assign.addresses[0].address,
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
            );
            assert_eq!(assign.addresses[0].prefix_length, 32);
        }
        other => panic!("expected AddressAssign, got {:?}", other),
    }

    let _ = done_tx.send(());
    proxy_handle.await.unwrap();
    drop(client_session.session);
    driver_handle.abort();
}

#[tokio::test]
async fn client_requests_address_from_proxy() {
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

        // Proxy receives ADDRESS_REQUEST from client
        let capsule = session.recv_capsule().await.unwrap().unwrap();
        match capsule {
            Capsule::AddressRequest(req) => {
                assert_eq!(req.addresses.len(), 1);
                assert_eq!(req.addresses[0].request_id, 1);

                // Respond with ADDRESS_ASSIGN
                let assign = AddressAssign {
                    addresses: vec![AssignedAddress {
                        request_id: 1, // matches the request
                        ip_version: IpVersion::V4,
                        address: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 42)),
                        prefix_length: 32,
                    }],
                };
                session.send_address_assign(&assign).await.unwrap();
            }
            other => panic!("expected AddressRequest, got {:?}", other),
        }

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

    // Client sends ADDRESS_REQUEST
    let request = AddressRequest {
        addresses: vec![RequestedAddress {
            request_id: 1,
            ip_version: IpVersion::V4,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED), // "assign any"
            prefix_length: 32,
        }],
    };
    client_session
        .session
        .send_address_request(&request)
        .await
        .unwrap();

    // Client receives ADDRESS_ASSIGN response
    let capsule = client_session.session.recv_capsule().await.unwrap().unwrap();
    match capsule {
        Capsule::AddressAssign(assign) => {
            assert_eq!(assign.addresses.len(), 1);
            assert_eq!(assign.addresses[0].request_id, 1);
            assert_eq!(
                assign.addresses[0].address,
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, 42))
            );
        }
        other => panic!("expected AddressAssign, got {:?}", other),
    }

    let _ = done_tx.send(());
    proxy_handle.await.unwrap();
    drop(client_session.session);
    driver_handle.abort();
}

#[tokio::test]
async fn proxy_advertises_routes_to_client() {
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

        // Proxy sends ROUTE_ADVERTISEMENT
        let routes = RouteAdvertisement {
            ranges: vec![
                IpAddressRange {
                    ip_version: IpVersion::V4,
                    start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)),
                    ip_protocol: 0,
                },
            ],
        };
        session.send_route_advertisement(&routes).await.unwrap();

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

    // Client receives ROUTE_ADVERTISEMENT
    let capsule = client_session.session.recv_capsule().await.unwrap().unwrap();
    match capsule {
        Capsule::RouteAdvertisement(routes) => {
            assert_eq!(routes.ranges.len(), 1);
            assert_eq!(
                routes.ranges[0].start,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))
            );
            assert_eq!(
                routes.ranges[0].end,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255))
            );
        }
        other => panic!("expected RouteAdvertisement, got {:?}", other),
    }

    let _ = done_tx.send(());
    proxy_handle.await.unwrap();
    drop(client_session.session);
    driver_handle.abort();
}

#[tokio::test]
async fn unknown_capsule_type_is_skipped() {
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

        // Send an unknown capsule type (0xFF)
        session
            .send_raw_capsule(&connect_ip::capsule::codec::RawCapsule {
                capsule_type: 0xFF,
                payload: bytes::Bytes::from_static(b"mystery"),
            })
            .await
            .unwrap();

        // Then send a known capsule (ADDRESS_ASSIGN)
        let assign = AddressAssign {
            addresses: vec![AssignedAddress {
                request_id: 0,
                ip_version: IpVersion::V4,
                address: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
                prefix_length: 32,
            }],
        };
        session.send_address_assign(&assign).await.unwrap();

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

    // Client should skip the unknown capsule and receive the ADDRESS_ASSIGN
    let capsule = client_session.session.recv_capsule().await.unwrap().unwrap();
    match capsule {
        Capsule::AddressAssign(assign) => {
            assert_eq!(assign.addresses.len(), 1);
            assert_eq!(
                assign.addresses[0].address,
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
            );
        }
        other => panic!(
            "expected AddressAssign (unknown should be skipped), got {:?}",
            other
        ),
    }

    let _ = done_tx.send(());
    proxy_handle.await.unwrap();
    drop(client_session.session);
    driver_handle.abort();
}
