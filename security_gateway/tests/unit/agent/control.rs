use super::*;

fn tcp() -> FiveTuple {
    FiveTuple::new(Protocol::Tcp, "10.0.1.2:40000".parse().unwrap(), "10.0.2.2:5001".parse().unwrap()).unwrap()
}

#[test]
fn requests_are_one_json_object_each() {
    let request = Request::Trust {
        connection: Tuple::of(&tcp()),
    };
    assert_eq!(
        serde_json::to_string(&request).unwrap(),
        r#"{"request":"trust","connection":{"protocol":"tcp","src":"10.0.1.2:40000","dst":"10.0.2.2:5001"}}"#
    );
    assert_eq!(serde_json::to_string(&Request::List).unwrap(), r#"{"request":"list"}"#);
    assert_eq!(Tuple::of(&tcp()).five_tuple(), Ok(tcp()));
}

#[test]
fn tuples_from_a_request_are_checked() {
    let mixed = Tuple {
        protocol: "udp".into(),
        src: "10.0.1.2:1".parse().unwrap(),
        dst: "[2001:db8::1]:2".parse().unwrap(),
    };
    assert!(mixed.five_tuple().is_err());
    let bad = Tuple {
        protocol: "sctp".into(),
        ..Tuple::of(&tcp())
    };
    assert!(bad.five_tuple().is_err());
}

#[test]
fn a_missing_socket_means_run_is_not_running() {
    let path = std::env::temp_dir().join(format!("wnc-gw-test-missing-{}.sock", std::process::id()));
    let e = request(&path, &Request::List).unwrap_err();
    assert_eq!(e.to_string(), format!("wnc-gw run is not running (cannot connect to {})", path.display()));
}

#[test]
fn a_request_gets_its_reply() {
    let path = std::env::temp_dir().join(format!("wnc-gw-test-{}.sock", std::process::id()));
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let server = runtime.block_on(async { ControlServer::bind(&path) }).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    let client_path = path.clone();
    let client = std::thread::spawn(move || request(&client_path, &Request::List));
    runtime.block_on(async {
        let mut incoming = server.accept().await.unwrap();
        assert!(incoming.allowed, "the same account is allowed");
        assert_eq!(incoming.read().await.unwrap(), Request::List);
        incoming.reply(&Response::Trusted { flows: Vec::new() }).await;
    });
    assert_eq!(client.join().unwrap().unwrap(), Response::Trusted { flows: Vec::new() });
    drop(server);
    assert!(!path.exists(), "the socket is removed when run stops");
}

#[test]
fn a_long_list_is_read_in_full() {
    let path = std::env::temp_dir().join(format!("wnc-gw-test-long-{}.sock", std::process::id()));
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let server = runtime.block_on(async { ControlServer::bind(&path) }).unwrap();
    let flows: Vec<Flow> = (0..2000)
        .map(|port| Flow {
            connection: Tuple {
                protocol: "udp".into(),
                src: format!("192.168.1.195:{}", 10000 + port).parse().unwrap(),
                dst: "68.206.48.206:80".parse().unwrap(),
            },
            packets_original: 1,
            bytes_original: 60,
            packets_reply: 0,
            bytes_reply: 0,
            next_hop_original: Some("10.99.2.2".parse().unwrap()),
            next_hop_reply: None,
        })
        .collect();
    let reply = Response::Trusted { flows };
    assert!(serde_json::to_string(&reply).unwrap().len() as u64 > MAX_MESSAGE, "longer than a request may be");
    let client_path = path.clone();
    let client = std::thread::spawn(move || request(&client_path, &Request::List));
    runtime.block_on(async {
        let mut incoming = server.accept().await.unwrap();
        incoming.read().await.unwrap();
        incoming.reply(&reply).await;
    });
    assert_eq!(client.join().unwrap().unwrap(), reply);
}
