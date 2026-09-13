use inode_cli::{
    platform::{self, Executor, Platform, Routes},
    protocol::*,
};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn packet() -> Vec<u8> {
    let mut p = vec![0; 24];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&24u16.to_be_bytes());
    p[8] = 64;
    p[9] = 1;
    p
}

#[test]
fn framing_handles_every_split_and_coalesced_packets() {
    let p = packet();
    let wire = frame(&p).unwrap();
    for split in 0..=wire.len() {
        let mut d = Frames::default();
        let mut got = d.feed(&wire[..split]).unwrap();
        got.extend(d.feed(&wire[split..]).unwrap());
        assert_eq!(got, vec![p.clone()]);
    }
    let mut wire2 = wire.clone();
    wire2.extend_from_slice(&wire);
    wire2.extend_from_slice(&wire[..3]);
    let mut d = Frames::default();
    assert_eq!(d.feed(&wire2).unwrap(), vec![p.clone(), p.clone()]);
    assert_eq!(d.feed(&wire[3..]).unwrap(), vec![p]);
}

#[test]
fn framing_rejects_bad_type_length_and_ip_header() {
    let wire = frame(&packet()).unwrap();
    for i in [0, 1, 3, 4, 6] {
        let mut bad = wire.clone();
        bad[i] = 0xff;
        if i == 3 {
            bad[2] = 0;
            bad[3] = 1;
        }
        assert!(Frames::default().feed(&bad).is_err(), "index {i}");
    }
}

#[test]
fn login_form_roundtrips_xml_and_url_metacharacters() {
    let user = "a&<\"'中文";
    let pass = "&>< +\"'";
    let encoded = login_body(user, pass);
    let decoded: Vec<_> = url::form_urlencoded::parse(encoded.as_bytes()).collect();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].0, "request");
    let xml = roxmltree::Document::parse(&decoded[0].1).unwrap();
    assert_eq!(
        xml.descendants()
            .find(|n| n.has_tag_name("username"))
            .unwrap()
            .text(),
        Some(user)
    );
    assert_eq!(
        xml.descendants()
            .find(|n| n.has_tag_name("password"))
            .unwrap()
            .text(),
        Some("%26%3E%3C+%2B%22%27")
    );
    assert!(!login_succeeded("<data><result>NotSuccess</result></data>").unwrap());
}

#[test]
fn native_xml_captcha_uses_case_sensitive_vendor_field() {
    let form = login_body_with_captcha("test", "synthetic", Some("AB&4"));
    let decoded: Vec<_> = url::form_urlencoded::parse(form.as_bytes()).collect();
    let doc = roxmltree::Document::parse(&decoded[0].1).unwrap();
    assert_eq!(
        doc.descendants()
            .find(|n| n.has_tag_name("vldCode"))
            .unwrap()
            .text(),
        Some("AB&4")
    );
    assert!(!doc.descendants().any(|n| n.has_tag_name("vldcode")));
}

#[test]
fn future_lockout_warning_is_not_current_lockout() {
    let warning =
        "Authentication failed. If another 3 login attempts fail, your account will be locked.";
    assert_eq!(
        authentication_error(warning),
        "authentication failed; gateway warns that further failures may lock the account"
    );
    assert_eq!(
        authentication_error("Your account has been locked."),
        "account or source is locked"
    );
}

#[test]
fn client_metadata_is_serialized_as_separate_xml_elements() {
    let client = ClientInfo {
        os: "Linux",
        mac: "02:00:00:00:00:01".into(),
    };
    let form = login_body_with_client("synthetic", "test", Some("AB12"), Some(&client));
    let decoded: Vec<_> = url::form_urlencoded::parse(form.as_bytes()).collect();
    let doc = roxmltree::Document::parse(&decoded[0].1).unwrap();
    for (tag, value) in [
        ("OS", "Linux"),
        ("language", "EN"),
        ("macAddress", "02:00:00:00:00:01"),
    ] {
        assert_eq!(
            doc.descendants()
                .find(|n| n.has_tag_name(tag))
                .unwrap()
                .text(),
            Some(value)
        );
    }
}

#[test]
fn discovery_requires_explicit_domain_and_same_origin() {
    let base = gateway("https://vpn.example:443").unwrap();
    let xml = "<data><domainlist><domain><name>A</name><url>/a</url></domain><domain><name>B</name><url>https://evil.example/b</url></domain></domainlist></data>";
    assert!(domain_endpoint(&base, xml, None).is_err());
    assert_eq!(
        domain_endpoint(&base, xml, Some("A"))
            .unwrap()
            .unwrap()
            .path(),
        "/a"
    );
    assert!(domain_endpoint(&base, xml, Some("B")).is_err());
    for url in [
        "http://vpn.example/",
        "https://evil.example/",
        "https://u:p@vpn.example/",
        "https://vpn.example:444/",
    ] {
        assert!(endpoint(&base, url).is_err());
    }
    assert!(gateway("https://u:p@vpn.example").is_err());
}

#[test]
fn real_gateway_captcha_flag_is_detected() {
    let base = gateway("https://vpn.example").unwrap();
    let body = "<data><gatewayinfo><auth><supportPassword>true</supportPassword><supportvldimg>true</supportvldimg><supportCert>false</supportCert></auth><url><login>/login</login><challenge>/challenge</challenge></url></gatewayinfo></data>";
    assert!(gateway_info(&base, body).unwrap().extra_auth);
    assert!(
        !gateway_info(
            &base,
            &body.replace("<supportvldimg>true", "<supportvldimg>false")
        )
        .unwrap()
        .extra_auth
    );
    assert!(
        gateway_info(
            &base,
            "<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>"
        )
        .is_err()
    );
}

#[tokio::test]
async fn handshake_preserves_first_tunnel_packet() {
    let (mut server, mut client) = tokio::io::duplex(1024);
    let wire = frame(&packet()).unwrap();
    let expected = wire.clone();
    let task = tokio::spawn(async move {
        server
            .write_all(b"HTTP/1.1 200 OK\r\nIPADDRESS: 10.1.2.3\r\n\r\n")
            .await
            .unwrap();
        server.write_all(&wire).await.unwrap();
    });
    let (addr, mut pending) = read_handshake(&mut client).await.unwrap();
    assert_eq!(addr.to_string(), "10.1.2.3");
    client.read_to_end(&mut pending).await.unwrap();
    assert_eq!(pending, expected);
    task.await.unwrap();
}

#[test]
fn route_guard_rolls_back_only_successful_adds() {
    #[derive(Clone)]
    struct Fake {
        calls: Arc<Mutex<Vec<Vec<String>>>>,
    }
    impl Executor for Fake {
        fn execute(&mut self, args: &[String]) -> anyhow::Result<()> {
            self.calls.lock().unwrap().push(args.to_vec());
            if args.iter().any(|arg| arg.ends_with("10.2.0.0/16")) {
                anyhow::bail!("route already exists")
            }
            Ok(())
        }
    }
    for os in [Platform::Linux, Platform::Windows, Platform::Macos] {
        let fake = Fake {
            calls: Default::default(),
        };
        let calls = fake.calls.clone();
        let nets = [
            "10.1.0.0/16".parse().unwrap(),
            "10.2.0.0/16".parse().unwrap(),
        ];
        assert!(Routes::install(os, "test0", &nets, fake).is_err());
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls[2],
            platform::route_command(os, false, nets[0], "test0")
        );
    }
}

#[test]
fn routes_cannot_capture_gateway_or_default_route() {
    let ips = ["10.20.1.2".parse().unwrap()];
    assert!(platform::validate_routes(&["10.0.0.0/8".parse().unwrap()], &ips).is_err());
    assert!(platform::validate_routes(&["0.0.0.0/0".parse().unwrap()], &ips).is_err());
    assert!(platform::validate_routes(&["192.168.3.0/24".parse().unwrap()], &ips).is_ok());
}
