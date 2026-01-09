#![cfg(feature = "proxy")]

use std::time::Duration;

use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::TcpListener,
	task,
	time,
};
use tokio_tungstenite::{open_tunnel, Proxy};
use tungstenite::http;

fn tunnel_request(uri: &str) -> http::Request<()> {
	http::Request::builder().uri(uri).body(()).unwrap()
}

async fn read_until_double_crlf(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
	let mut buf = Vec::new();
	while !buf.ends_with(b"\r\n\r\n") {
		let mut byte = [0u8; 1];
		let n = socket.read(&mut byte).await.unwrap();
		if n == 0 {
			break;
		}
		buf.extend_from_slice(&byte[..n]);
	}
	buf
}

#[tokio::test]
async fn http_connect_without_auth() {
	let _ = env_logger::try_init();

	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let proxy_addr = listener.local_addr().unwrap();

	let server = task::spawn(async move {
		let (mut socket, _) = listener.accept().await.unwrap();
		let received = read_until_double_crlf(&mut socket).await;
		let request_text = String::from_utf8_lossy(&received);
		assert!(request_text.starts_with("CONNECT ws.example.org:443 HTTP/1.1"));
		assert!(request_text.contains("Host: ws.example.org:443"));
		assert!(!request_text.contains("Proxy-Authorization"));

		socket
			.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
			.await
			.unwrap();

		let mut buf = [0u8; 4];
		socket.read_exact(&mut buf).await.unwrap();
		assert_eq!(&buf, b"ping");
		socket.write_all(b"pong").await.unwrap();
	});

	let proxy = Proxy::new(format!("http://{}", proxy_addr).parse().unwrap());
	let mut stream = open_tunnel(&tunnel_request("wss://ws.example.org/socket"), proxy, false)
		.await
		.unwrap();

	stream.write_all(b"ping").await.unwrap();
	let mut buf = [0u8; 4];
	stream.read_exact(&mut buf).await.unwrap();
	assert_eq!(&buf, b"pong");

	server.await.unwrap();
}

#[tokio::test]
async fn http_connect_with_basic_auth() {
	let _ = env_logger::try_init();

	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let proxy_addr = listener.local_addr().unwrap();

	let server = task::spawn(async move {
		let (mut socket, _) = listener.accept().await.unwrap();
		let received = read_until_double_crlf(&mut socket).await;
		let request_text = String::from_utf8_lossy(&received);
		assert!(request_text.contains("Proxy-Authorization: Basic dXNlcjpzZWNyZXQ="));
		socket
			.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
			.await
			.unwrap();
	});

	let proxy = Proxy::new(format!("http://user:secret@{}", proxy_addr).parse().unwrap());
	open_tunnel(&tunnel_request("ws://ws.example.org/"), proxy, false).await.unwrap();

	server.await.unwrap();
}

#[tokio::test]
async fn socks5h_with_auth_and_domain_resolution() {
	let _ = env_logger::try_init();

	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let proxy_addr = listener.local_addr().unwrap();

	let server = task::spawn(async move {
		let (mut socket, _) = listener.accept().await.unwrap();

		let mut greet = [0u8; 4];
		socket.read_exact(&mut greet).await.unwrap();
		assert_eq!(&greet, &[0x05, 0x02, 0x00, 0x02]);
		socket.write_all(&[0x05, 0x02]).await.unwrap();

		let mut auth_header = [0u8; 2];
		socket.read_exact(&mut auth_header).await.unwrap();
		assert_eq!(auth_header[0], 0x01);
		let ulen = auth_header[1] as usize;
		let mut user = vec![0u8; ulen + 1];
		socket.read_exact(&mut user).await.unwrap();
		let plen = user[ulen] as usize;
		let username = &user[..ulen];
		let mut pass = vec![0u8; plen];
		socket.read_exact(&mut pass).await.unwrap();
		assert_eq!(username, b"user");
		assert_eq!(pass, b"pass");
		socket.write_all(&[0x01, 0x00]).await.unwrap();

		let mut req_header = [0u8; 4];
		socket.read_exact(&mut req_header).await.unwrap();
		assert_eq!(&req_header[..3], &[0x05, 0x01, 0x00]);
		assert_eq!(req_header[3], 0x03);
		let mut len_buf = [0u8; 1];
		socket.read_exact(&mut len_buf).await.unwrap();
		let domain_len = len_buf[0] as usize;
		let mut domain = vec![0u8; domain_len];
		socket.read_exact(&mut domain).await.unwrap();
		assert_eq!(domain, b"ws.example.org");
		let mut port_bytes = [0u8; 2];
		socket.read_exact(&mut port_bytes).await.unwrap();
		assert_eq!(u16::from_be_bytes(port_bytes), 443);

		socket
			.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x10, 0x00])
			.await
			.unwrap();

		let mut buf = [0u8; 4];
		socket.read_exact(&mut buf).await.unwrap();
		assert_eq!(&buf, b"ping");
		socket.write_all(b"pong").await.unwrap();
	});

	let proxy = Proxy::new(format!("socks5h://user:pass@{}", proxy_addr).parse().unwrap());
	let mut stream = open_tunnel(&tunnel_request("wss://ws.example.org/"), proxy, false)
		.await
		.unwrap();
	stream.write_all(b"ping").await.unwrap();
	let mut buf = [0u8; 4];
	stream.read_exact(&mut buf).await.unwrap();
	assert_eq!(&buf, b"pong");

	server.await.unwrap();
}

#[tokio::test]
async fn socks5_no_auth_ip_target() {
	let _ = env_logger::try_init();

	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let proxy_addr = listener.local_addr().unwrap();

	let server = task::spawn(async move {
		let (mut socket, _) = listener.accept().await.unwrap();

		let mut greet = [0u8; 3];
		socket.read_exact(&mut greet).await.unwrap();
		assert_eq!(&greet, &[0x05, 0x01, 0x00]);
		socket.write_all(&[0x05, 0x00]).await.unwrap();

		let mut req_header = [0u8; 4];
		socket.read_exact(&mut req_header).await.unwrap();
		assert_eq!(&req_header[..3], &[0x05, 0x01, 0x00]);
		assert_eq!(req_header[3], 0x01);
		let mut addr = [0u8; 4];
		socket.read_exact(&mut addr).await.unwrap();
		assert_eq!(addr, [127, 0, 0, 1]);
		let mut port_bytes = [0u8; 2];
		socket.read_exact(&mut port_bytes).await.unwrap();
		assert_eq!(u16::from_be_bytes(port_bytes), 9001);

		socket
			.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x23, 0x45])
			.await
			.unwrap();
	});

	let proxy = Proxy::new(format!("socks5://{}", proxy_addr).parse().unwrap());
	let request = http::Request::builder()
		.uri("ws://127.0.0.1:9001")
		.body(())
		.unwrap();

	let stream_fut = open_tunnel(&request, proxy, false);
	let result = time::timeout(Duration::from_secs(2), stream_fut).await;
	assert!(result.unwrap().is_ok());

	server.await.unwrap();
}
