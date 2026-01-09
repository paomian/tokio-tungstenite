//! Example showing how to connect through a proxy.
//!
//! Run with:
//! cargo run --example client-proxy --features proxy,rustls-tls-webpki-roots

use tokio_tungstenite::{connect_async_with_proxy, Proxy};
use url::Url;

#[tokio::main]
async fn main() {
    env_logger::init();

    // Example: HTTP proxy with basic auth
    let proxy_url = Url::parse("http://user:pass@localhost:8080").unwrap();
    let proxy = Proxy::new(proxy_url);

    // WebSocket URL
    let ws_url = "wss://echo.websocket.org";

    println!("Connecting to {} via proxy...", ws_url);
    match connect_async_with_proxy(ws_url, proxy).await {
        Ok((ws_stream, response)) => {
            println!("WebSocket handshake completed.");
            println!("Response status: {:?}", response.status());
            println!("Response headers: {:#?}", response.headers());
            drop(ws_stream);
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }

    // Example: SOCKS5h proxy (remote DNS)
    let socks5h_url = Url::parse("socks5h://user:pass@localhost:1080").unwrap();
    let socks_proxy = Proxy::new(socks5h_url);

    println!("\nConnecting to {} via SOCKS5h proxy...", ws_url);
    match connect_async_with_proxy(ws_url, socks_proxy).await {
        Ok((ws_stream, response)) => {
            println!("WebSocket handshake completed.");
            println!("Response status: {:?}", response.status());
            drop(ws_stream);
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }
}
