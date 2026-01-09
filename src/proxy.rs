//! Proxy support for client connections.
#[cfg(feature = "proxy")]
use std::{fmt, net::IpAddr};

#[cfg(feature = "__rustls-tls")]
use std::convert::TryFrom;

use tokio::{
    io::{self, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
};

use base64::Engine;
use url::Url;

use tungstenite::{
    error::{Error, UrlError},
    http,
};

use crate::{domain, tls::Connector, WebSocketStream};

/// A boxed stream used by proxy-enabled connectors.
pub type BoxedStream = Box<dyn AsyncReadWriteSendUnpin>;

/// Convenience alias for the WebSocket stream returned by proxy-aware connect helpers.
pub type ProxiedStream = WebSocketStream<crate::stream::MaybeTlsStream<BoxedStream>>;

/// Proxy configuration represented by a URL, e.g.:
/// - http://user:pass@proxy:8080
/// - https://user:pass@proxy:8443
/// - socks4://proxy:1080
/// - socks4a://user@proxy:1080
/// - socks5://user:pass@proxy:1080
/// - socks5h://user:pass@proxy:1080
#[derive(Clone, Debug)]
pub struct Proxy {
    /// Proxy URL with embedded credentials (scheme, host, port, user, password).
    pub url: Url,
    /// Optional TLS connector for HTTPS proxies.
    pub tls_connector: Option<Connector>,
}

impl Proxy {
    /// Create a new proxy from a URL.
    pub fn new(url: Url) -> Self {
        Self { url, tls_connector: None }
    }
    /// Set the TLS connector for HTTPS proxies.
    pub fn with_tls(mut self, connector: Connector) -> Self {
        self.tls_connector = Some(connector);
        self
    }
}

/// Trait alias to simplify boxing of async streams.
pub trait AsyncReadWriteSendUnpin: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWriteSendUnpin for T {}

/// Open a TCP tunnel to the websocket target using the given proxy configuration.
pub async fn open_tunnel(
    request: &http::Request<()>,
    proxy: Proxy,
    disable_nagle: bool,
) -> Result<BoxedStream, Error> {
    let host = domain(request)?;
    let port = request
        .uri()
        .port_u16()
        .or_else(|| match request.uri().scheme_str() {
            Some("wss") => Some(443),
            Some("ws") => Some(80),
            _ => None,
        })
        .ok_or(Error::Url(UrlError::UnsupportedUrlScheme))?;

    let scheme = proxy.url.scheme();
    let proxy_host = proxy.url.host_str().ok_or(Error::Url(UrlError::NoHostName))?;
    let proxy_port = proxy.url.port_or_known_default().unwrap_or(1080);

    match scheme {
        "http" => {
            let socket = TcpStream::connect(format!("{proxy_host}:{proxy_port}"))
                .await
                .map_err(Error::Io)?;
            if disable_nagle {
                socket.set_nodelay(true)?;
            }
            let auth = proxy_auth_from_url(&proxy.url);
            let stream = perform_http_connect(socket, &host, port, auth.as_ref()).await?;
            Ok(Box::new(stream))
        }
        "https" => {
            let tcp = TcpStream::connect(format!("{proxy_host}:{proxy_port}"))
                .await
                .map_err(Error::Io)?;
            if disable_nagle {
                tcp.set_nodelay(true)?;
            }
            let tls =
                wrap_tls_to_proxy(tcp, proxy_host.to_string(), proxy.tls_connector.clone()).await?;
            let auth = proxy_auth_from_url(&proxy.url);
            let stream = perform_http_connect(tls, &host, port, auth.as_ref()).await?;
            Ok(Box::new(stream))
        }
        "socks4" => {
            let tcp = TcpStream::connect(format!("{proxy_host}:{proxy_port}"))
                .await
                .map_err(Error::Io)?;
            if disable_nagle {
                tcp.set_nodelay(true)?;
            }
            let user = user_from_url(&proxy.url);
            let stream = socks4_connect(tcp, &host, port, user.as_deref(), false).await?;
            Ok(Box::new(stream))
        }
        "socks4a" => {
            let tcp = TcpStream::connect(format!("{proxy_host}:{proxy_port}"))
                .await
                .map_err(Error::Io)?;
            if disable_nagle {
                tcp.set_nodelay(true)?;
            }
            let user = user_from_url(&proxy.url);
            let stream = socks4_connect(tcp, &host, port, user.as_deref(), true).await?;
            Ok(Box::new(stream))
        }
        "socks5" => {
            let tcp = TcpStream::connect(format!("{proxy_host}:{proxy_port}"))
                .await
                .map_err(Error::Io)?;
            if disable_nagle {
                tcp.set_nodelay(true)?;
            }
            let auth = proxy_auth_from_url(&proxy.url);
            let stream = socks5_connect(tcp, &host, port, auth.as_ref(), false).await?;
            Ok(Box::new(stream))
        }
        "socks5h" => {
            let tcp = TcpStream::connect(format!("{proxy_host}:{proxy_port}"))
                .await
                .map_err(Error::Io)?;
            if disable_nagle {
                tcp.set_nodelay(true)?;
            }
            let auth = proxy_auth_from_url(&proxy.url);
            let stream = socks5_connect(tcp, &host, port, auth.as_ref(), true).await?;
            Ok(Box::new(stream))
        }
        _ => Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported proxy scheme: {scheme}"),
        ))),
    }
}

fn proxy_auth_from_url(url: &Url) -> Option<ProxyAuth> {
    let user = url.username();
    if user.is_empty() {
        return None;
    }
    let pass = url.password().unwrap_or("");
    Some(ProxyAuth { username: user.to_string(), password: pass.to_string() })
}

fn user_from_url(url: &Url) -> Option<String> {
    let user = url.username();
    if user.is_empty() {
        None
    } else {
        Some(user.to_string())
    }
}

async fn perform_http_connect<S>(
    mut stream: S,
    host: &str,
    port: u16,
    auth: Option<&ProxyAuth>,
) -> Result<S, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(auth) = auth {
        let token = format!("{}:{}", auth.username, auth.password);
        let encoded = base64::engine::general_purpose::STANDARD.encode(token);
        request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    request.push_str("Connection: keep-alive\r\n\r\n");

    stream.write_all(request.as_bytes()).await.map_err(Error::Io)?;
    stream.flush().await.map_err(Error::Io)?;

    let mut reader = BufReader::new(&mut stream);
    let mut buf = Vec::with_capacity(256);
    loop {
        let n = reader.read_until(b'\n', &mut buf).await.map_err(Error::Io)?;
        if n == 0 {
            return Err(Error::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "proxy closed")));
        }
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8 * 1024 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy response too large",
            )));
        }
    }

    let status_line = buf
        .split(|b| *b == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .unwrap_or("")
        .trim();

    if !status_line.contains(" 200") {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("proxy CONNECT failed: {status_line}"),
        )));
    }

    // Drop the BufReader to return the underlying stream.
    drop(reader);
    Ok(stream)
}

#[cfg(any(feature = "native-tls", feature = "__rustls-tls"))]
async fn wrap_tls_to_proxy(
    tcp: TcpStream,
    domain: String,
    connector: Option<Connector>,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send, Error> {
    match connector {
        #[cfg(feature = "native-tls")]
        Some(Connector::NativeTls(conn)) => {
            let tls = tokio_native_tls::TlsConnector::from(conn)
                .connect(&domain, tcp)
                .await
                .map_err(|e| Error::Tls(e.into()))?;
            Ok(tls)
        }
        #[cfg(feature = "__rustls-tls")]
        Some(Connector::Rustls(config)) => {
            let name = rustls_pki_types::ServerName::try_from(domain.as_str())
                .map_err(|_| Error::Url(UrlError::NoHostName))?
                .to_owned();
            let tls = tokio_rustls::TlsConnector::from(config)
                .connect(name, tcp)
                .await
                .map_err(Error::Io)?;
            Ok(tls)
        }
        Some(Connector::Plain) => Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "plain connector not valid for HTTPS proxy",
        ))),
        None => {
            #[cfg(feature = "native-tls")]
            {
                let connector =
                    native_tls_crate::TlsConnector::new().map_err(|e| Error::Tls(e.into()))?;
                let tls = tokio_native_tls::TlsConnector::from(connector)
                    .connect(&domain, tcp)
                    .await
                    .map_err(|e| Error::Tls(e.into()))?;
                Ok(tls)
            }
            #[cfg(all(feature = "__rustls-tls", not(feature = "native-tls")))]
            {
                use rustls::{ClientConfig, RootCertStore};
                let mut roots = RootCertStore::empty();
                #[cfg(feature = "rustls-tls-webpki-roots")]
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let config = std::sync::Arc::new(
                    ClientConfig::builder().with_root_certificates(roots).with_no_client_auth(),
                );
                let name = rustls_pki_types::ServerName::try_from(domain.as_str())
                    .map_err(|_| Error::Url(UrlError::NoHostName))?
                    .to_owned();
                let tls = tokio_rustls::TlsConnector::from(config)
                    .connect(name, tcp)
                    .await
                    .map_err(Error::Io)?;
                Ok(tls)
            }
            #[cfg(not(any(feature = "native-tls", feature = "__rustls-tls")))]
            {
                let _ = domain;
                Err(Error::Url(UrlError::TlsFeatureNotEnabled))
            }
        }
    }
}

#[cfg(not(any(feature = "native-tls", feature = "__rustls-tls")))]
async fn wrap_tls_to_proxy(
    _tcp: TcpStream,
    _domain: String,
    _connector: Option<Connector>,
) -> Result<TcpStream, Error> {
    Err(Error::Url(UrlError::TlsFeatureNotEnabled))
}

async fn socks4_connect(
    mut stream: TcpStream,
    host: &str,
    port: u16,
    user: Option<&str>,
    remote_dns: bool,
) -> Result<TcpStream, Error> {
    let mut buf = Vec::with_capacity(512);
    buf.push(0x04); // VN
    buf.push(0x01); // CONNECT
    buf.extend_from_slice(&port.to_be_bytes());

    if remote_dns {
        buf.extend_from_slice(&[0, 0, 0, 1]);
    } else if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
            IpAddr::V6(_) => {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IPv6 not supported in SOCKS4",
                )))
            }
        }
    } else {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hostname DNS resolution required for SOCKS4",
        )));
    }

    if let Some(user) = user {
        buf.extend_from_slice(user.as_bytes());
    }
    buf.push(0x00); // NUL terminator for userid

    if remote_dns {
        if host.len() > 255 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hostname too long for socks4a",
            )));
        }
        buf.extend_from_slice(host.as_bytes());
        buf.push(0x00);
    }

    stream.write_all(&buf).await.map_err(Error::Io)?;
    stream.flush().await.map_err(Error::Io)?;

    let mut resp = [0u8; 8];
    stream.read_exact(&mut resp).await.map_err(Error::Io)?;
    if resp[1] != 0x5A {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "socks4 connect failed",
        )));
    }

    Ok(stream)
}

async fn socks5_connect(
    mut stream: TcpStream,
    host: &str,
    port: u16,
    auth: Option<&ProxyAuth>,
    remote_dns: bool,
) -> Result<TcpStream, Error> {
    // Greeting
    let mut greet = Vec::with_capacity(4);
    greet.push(0x05);
    match auth {
        Some(_) => greet.extend_from_slice(&[0x02, 0x00, 0x02]), // methods: no auth, username/password
        None => greet.extend_from_slice(&[0x01, 0x00]),          // methods: no auth
    }
    stream.write_all(&greet).await.map_err(Error::Io)?;
    stream.flush().await.map_err(Error::Io)?;

    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp).await.map_err(Error::Io)?;
    if method_resp[0] != 0x05 {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid socks5 version",
        )));
    }
    match method_resp[1] {
        0x00 => {}
        0x02 => {
            if let Some(auth) = auth {
                socks5_auth(&mut stream, auth).await?;
            } else {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "proxy requires auth",
                )));
            }
        }
        0xFF => {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                "no acceptable socks5 auth method",
            )));
        }
        _ => {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                "unsupported socks5 auth method",
            )));
        }
    }

    let mut req = Vec::with_capacity(6 + host.len());
    req.push(0x05); // version
    req.push(0x01); // CONNECT
    req.push(0x00); // RSV

    let push_domain = |req: &mut Vec<u8>, host: &str| -> Result<(), Error> {
        if host.len() > 255 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hostname too long for socks5",
            )));
        }
        req.push(0x03);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
        Ok(())
    };

    if !remote_dns {
        if let Ok(ip) = host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    req.push(0x01);
                    req.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    req.push(0x04);
                    req.extend_from_slice(&v6.octets());
                }
            }
        } else {
            push_domain(&mut req, host)?;
        }
    } else {
        push_domain(&mut req, host)?;
    }

    req.extend_from_slice(&port.to_be_bytes());

    stream.write_all(&req).await.map_err(Error::Io)?;
    stream.flush().await.map_err(Error::Io)?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.map_err(Error::Io)?;
    if header[1] != 0x00 {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("socks5 connect failed code {}", header[1]),
        )));
    }

    let atyp = header[3];
    match atyp {
        0x01 => {
            let mut skip = [0u8; 4];
            stream.read_exact(&mut skip).await.map_err(Error::Io)?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(Error::Io)?;
            let mut skip = vec![0u8; len[0] as usize];
            stream.read_exact(&mut skip).await.map_err(Error::Io)?;
        }
        0x04 => {
            let mut skip = [0u8; 16];
            stream.read_exact(&mut skip).await.map_err(Error::Io)?;
        }
        _ => {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid socks5 atyp",
            )));
        }
    }
    let mut skip_port = [0u8; 2];
    stream.read_exact(&mut skip_port).await.map_err(Error::Io)?;

    Ok(stream)
}

async fn socks5_auth(stream: &mut TcpStream, auth: &ProxyAuth) -> Result<(), Error> {
    let user = auth.username.as_bytes();
    let pass = auth.password.as_bytes();

    if user.len() > 255 || pass.len() > 255 {
        return Err(Error::Io(io::Error::new(io::ErrorKind::InvalidInput, "credentials too long")));
    }

    let mut msg = Vec::with_capacity(3 + user.len() + pass.len());
    msg.push(0x01); // subnegotiation version
    msg.push(user.len() as u8);
    msg.extend_from_slice(user);
    msg.push(pass.len() as u8);
    msg.extend_from_slice(pass);

    stream.write_all(&msg).await.map_err(Error::Io)?;
    stream.flush().await.map_err(Error::Io)?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.map_err(Error::Io)?;
    if resp[1] != 0x00 {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks5 auth failed",
        )));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct ProxyAuth {
    username: String,
    password: String,
}

impl fmt::Display for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}
