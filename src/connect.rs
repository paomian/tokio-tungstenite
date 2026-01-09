//! Connection helper.
use tokio::net::TcpStream;

use tungstenite::{
    error::{Error, UrlError},
    handshake::client::{Request, Response},
    protocol::WebSocketConfig,
};

use crate::{domain, stream::MaybeTlsStream, Connector, IntoClientRequest, WebSocketStream};
#[cfg(feature = "proxy")]
use crate::{proxy::open_tunnel, proxy::Proxy, tls};
#[cfg(feature = "proxy")]
use crate::proxy::BoxedStream;

#[cfg(feature = "proxy")]
type ClientWsStream = WebSocketStream<MaybeTlsStream<BoxedStream>>;
#[cfg(not(feature = "proxy"))]
type ClientWsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[cfg(feature = "proxy")]
fn wrap_tcp(stream: TcpStream) -> BoxedStream {
    Box::new(stream)
}

#[cfg(not(feature = "proxy"))]
fn wrap_tcp(stream: TcpStream) -> TcpStream {
    stream
}

/// Connect to a given URL.
///
/// Accepts any request that implements [`IntoClientRequest`], which is often just `&str`, but can
/// be a variety of types such as `httparse::Request` or [`tungstenite::http::Request`] for more
/// complex uses.
///
/// ```no_run
/// # use tungstenite::client::IntoClientRequest;
///
/// # async fn test() {
/// use tungstenite::http::{Method, Request};
/// use tokio_tungstenite::connect_async;
///
/// let mut request = "wss://api.example.com".into_client_request().unwrap();
/// request.headers_mut().insert("api-key", "42".parse().unwrap());
///
/// let (stream, response) = connect_async(request).await.unwrap();
/// # }
/// ```
pub async fn connect_async<R>(request: R) -> Result<(ClientWsStream, Response), Error>
where
    R: IntoClientRequest + Unpin,
{
    connect_async_with_config(request, None, false).await
}

/// The same as `connect_async()` but the one can specify a websocket configuration.
/// Please refer to `connect_async()` for more details. `disable_nagle` specifies if
/// the Nagle's algorithm must be disabled, i.e. `set_nodelay(true)`. If you don't know
/// what the Nagle's algorithm is, better leave it set to `false`.
pub async fn connect_async_with_config<R>(
    request: R,
    config: Option<WebSocketConfig>,
    disable_nagle: bool,
) -> Result<(ClientWsStream, Response), Error>
where
    R: IntoClientRequest + Unpin,
{
    connect(request.into_client_request()?, config, disable_nagle, None).await
}

/// Connect to a given URL through a proxy.
#[cfg(feature = "proxy")]
pub async fn connect_async_with_proxy<R>(
    request: R,
    proxy: Proxy,
) -> Result<(ClientWsStream, Response), Error>
where
    R: IntoClientRequest + Unpin,
{
    connect_with_proxy(request.into_client_request()?, None, false, None, proxy).await
}

/// Same as `connect_async_with_proxy` but with websocket config, Nagle, TLS connector and proxy.
#[cfg(feature = "proxy")]
pub async fn connect_async_with_config_and_proxy<R>(
    request: R,
    config: Option<WebSocketConfig>,
    disable_nagle: bool,
    connector: Option<Connector>,
    proxy: Proxy,
) -> Result<(ClientWsStream, Response), Error>
where
    R: IntoClientRequest + Unpin,
{
    connect_with_proxy(request.into_client_request()?, config, disable_nagle, connector, proxy)
        .await
}

/// The same as `connect_async()` but the one can specify a websocket configuration,
/// and a TLS connector to use. Please refer to `connect_async()` for more details.
/// `disable_nagle` specifies if the Nagle's algorithm must be disabled, i.e.
/// `set_nodelay(true)`. If you don't know what the Nagle's algorithm is, better
/// leave it to `false`.
#[cfg(any(feature = "native-tls", feature = "__rustls-tls"))]
pub async fn connect_async_tls_with_config<R>(
    request: R,
    config: Option<WebSocketConfig>,
    disable_nagle: bool,
    connector: Option<Connector>,
) -> Result<(ClientWsStream, Response), Error>
where
    R: IntoClientRequest + Unpin,
{
    connect(request.into_client_request()?, config, disable_nagle, connector).await
}

async fn connect(
    request: Request,
    config: Option<WebSocketConfig>,
    disable_nagle: bool,
    connector: Option<Connector>,
) -> Result<(ClientWsStream, Response), Error> {
    let domain = domain(&request)?;
    let port = request
        .uri()
        .port_u16()
        .or_else(|| match request.uri().scheme_str() {
            Some("wss") => Some(443),
            Some("ws") => Some(80),
            _ => None,
        })
        .ok_or(Error::Url(UrlError::UnsupportedUrlScheme))?;

    let addr = format!("{domain}:{port}");
    let socket = TcpStream::connect(addr).await.map_err(Error::Io)?;

    if disable_nagle {
        socket.set_nodelay(true)?;
    }

    let stream = wrap_tcp(socket);

    crate::tls::client_async_tls_with_config(request, stream, config, connector).await
}

#[cfg(feature = "proxy")]
async fn connect_with_proxy(
    request: Request,
    config: Option<WebSocketConfig>,
    disable_nagle: bool,
    connector: Option<Connector>,
    proxy: Proxy,
) -> Result<(ClientWsStream, Response), Error> {
    let stream = open_tunnel(&request, proxy, disable_nagle).await?;
    tls::client_async_tls_with_config(request, stream, config, connector).await
}
