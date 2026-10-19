use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::auth::Auth;
use crate::copy;

const HOP_BY_HOP: &[&str] = &["proxy-authorization", "proxy-connection"];

fn resolve_connect(addr: &str, timeout: Duration) -> io::Result<TcpStream> {
    let mut last_err = io::Error::new(io::ErrorKind::NotFound, "no addresses");
    for sa in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&sa, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

pub fn handle_http(
    mut client: TcpStream,
    first_byte: u8,
    auth: Option<&Auth>,
    timeout: Duration,
) -> io::Result<()> {
    let mut header_buf: Vec<u8> = Vec::with_capacity(1024);
    header_buf.push(first_byte);

    let mut chunk = [0u8; 1024];
    let end_idx = loop {
        if let Some(pos) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if header_buf.len() > 16384 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
        let n = client.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before end of headers",
            ));
        }
        header_buf.extend_from_slice(&chunk[..n]);
    };

    let header_str = String::from_utf8_lossy(&header_buf[..end_idx]);
    let initial_payload = &header_buf[end_idx..];
    let mut lines = header_str.split("\r\n");

    let request_line = match lines.next() {
        Some(l) if !l.is_empty() => l,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty HTTP request line",
            ))
        }
    };

    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("HTTP/1.1");

    let mut proxy_auth_val: Option<&str> = None;
    let mut forward_headers: Vec<(&str, &str)> = Vec::with_capacity(16);

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            let key_lower = key.to_ascii_lowercase();
            if HOP_BY_HOP.iter().any(|h| *h == key_lower) {
                if key_lower == "proxy-authorization" {
                    proxy_auth_val = Some(val);
                }
            } else {
                forward_headers.push((key, val));
            }
        }
    }

    if let Some(cfg) = auth {
        let ok = proxy_auth_val.map(|v| cfg.verify_basic(v)).unwrap_or(false);
        if !ok {
            let _ = client.write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"nanoproxy\"\r\n\
                  Content-Length: 0\r\n\
                  Connection: close\r\n\r\n",
            );
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "proxy auth required",
            ));
        }
    }

    if method == "CONNECT" {
        let addr = if target.contains(':') {
            target.to_string()
        } else {
            format!("{target}:443")
        };

        match resolve_connect(&addr, timeout) {
            Ok(mut upstream) => {
                client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                if !initial_payload.is_empty() {
                    upstream.write_all(initial_payload)?;
                }
                copy::relay(client, upstream)
            }
            Err(e) => {
                let _ = client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                Err(e)
            }
        }
    } else {
        let url = target.strip_prefix("http://").unwrap_or(target);
        let (host_port, path) = match url.split_once('/') {
            Some((hp, p)) => (hp, format!("/{p}")),
            None => (url, "/".to_string()),
        };
        let (host, port) = match host_port.split_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().unwrap_or(80)),
            None => (host_port, 80u16),
        };
        let upstream_addr = format!("{host}:{port}");

        let mut upstream = match resolve_connect(&upstream_addr, timeout) {
            Ok(s) => s,
            Err(e) => {
                let _ = client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                return Err(e);
            }
        };
        upstream.set_nodelay(true)?;

        let mut req: Vec<u8> = Vec::with_capacity(256);
        write!(req, "{method} {path} {version}\r\n")?;
        let mut has_host = false;
        for (k, v) in &forward_headers {
            if k.eq_ignore_ascii_case("host") {
                has_host = true;
            }
            write!(req, "{k}: {v}\r\n")?;
        }
        if !has_host {
            write!(req, "Host: {host_port}\r\n")?;
        }
        req.extend_from_slice(b"\r\n");
        upstream.write_all(&req)?;
        if !initial_payload.is_empty() {
            upstream.write_all(initial_payload)?;
        }

        copy::relay(client, upstream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Auth;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn fake_http_server(response: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = conn.read(&mut buf);
                let _ = conn.write_all(response);
                let _ = conn.shutdown(std::net::Shutdown::Both);
            }
        });
        port
    }

    fn spawn_proxy(auth: Option<Auth>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut first = [0u8; 1];
                if conn.read_exact(&mut first).is_ok() {
                    let _ = handle_http(conn, first[0], auth.as_ref(), Duration::from_secs(5));
                }
            }
        });
        port
    }

    #[test]
    fn test_http_plain_proxy_no_auth() {
        let upstream_port = fake_http_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        );
        let proxy_port = spawn_proxy(None);
        let mut client = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
        write!(
            client,
            "GET http://127.0.0.1:{upstream_port}/ HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
        )
        .unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("200 OK"), "got: {resp}");
        assert!(resp.ends_with("hello"), "got: {resp}");
    }

    #[test]
    fn test_http_proxy_auth_rejected() {
        let proxy_port = spawn_proxy(Some(Auth::new("user", "pass")));
        let mut client = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
        write!(
            client,
            "GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\n\r\n"
        )
        .unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("407"), "got: {resp}");
    }

    #[test]
    fn test_http_proxy_auth_accepted() {
        let upstream_port = fake_http_server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let proxy_port = spawn_proxy(Some(Auth::new("user", "pass")));
        let mut client = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
        write!(
            client,
            "GET http://127.0.0.1:{upstream_port}/ HTTP/1.0\r\n\
             Host: 127.0.0.1\r\n\
             Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n"
        )
        .unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("200"), "got: {resp}");
    }

    #[test]
    fn test_hop_by_hop_headers_stripped() {
        let upstream_port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            thread::spawn(move || {
                if let Ok((mut conn, _)) = listener.accept() {
                    let mut buf = vec![0u8; 4096];
                    let n = conn.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                    let body = if req.contains("proxy-authorization") || req.contains("proxy-connection") {
                        "leaked"
                    } else {
                        "clean"
                    };
                    let _ = conn.write_all(
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", body.len(), body)
                            .as_bytes(),
                    );
                    let _ = conn.shutdown(std::net::Shutdown::Both);
                }
            });
            port
        };
        let proxy_port = spawn_proxy(None);
        let mut client = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
        write!(
            client,
            "GET http://127.0.0.1:{upstream_port}/ HTTP/1.0\r\n\
             Host: 127.0.0.1\r\n\
             Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\
             Proxy-Connection: keep-alive\r\n\r\n"
        )
        .unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.ends_with("clean"), "hop-by-hop headers leaked: {resp}");
    }

    #[test]
    fn test_http_connect_tunnel_no_auth() {
        let upstream_port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            thread::spawn(move || {
                if let Ok((mut conn, _)) = listener.accept() {
                    let mut buf = [0u8; 4];
                    conn.read_exact(&mut buf).unwrap();
                    assert_eq!(&buf, b"ping");
                    conn.write_all(b"pong").unwrap();
                    let _ = conn.shutdown(std::net::Shutdown::Both);
                }
            });
            port
        };

        let proxy_port = spawn_proxy(None);
        let mut client = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
        write!(
            client,
            "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
        )
        .unwrap();

        let mut buf = [0u8; 39];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        client.write_all(b"ping").unwrap();
        let mut resp = [0u8; 4];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"pong");
    }

    #[test]
    fn test_http_connect_tunnel_with_auth() {
        let upstream_port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            thread::spawn(move || {
                if let Ok((mut conn, _)) = listener.accept() {
                    let _ = conn.write_all(b"ok");
                    let _ = conn.shutdown(std::net::Shutdown::Both);
                }
            });
            port
        };

        let proxy_port = spawn_proxy(Some(Auth::new("user", "pass")));
        let mut client = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
        write!(
            client,
            "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\n\
             Host: 127.0.0.1:{upstream_port}\r\n\
             Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n"
        )
        .unwrap();

        let mut buf = [0u8; 39];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"ok");
    }

    #[test]
    fn test_http_connect_bad_gateway() {
        let closed_port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };

        let proxy_port = spawn_proxy(None);
        let mut client = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
        write!(
            client,
            "CONNECT 127.0.0.1:{closed_port} HTTP/1.1\r\nHost: 127.0.0.1:{closed_port}\r\n\r\n"
        )
        .unwrap();

        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("502 Bad Gateway"), "got: {resp}");
    }

    #[test]
    fn test_http_post_body_forwarding() {
        let upstream_port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            thread::spawn(move || {
                if let Ok((mut conn, _)) = listener.accept() {
                    let mut buf = vec![0u8; 1024];
                    let mut total = 0;
                    while total < buf.len() {
                        let n = conn.read(&mut buf[total..]).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        total += n;
                        let text = String::from_utf8_lossy(&buf[..total]);
                        if text.contains("hello-body") {
                            break;
                        }
                    }
                    let req = String::from_utf8_lossy(&buf[..total]);
                    assert!(req.contains("POST /submit HTTP/1.0"));
                    assert!(req.contains("hello-body"));
                    let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                    let _ = conn.shutdown(std::net::Shutdown::Both);
                }
            });
            port
        };

        let proxy_port = spawn_proxy(None);
        let mut client = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
        write!(
            client,
            "POST http://127.0.0.1:{upstream_port}/submit HTTP/1.0\r\n\
             Host: 127.0.0.1\r\n\
             Content-Length: 10\r\n\r\n\
             hello-body"
        )
        .unwrap();

        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("200 OK"), "got: {resp}");
    }
}
