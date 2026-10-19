use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::auth::Auth;
use crate::copy;

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

pub fn handle_socks5(
    mut client: TcpStream,
    first_byte: u8,
    auth: Option<&Auth>,
    timeout: Duration,
) -> io::Result<()> {
    if first_byte != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not SOCKS5",
        ));
    }

    let mut buf1 = [0u8; 1];
    client.read_exact(&mut buf1)?;
    let nmethods = buf1[0] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods)?;

    if let Some(auth_cfg) = auth {
        if !methods.contains(&2) {
            let _ = client.write_all(&[5, 0xFF]);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "no acceptable auth method",
            ));
        }
        client.write_all(&[5, 2])?;

        let mut sub = [0u8; 1];
        client.read_exact(&mut sub)?;
        if sub[0] != 1 {
            let _ = client.write_all(&[1, 1]);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad subneg version",
            ));
        }

        let mut ulen = [0u8; 1];
        client.read_exact(&mut ulen)?;
        let mut user_buf = vec![0u8; ulen[0] as usize];
        client.read_exact(&mut user_buf)?;

        let mut plen = [0u8; 1];
        client.read_exact(&mut plen)?;
        let mut pass_buf = vec![0u8; plen[0] as usize];
        client.read_exact(&mut pass_buf)?;

        let user = std::str::from_utf8(&user_buf).unwrap_or("");
        let pass = std::str::from_utf8(&pass_buf).unwrap_or("");

        if auth_cfg.verify(user, pass) {
            client.write_all(&[1, 0])?;
        } else {
            let _ = client.write_all(&[1, 1]);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "bad credentials",
            ));
        }
    } else {
        if methods.contains(&0) {
            client.write_all(&[5, 0])?;
        } else {
            let _ = client.write_all(&[5, 0xFF]);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "no acceptable auth method",
            ));
        }
    }

    let mut req_hdr = [0u8; 4];
    client.read_exact(&mut req_hdr)?;

    if req_hdr[0] != 5 {
        socks5_send_reply(&mut client, 0x07)?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request version"));
    }
    if req_hdr[1] != 1 {
        socks5_send_reply(&mut client, 0x07)?;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only CONNECT supported",
        ));
    }

    let atyp = req_hdr[3];
    let target_addr: String = match atyp {
        0x01 => {
            let mut ipv4 = [0u8; 4];
            client.read_exact(&mut ipv4)?;
            Ipv4Addr::from(ipv4).to_string()
        }
        0x03 => {
            let mut dlen = [0u8; 1];
            client.read_exact(&mut dlen)?;
            let mut domain = vec![0u8; dlen[0] as usize];
            client.read_exact(&mut domain)?;
            String::from_utf8_lossy(&domain).into_owned()
        }
        0x04 => {
            let mut ipv6 = [0u8; 16];
            client.read_exact(&mut ipv6)?;
            Ipv6Addr::from(ipv6).to_string()
        }
        _ => {
            socks5_send_reply(&mut client, 0x08)?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported address type",
            ));
        }
    };

    let mut port_buf = [0u8; 2];
    client.read_exact(&mut port_buf)?;
    let port = u16::from_be_bytes(port_buf);

    let upstream_addr = format!("{target_addr}:{port}");
    match resolve_connect(&upstream_addr, timeout) {
        Ok(upstream) => {
            socks5_send_reply(&mut client, 0x00)?;
            copy::relay(client, upstream)
        }
        Err(e) => {
            let code = match e.kind() {
                io::ErrorKind::ConnectionRefused => 0x05,
                io::ErrorKind::NotFound => 0x04,
                _ => 0x01,
            };
            let _ = socks5_send_reply(&mut client, code);
            Err(e)
        }
    }
}

fn socks5_send_reply(client: &mut TcpStream, code: u8) -> io::Result<()> {
    client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let _ = conn.write_all(b"hello from upstream");
                let _ = conn.shutdown(std::net::Shutdown::Both);
            }
        });
        port
    }

    fn proxy_conn(auth: Option<Auth>) -> (TcpStream, thread::JoinHandle<io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut conn, _) = listener.accept()?;
            let mut first = [0u8; 1];
            conn.read_exact(&mut first)?;
            handle_socks5(conn, first[0], auth.as_ref(), Duration::from_secs(5))
        });
        let client = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        (client, handle)
    }

    fn socks5_connect_ipv4(port: u16) -> Vec<u8> {
        let mut req = vec![5, 1, 0];
        req.extend_from_slice(&[5, 1, 0, 1]);
        req.extend_from_slice(&[127, 0, 0, 1]);
        req.extend_from_slice(&port.to_be_bytes());
        req
    }

    fn socks5_connect_domain(host: &str, port: u16) -> Vec<u8> {
        let hb = host.as_bytes();
        let mut req = vec![5, 1, 0];
        req.extend_from_slice(&[5, 1, 0, 3]);
        req.push(hb.len() as u8);
        req.extend_from_slice(hb);
        req.extend_from_slice(&port.to_be_bytes());
        req
    }

    #[test]
    fn test_socks5_no_auth_ipv4_connect() {
        let upstream_port = echo_server();
        let (mut client, _proxy) = proxy_conn(None);

        let req = socks5_connect_ipv4(upstream_port);
        client.write_all(&req).unwrap();

        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(resp, [5, 0], "server chose no-auth");

        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0, "reply code should be success");

        let mut data = vec![0u8; 19];
        client.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"hello from upstream");
        let _ = client.shutdown(std::net::Shutdown::Both);
    }

    #[test]
    fn test_socks5_no_auth_domain_connect() {
        let upstream_port = echo_server();
        let (mut client, _proxy) = proxy_conn(None);

        let req = socks5_connect_domain("127.0.0.1", upstream_port);
        client.write_all(&req).unwrap();

        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(resp[1], 0);

        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0);

        let mut data = vec![0u8; 19];
        client.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"hello from upstream");
        let _ = client.shutdown(std::net::Shutdown::Both);
    }

    #[test]
    fn test_socks5_auth_correct_credentials() {
        let upstream_port = echo_server();
        let auth = Auth::new("alice", "secret");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut first = [0u8; 1];
                conn.read_exact(&mut first).unwrap();
                let _ = handle_socks5(conn, first[0], Some(&auth), Duration::from_secs(5));
            }
        });

        let mut client =
            TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();

        client.write_all(&[5, 1, 2]).unwrap();
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).unwrap();
        assert_eq!(choice, [5, 2], "server should pick method 2");

        let mut subneg = vec![1u8, 5];
        subneg.extend_from_slice(b"alice");
        subneg.push(6);
        subneg.extend_from_slice(b"secret");
        client.write_all(&subneg).unwrap();

        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).unwrap();
        assert_eq!(auth_reply[1], 0, "auth should succeed");

        let mut req = vec![5, 1, 0, 1];
        req.extend_from_slice(&[127, 0, 0, 1]);
        req.extend_from_slice(&upstream_port.to_be_bytes());
        client.write_all(&req).unwrap();

        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0, "connect should succeed");

        let mut data = vec![0u8; 19];
        client.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"hello from upstream");
        let _ = client.shutdown(std::net::Shutdown::Both);
    }

    #[test]
    fn test_socks5_auth_wrong_credentials() {
        let auth = Auth::new("alice", "secret");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut first = [0u8; 1];
                conn.read_exact(&mut first).unwrap();
                let _ = handle_socks5(conn, first[0], Some(&auth), Duration::from_secs(5));
            }
        });

        let mut client =
            TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();

        client.write_all(&[5, 1, 2]).unwrap();
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).unwrap();

        let mut subneg = vec![1u8, 5];
        subneg.extend_from_slice(b"alice");
        subneg.push(5);
        subneg.extend_from_slice(b"wrong");
        client.write_all(&subneg).unwrap();

        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).unwrap();
        assert_ne!(auth_reply[1], 0, "auth should fail");
    }

    #[test]
    fn test_socks5_no_acceptable_method() {
        let auth = Auth::new("u", "p");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut first = [0u8; 1];
                conn.read_exact(&mut first).unwrap();
                let _ = handle_socks5(conn, first[0], Some(&auth), Duration::from_secs(5));
            }
        });

        let mut client =
            TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();

        client.write_all(&[5, 1, 0]).unwrap();

        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).unwrap();
        assert_eq!(choice[1], 0xFF, "server should reject with 0xFF");
    }

    #[test]
    fn test_socks5_unsupported_command() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut first = [0u8; 1];
                conn.read_exact(&mut first).unwrap();
                let _ = handle_socks5(conn, first[0], None, Duration::from_secs(5));
            }
        });

        let mut client =
            TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();

        client.write_all(&[5, 1, 0]).unwrap();
        let mut _choice = [0u8; 2];
        client.read_exact(&mut _choice).unwrap();

        let req = [5u8, 2, 0, 1, 127, 0, 0, 1, 0x04, 0x00];
        client.write_all(&req).unwrap();

        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0x07, "should return command not supported");
    }

    #[test]
    fn test_socks5_invalid_version() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            handle_socks5(conn, 4, None, Duration::from_secs(5))
        });

        let _client = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
        let res = handle.join().unwrap();
        assert!(res.is_err());
    }

    #[test]
    fn test_socks5_unsupported_address_type() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut first = [0u8; 1];
                conn.read_exact(&mut first).unwrap();
                let _ = handle_socks5(conn, first[0], None, Duration::from_secs(5));
            }
        });

        let mut client = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).unwrap();
        assert_eq!(choice, [5, 0]);

        client.write_all(&[5, 1, 0, 0x99]).unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0x08, "address type not supported");
    }

    #[test]
    fn test_socks5_ipv6_connect() {
        let listener = TcpListener::bind("[::1]:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let _ = conn.write_all(b"ipv6-upstream");
                let _ = conn.shutdown(std::net::Shutdown::Both);
            }
        });

        let (mut client, _proxy) = proxy_conn(None);
        client.write_all(&[5, 1, 0]).unwrap();
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).unwrap();
        assert_eq!(choice, [5, 0]);

        let mut req = vec![5, 1, 0, 4];
        let mut ipv6_bytes = [0u8; 16];
        ipv6_bytes[15] = 1;
        req.extend_from_slice(&ipv6_bytes);
        req.extend_from_slice(&upstream_port.to_be_bytes());
        client.write_all(&req).unwrap();

        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0, "IPv6 connect success");

        let mut data = vec![0u8; 13];
        client.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"ipv6-upstream");
        let _ = client.shutdown(std::net::Shutdown::Both);
    }
}
