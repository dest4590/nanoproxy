mod auth;
mod copy;
mod http;
mod socks5;

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use std::{env, process, thread};

use auth::Auth;

#[derive(Debug, PartialEq)]
struct Config {
    bind: String,
    auth: Option<Auth>,
    timeout: Duration,
}

fn print_help() {
    println!(
        r#"nanoproxy - ultra-lightweight socks5 & http proxy for routers

USAGE:
    nanoproxy [OPTIONS]

OPTIONS:
    -b, --bind <ADDR:PORT>    Bind address (default: 0.0.0.0:1080)
    -a, --auth <USER:PASS>    Enable username & password authentication
    -t, --timeout <SECS>      Connection timeout in seconds (default: 15)
    -h, --help                Print this help

FEATURES:
    * Auto-detect SOCKS5 / HTTP / HTTPS CONNECT on one port
    * SOCKS5 RFC 1928 + RFC 1929 username/password auth
    * HTTP Proxy with RFC 7235 Basic Auth & HTTPS CONNECT tunneling
    * 64 KB stack per thread, zero dependencies, <100 KB static binary
"#
    );
}

fn parse_args_from<T: AsRef<str>>(args: &[T]) -> Result<Option<Config>, String> {
    let mut bind = "0.0.0.0:1080".to_string();
    let mut auth = None;
    let mut timeout = Duration::from_secs(15);

    let mut i = 1;
    while i < args.len() {
        let arg = args[i].as_ref();
        match arg {
            "-b" | "--bind" => {
                if i + 1 < args.len() {
                    bind = args[i + 1].as_ref().to_string();
                    i += 1;
                } else {
                    return Err(format!("missing value for {arg}"));
                }
            }
            "-a" | "--auth" => {
                if i + 1 < args.len() {
                    let val = args[i + 1].as_ref();
                    match val.split_once(':') {
                        Some((u, p)) => auth = Some(Auth::new(u, p)),
                        None => return Err("--auth must be USER:PASS".to_string()),
                    }
                    i += 1;
                } else {
                    return Err(format!("missing value for {arg}"));
                }
            }
            "-t" | "--timeout" => {
                if i + 1 < args.len() {
                    match args[i + 1].as_ref().parse::<u64>() {
                        Ok(s) => timeout = Duration::from_secs(s),
                        Err(_) => return Err("--timeout must be a positive integer".to_string()),
                    }
                    i += 1;
                } else {
                    return Err(format!("missing value for {arg}"));
                }
            }
            "-h" | "--help" => {
                print_help();
                return Ok(None);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    Ok(Some(Config {
        bind,
        auth,
        timeout,
    }))
}

fn handle_connection(stream: TcpStream, auth: Option<&Auth>, timeout: Duration) {
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let mut first = [0u8; 1];
    let mut s = stream;
    if s.read_exact(&mut first).is_err() {
        return;
    }

    let res = if first[0] == 0x05 {
        socks5::handle_socks5(s, first[0], auth, timeout)
    } else {
        http::handle_http(s, first[0], auth, timeout)
    };

    if let Err(e) = res {
        match e.kind() {
            std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::TimedOut => {}
            _ => eprintln!("connection error: {e}"),
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let config = match parse_args_from(&args) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => process::exit(0),
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    let listener = match TcpListener::bind(&config.bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {}: {e}", config.bind);
            process::exit(1);
        }
    };
    eprintln!("listening on {}", config.bind);

    let auth = Arc::new(config.auth);
    let timeout = config.timeout;

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let auth = Arc::clone(&auth);
        thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || handle_connection(stream, auth.as_ref().as_ref(), timeout))
            .ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_args_defaults() {
        let args = ["nanoproxy"];
        let cfg = parse_args_from(&args).unwrap().unwrap();
        assert_eq!(cfg.bind, "0.0.0.0:1080");
        assert_eq!(cfg.auth, None);
        assert_eq!(cfg.timeout, Duration::from_secs(15));
    }

    #[test]
    fn test_parse_args_custom_bind() {
        let args = ["nanoproxy", "-b", "127.0.0.1:9050"];
        let cfg = parse_args_from(&args).unwrap().unwrap();
        assert_eq!(cfg.bind, "127.0.0.1:9050");

        let args2 = ["nanoproxy", "--bind", "10.0.0.1:8080"];
        let cfg2 = parse_args_from(&args2).unwrap().unwrap();
        assert_eq!(cfg2.bind, "10.0.0.1:8080");
    }

    #[test]
    fn test_parse_args_auth() {
        let args = ["nanoproxy", "-a", "admin:s3cr3t"];
        let cfg = parse_args_from(&args).unwrap().unwrap();
        assert_eq!(
            cfg.auth,
            Some(Auth {
                username: "admin".to_string(),
                password: "s3cr3t".to_string()
            })
        );
    }

    #[test]
    fn test_parse_args_timeout() {
        let args = ["nanoproxy", "-t", "45"];
        let cfg = parse_args_from(&args).unwrap().unwrap();
        assert_eq!(cfg.timeout, Duration::from_secs(45));
    }

    #[test]
    fn test_parse_args_help() {
        let args = ["nanoproxy", "-h"];
        assert_eq!(parse_args_from(&args).unwrap(), None);

        let args2 = ["nanoproxy", "--help"];
        assert_eq!(parse_args_from(&args2).unwrap(), None);
    }

    #[test]
    fn test_parse_args_invalid_auth() {
        let args = ["nanoproxy", "-a", "no_colon"];
        assert!(parse_args_from(&args).is_err());
    }

    #[test]
    fn test_parse_args_invalid_timeout() {
        let args = ["nanoproxy", "-t", "not_a_number"];
        assert!(parse_args_from(&args).is_err());
    }

    #[test]
    fn test_parse_args_missing_val() {
        let args = ["nanoproxy", "-b"];
        assert!(parse_args_from(&args).is_err());
    }

    #[test]
    fn test_parse_args_unknown() {
        let args = ["nanoproxy", "--unknown-flag"];
        assert!(parse_args_from(&args).is_err());
    }
}
