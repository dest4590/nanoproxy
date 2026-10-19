use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::thread;

const BUF_SIZE: usize = 16384;

pub fn relay(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
    client.set_nodelay(true)?;
    upstream.set_nodelay(true)?;

    let mut client_r = client.try_clone()?;
    let mut upstream_w = upstream.try_clone()?;

    thread::spawn(move || {
        pipe(&mut client_r, &mut upstream_w);
        let _ = upstream_w.shutdown(Shutdown::Write);
    });

    let mut upstream_r = upstream;
    let mut client_w = client;
    pipe(&mut upstream_r, &mut client_w);
    let _ = client_w.shutdown(Shutdown::Write);

    Ok(())
}

#[inline]
fn pipe(src: &mut TcpStream, dst: &mut TcpStream) {
    let mut buf = [0u8; BUF_SIZE];
    loop {
        match src.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}
