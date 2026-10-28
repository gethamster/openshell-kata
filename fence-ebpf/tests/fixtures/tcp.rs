//! HTTP fixture used only inside an isolated privileged packet-path test.
use std::{
    io::{Read, Write},
    net::TcpListener,
    time::Duration,
};
fn main() -> std::io::Result<()> {
    let port = std::env::args()
        .nth(1)
        .expect("port")
        .parse::<u16>()
        .expect("numeric port");
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    for incoming in listener.incoming() {
        let mut stream = incoming?;
        eprintln!("accepted {} on {port}", stream.peer_addr()?);
        std::thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buffer = [0; 1024];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO",
            );
        });
    }
    Ok(())
}
