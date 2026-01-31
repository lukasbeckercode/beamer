use std::net::TcpListener;
use std::{io, process};
use crate::net::{recv_key_material, recv_streaming_message};

pub fn receive(port: &String, is_pipe: bool) {
    let addr = format!("0.0.0.0:{port}");

    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to {addr}: {e}");
            process::exit(1);
        }
    };

    eprintln!("Listening on {addr}");

    let (mut stream, peer) = match listener.accept() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to accept connection: {e}");
            process::exit(1);
        }
    };

    eprintln!("Connection from {peer}");
    let _ = stream.set_nodelay(true);

    if let Err(e) = (|| -> io::Result<()> {
        let mat = recv_key_material(&mut stream)?;
        if is_pipe {
            //TODO implement pipe
        } else {
            let mut out = io::stdout().lock();
            recv_streaming_message(&mut stream, &mat, &mut out)?;
        }
        Ok(())
    })() {
        eprintln!("Receive failed: {e}");
        process::exit(1);
    }
}
