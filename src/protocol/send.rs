use std::net::{Shutdown, TcpStream};
use std::{io, process};
use std::io::Write;
use crate::crypto::AesKeyMaterial;
use crate::net::{send_key_material, send_streaming_message};

pub fn send(ip: &String, port: &String, is_pipe: bool) {
    let port_num: u16 = match port.parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Invalid port: {port}");
            process::exit(2);
        }
    };

    let addr = format!("{ip}:{port_num}");

    let mut stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to connect to {addr}: {e}");
            process::exit(1);
        }
    };

    let _ = stream.set_nodelay(true);

    let mat = match AesKeyMaterial::generate() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to generate key material: {e}");
            process::exit(1);
        }
    };

    if let Err(e) = (|| -> io::Result<()> {
        send_key_material(&mut stream, &mat)?;
        if is_pipe {  
            //TODO Implement pipe
        } else { 
            let mut input = io::stdin();
            send_streaming_message(&mut stream, &mat, &mut input)?;
        }
        stream.flush()?;
        Ok(())
    })() {
        eprintln!("Send failed: {e}");
        process::exit(1);
    }

    let _ = stream.shutdown(Shutdown::Write);
}
