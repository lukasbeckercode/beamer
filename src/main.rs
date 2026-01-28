use std::env;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use rand::rngs::OsRng;
use rand::TryRngCore;

const CHUNK_SIZE: usize = 64 * 1024;
const MAGIC: [u8; 4] = *b"AES1";
const VERSION: u8 = 1;

#[derive(Debug, Clone)]
pub struct AesKeyMaterial {
    pub key: [u8; 16],
    pub nonce: [u8; 12], // base nonce
}

impl AesKeyMaterial {
    pub fn generate() -> io::Result<Self> {
        let mut rng = OsRng;

        let mut key = [0u8; 16];
        rng.try_fill_bytes(&mut key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("rng error: {e}")))?;

        let mut nonce = [0u8; 12];
        rng.try_fill_bytes(&mut nonce)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("rng error: {e}")))?;

        Ok(Self { key, nonce })
    }
}

// -------- framing helpers --------

fn write_u32_be(stream: &mut TcpStream, v: u32) -> io::Result<()> {
    stream.write_all(&v.to_be_bytes())
}

fn read_u32_be(stream: &mut TcpStream) -> io::Result<u32> {
    let mut b = [0u8; 4];
    stream.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

fn nonce_for_chunk(base: [u8; 12], chunk_index: u32) -> [u8; 12] {
    let mut n = base;
    n[8..12].copy_from_slice(&chunk_index.to_be_bytes());
    n
}

// -------- protocol: send/recv material --------

fn send_key_material(stream: &mut TcpStream, mat: &AesKeyMaterial) -> io::Result<()> {
    stream.write_all(&MAGIC)?;
    stream.write_all(&[VERSION])?;

    // fixed-length payload: key || nonce
    let payload_len: u32 = (16 + 12) as u32;
    write_u32_be(stream, payload_len)?;
    stream.write_all(&mat.key)?;
    stream.write_all(&mat.nonce)?;
    Ok(())
}

fn recv_key_material(stream: &mut TcpStream) -> io::Result<AesKeyMaterial> {
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad MAGIC (not an AES1 stream)",
        ));
    }

    let mut ver = [0u8; 1];
    stream.read_exact(&mut ver)?;
    if ver[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported VERSION",
        ));
    }

    let len = read_u32_be(stream)? as usize;
    if len != 28 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected key material length",
        ));
    }

    let mut key = [0u8; 16];
    let mut nonce = [0u8; 12];
    stream.read_exact(&mut key)?;
    stream.read_exact(&mut nonce)?;
    Ok(AesKeyMaterial { key, nonce })
}

// -------- crypto wrapper --------

fn aes_chunk(text: &[u8], encrypt: bool, mat: &AesKeyMaterial, chunk_index: u32) -> Result<Vec<u8>, String> {
    let aad = b""; // keep empty

    let cipher = Aes128Gcm::new_from_slice(&mat.key)
        .map_err(|e| format!("bad key length: {e:?}"))?;

    let derived = nonce_for_chunk(mat.nonce, chunk_index);
    let nonce = Nonce::from_slice(&derived);

    if encrypt {
        cipher
            .encrypt(nonce, Payload { msg: text, aad })
            .map_err(|e| format!("encrypt failed: {e:?}"))
    } else {
        cipher
            .decrypt(nonce, Payload { msg: text, aad })
            .map_err(|e| format!("decrypt failed: {e:?}"))
    }
}

// -------- streaming send/recv --------

fn send_streaming_message(stream: &mut TcpStream, mat: &AesKeyMaterial) -> io::Result<()> {
    let mut stdin = io::stdin().lock();
    let mut buf = [0u8; CHUNK_SIZE];
    let mut chunk_index: u32 = 0;

    loop {
        let n = stdin.read(&mut buf)?;
        if n == 0 {
            break;
        }

        let ct = aes_chunk(&buf[..n], true, mat, chunk_index)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Frame: [chunk_index][ct_len][ct_bytes]
        write_u32_be(stream, chunk_index)?;
        write_u32_be(stream, ct.len() as u32)?;
        stream.write_all(&ct)?;

        chunk_index = chunk_index.wrapping_add(1);
    }

    // End marker: [u32::MAX][0]
    write_u32_be(stream, u32::MAX)?;
    write_u32_be(stream, 0)?;
    Ok(())
}

fn recv_streaming_message(stream: &mut TcpStream, mat: &AesKeyMaterial) -> io::Result<()> {
    let mut stdout = io::stdout().lock();

    loop {
        let chunk_index = read_u32_be(stream)?;
        let ct_len = read_u32_be(stream)? as usize;

        if chunk_index == u32::MAX && ct_len == 0 {
            break;
        }

        let mut ct = vec![0u8; ct_len];
        stream.read_exact(&mut ct)?;

        let pt = aes_chunk(&ct, false, mat, chunk_index)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        stdout.write_all(&pt)?;
    }

    stdout.flush()?;
    Ok(())
}

// -------- cli --------

fn usage() -> ! {
    eprintln!("Usage:");
    eprintln!("  beamer -s <ip> <port>    (send; reads from stdin)");
    eprintln!("  beamer -r <port>         (receive; writes to stdout)");
    eprintln!("  beamer -h");
    process::exit(2);
}

fn send(ip: &String, port: &String) {
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
        send_streaming_message(&mut stream, &mat)?;
        stream.flush()?;
        Ok(())
    })() {
        eprintln!("Send failed: {e}");
        process::exit(1);
    }

    let _ = stream.shutdown(Shutdown::Write);
}

fn receive(port: &String) {
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
        recv_streaming_message(&mut stream, &mat)?;
        Ok(())
    })() {
        eprintln!("Receive failed: {e}");
        process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        usage();
    }

    let op_mode = args[1].to_lowercase();
    if op_mode == "-s" {
        if args.len() != 4 {
            usage();
        }
        send(&args[2], &args[3]);
    } else if op_mode == "-r" {
        if args.len() != 3 {
            usage();
        }
        receive(&args[2]);
    } else if op_mode == "-h" {
        usage();
    } else {
        usage();
    }
}
