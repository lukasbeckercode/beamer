// -------- framing helpers --------

use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;

pub(crate) fn write_u32_be(stream: &mut TcpStream, v: u32) -> io::Result<()> {
    stream.write_all(&v.to_be_bytes())
}

pub(crate) fn read_u32_be(stream: &mut TcpStream) -> io::Result<u32> {
    let mut b = [0u8; 4];
    stream.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

pub fn nonce_for_chunk(base: [u8; 12], chunk_index: u32) -> [u8; 12] {
    let mut n = base;
    n[8..12].copy_from_slice(&chunk_index.to_be_bytes());
    n
}
