// -------- protocol: send/recv material --------

use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;
use crate::crypto::{aes_chunk, AesKeyMaterial};
use crate::net::constants::{CHUNK_SIZE, MAGIC, VERSION};
use crate::net::framing::{read_u32_be, write_u32_be};


pub fn send_key_material(stream: &mut TcpStream, mat: &AesKeyMaterial) -> io::Result<()> {
    stream.write_all(&MAGIC)?;
    stream.write_all(&[VERSION])?;

    // fixed-length payload: key || nonce
    let payload_len: u32 = (16 + 12) as u32;
    write_u32_be(stream, payload_len)?;
    stream.write_all(&mat.key)?;
    stream.write_all(&mat.nonce)?;
    Ok(())
}

pub fn recv_key_material(stream: &mut TcpStream) -> io::Result<AesKeyMaterial> {
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


// -------- streaming send/recv --------

pub fn send_streaming_message<R: Read>(stream: &mut TcpStream, mat: &AesKeyMaterial, mut input: R) -> io::Result<()> {
    let mut buf = [0u8; CHUNK_SIZE];
    let mut chunk_index: u32 = 0;

    loop {
        let n = input.read(&mut buf)?;
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

pub fn recv_streaming_message<W: Write>(stream: &mut TcpStream, mat: &AesKeyMaterial, mut output: W) -> io::Result<()> {

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

        output.write_all(&pt)?;
    }

    output.flush()?;
    Ok(())
}
