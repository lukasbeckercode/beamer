
// -------- crypto wrapper --------

use std::io;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, Payload};
use rand::rand_core::OsRng;
use rand::TryRngCore;
use crate::net::nonce_for_chunk;



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
pub fn aes_chunk(text: &[u8], encrypt: bool, mat: &AesKeyMaterial, chunk_index: u32) -> Result<Vec<u8>, String> {
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
