# beamer

beamer is a small Rust CLI tool that forwards arbitrary binary data over a TCP connection using a simple custom framing format and AES-GCM encryption.

It is designed as a learning / CTF-style project, demonstrating how SSL interception can be made irrelevant.

**This is not intended for real-world secure communication, it merely makes SSL interception useless**



## Features

- Encrypts arbitrary binary input from stdin
- Streams data over TCP in framed chunks
- Decrypts and writes received data to stdout
- Uses AES-128-GCM with a per-chunk nonce counter
- Simple custom wire protocol (no TLS, no authentication)



## How it works

1. The sender generates an AES key and base nonce
2. The key material is sent to the receiver in plaintext
3. Data from stdin is read in chunks
4. Each chunk is encrypted with AES-GCM using a derived nonce
5. Chunks are sent with length framing
6. The receiver decrypts and writes plaintext to stdout

This is conceptually similar to tools like netcat with TLS, but implemented manually for educational purposes.



## Usage

### Build

```bash
cargo build --release
```
## Send Data

Send data by piping it into beamer. Data can be text or arbitrary binary.
```
cat file.bin | ./beamer -s <ip> <port>

Example:

# Terminal 1 (receiver)
./beamer -r 9000 > received.txt

# Terminal 2 (sender)
echo "Hello" | ./beamer -s 127.0.0.1 9000

```

## Receive Data

Receive data on a TCP port and write decrypted output to stdout.
```
./beamer -r <port>
```
You can redirect the output to a file:
```
./beamer -r 9000 > output.bin
```


## Wire Format

The protocol uses a simple custom framing format.
---

MAGIC "AES1"   
VERSION (1 byte)   
KEY_MATERIAL_LENGTH (u32)   
AES_KEY || BASE_NONCE   

---

**Repeated for each chunk:**  
CHUNK_INDEX (u32)   
CIPHERTEXT_LENGTH (u32)   
CIPHERTEXT   

---

**End marker:**   
0xFFFFFFFF   
0x00000000   

---

## Security Notes

This tool is intentionally insecure and designed for learning and CTF-style challenges only.

- Encryption keys are sent in plaintext
- No authentication or key exchange
- No protection against replay or tampering beyond AES-GCM per chunk

Do not use this tool for real-world secure communication.
