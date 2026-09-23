use crate::error::Result;
use orion::aead::streaming::{Nonce, StreamOpener, StreamTag, ABYTES};
use orion::aead::SecretKey;
use std::io::{Read, Write};

/// Decrypt `input` → `output` chunk-by-chunk. Never buffers the full plaintext.
pub fn decrypt_stream(
    input: &mut dyn Read,
    output: &mut dyn Write,
    key: &[u8; crate::crypto::kdf::KEY_LEN],
    nonce: &Nonce,
) -> Result<()> {
    let secret_key = SecretKey::from_slice(key)?;
    let mut opener = StreamOpener::new(&secret_key, nonce)?;

    let mut len_buf = [0u8; 4];
    loop {
        match input.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(crate::error::Error::StreamTruncated);
            }
            Err(e) => return Err(e.into()),
        }
        let chunk_len = u32::from_le_bytes(len_buf) as usize;
        if chunk_len < ABYTES {
            return Err(crate::error::Error::InvalidChunkSize(format!(
                "chunk length {chunk_len} < minimum {ABYTES}"
            )));
        }
        let mut chunk = vec![0u8; chunk_len];
        input.read_exact(&mut chunk)?;

        let (plaintext, tag) = opener.open_chunk(&chunk)?;
        output.write_all(&plaintext)?;

        if tag == StreamTag::Finish {
            break;
        }
    }
    output.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::{derive_key, generate_salt, KEY_LEN};

    /// Build a valid encrypted stream using the same logic as the encrypt command.
    fn encrypt_bytes(plaintext: &[u8], key: &[u8; KEY_LEN], chunk_size: usize) -> (Nonce, Vec<u8>) {
        use orion::aead::streaming::StreamSealer;

        let secret_key = SecretKey::from_slice(key).unwrap();
        let (mut sealer, nonce) = StreamSealer::new(&secret_key).unwrap();

        let mut out = Vec::new();
        if plaintext.is_empty() {
            let sealed = sealer.seal_chunk(&[], &StreamTag::Finish).unwrap();
            out.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
            out.extend_from_slice(&sealed);
            return (nonce, out);
        }

        let mut curr = 0;
        loop {
            let end = (curr + chunk_size).min(plaintext.len());
            let is_last = end == plaintext.len();
            let tag = if is_last {
                StreamTag::Finish
            } else {
                StreamTag::Message
            };
            let sealed = sealer.seal_chunk(&plaintext[curr..end], &tag).unwrap();
            out.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
            out.extend_from_slice(&sealed);
            if is_last {
                break;
            }
            curr = end;
        }
        (nonce, out)
    }

    fn test_key() -> [u8; KEY_LEN] {
        let salt = generate_salt().unwrap();
        *derive_key(b"test-password", &salt, 8, 2, 1).unwrap()
    }

    #[test]
    fn roundtrip_small() {
        let key = test_key();
        let data = b"hello world";
        let (nonce, enc) = encrypt_bytes(data, &key, 64);
        let mut out = Vec::new();
        decrypt_stream(&mut &enc[..], &mut out, &key, &nonce).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn roundtrip_empty() {
        let key = test_key();
        let (nonce, enc) = encrypt_bytes(b"", &key, 64);
        let mut out = Vec::new();
        decrypt_stream(&mut &enc[..], &mut out, &key, &nonce).unwrap();
        assert_eq!(out, b"");
    }

    #[test]
    fn roundtrip_multi_chunk() {
        let key = test_key();
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
        let (nonce, enc) = encrypt_bytes(&data, &key, 64);
        let mut out = Vec::new();
        decrypt_stream(&mut &enc[..], &mut out, &key, &nonce).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn roundtrip_exact_chunk_boundary() {
        let key = test_key();
        let data = vec![0xAAu8; 128];
        let (nonce, enc) = encrypt_bytes(&data, &key, 64);
        let mut out = Vec::new();
        decrypt_stream(&mut &enc[..], &mut out, &key, &nonce).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn roundtrip_binary_all_byte_values() {
        let key = test_key();
        let data: Vec<u8> = (0..=255u8).collect();
        let (nonce, enc) = encrypt_bytes(&data, &key, 16);
        let mut out = Vec::new();
        decrypt_stream(&mut &enc[..], &mut out, &key, &nonce).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = test_key();
        let key2 = test_key();
        // key2 is from a different salt so it differs
        assert_ne!(key1, key2);
        let (nonce, enc) = encrypt_bytes(b"secret", &key1, 64);
        let mut out = Vec::new();
        assert!(decrypt_stream(&mut &enc[..], &mut out, &key2, &nonce).is_err());
    }

    #[test]
    fn truncated_stream_fails() {
        let key = test_key();
        let data = vec![0x55u8; 200];
        let (nonce, enc) = encrypt_bytes(&data, &key, 64);

        // Truncate mid-chunk: read_exact on chunk body hits EOF → Io error.
        let truncated = &enc[..enc.len() - 10];
        let mut out = Vec::new();
        assert!(decrypt_stream(&mut &truncated[..], &mut out, &key, &nonce).is_err());

        // Truncate to exactly the first length prefix boundary → StreamTruncated.
        // First chunk: 4-byte len + sealed. Cut right at the start of second chunk's len prefix.
        // Simpler: truncate to just the 4-byte length prefix of the first chunk minus nothing,
        // i.e. only 2 bytes total (can't even read a length prefix).
        let mut out = Vec::new();
        let err = decrypt_stream(&mut &enc[..2][..], &mut out, &key, &nonce).unwrap_err();
        assert!(matches!(err, crate::error::Error::StreamTruncated));
    }

    #[test]
    fn corrupted_chunk_fails() {
        let key = test_key();
        let data = vec![0x77u8; 200];
        let (nonce, mut enc) = encrypt_bytes(&data, &key, 64);
        // Flip a byte in the ciphertext body (past the 4-byte length prefix of first chunk)
        let idx = 10;
        enc[idx] ^= 0xFF;
        let mut out = Vec::new();
        assert!(decrypt_stream(&mut &enc[..], &mut out, &key, &nonce).is_err());
    }

    #[test]
    fn empty_ciphertext_fails() {
        let key = test_key();
        let nonce = Nonce::from_slice(&[0u8; 24]).unwrap();
        let mut out = Vec::new();
        let err = decrypt_stream(&mut &[][..], &mut out, &key, &nonce).unwrap_err();
        assert!(matches!(err, crate::error::Error::StreamTruncated));
    }

    #[test]
    fn large_roundtrip() {
        let key = test_key();
        let data: Vec<u8> = (0..100_000u32).map(|i| ((i * 7) % 256) as u8).collect();
        let (nonce, enc) = encrypt_bytes(&data, &key, 4096);
        let mut out = Vec::new();
        decrypt_stream(&mut &enc[..], &mut out, &key, &nonce).unwrap();
        assert_eq!(out, data);
    }
}
