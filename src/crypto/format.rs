use crate::error::Result;
use orion::aead::streaming::Nonce;
use std::io::{Read, Write};

pub const MAGIC: [u8; 4] = [0x52, 0x53, 0x43, 0x4D]; // "RSCM"
pub const VERSION: u8 = 1;
pub const KDF_ALGORITHM_ARGON2ID: u8 = 1;
pub const SALT_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct FileHeader {
    pub version: u8,
    pub kdf_algorithm: u8,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce: Nonce,
}

pub fn write_header<W: Write>(writer: &mut W, header: &FileHeader) -> Result<()> {
    writer.write_all(&MAGIC)?;
    writer.write_all(&[header.version])?;
    writer.write_all(&[header.kdf_algorithm])?;
    writer.write_all(&header.memory_kib.to_le_bytes())?;
    writer.write_all(&header.iterations.to_le_bytes())?;
    writer.write_all(&[header.parallelism as u8])?;
    writer.write_all(&header.salt)?;
    writer.write_all(header.nonce.as_ref())?;
    Ok(())
}

pub fn read_header<R: Read>(reader: &mut R) -> Result<FileHeader> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(crate::error::Error::InvalidFormat(
            "Invalid magic bytes".to_string(),
        ));
    }

    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte)?;
    let version = byte[0];
    if version != VERSION {
        return Err(crate::error::Error::InvalidFormat(format!(
            "Unsupported version: {}",
            version
        )));
    }

    reader.read_exact(&mut byte)?;
    let kdf_algorithm = byte[0];
    if kdf_algorithm != KDF_ALGORITHM_ARGON2ID {
        return Err(crate::error::Error::InvalidFormat(format!(
            "Unsupported KDF algorithm: {}",
            kdf_algorithm
        )));
    }

    let memory_kib = u32::from_le_bytes({
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        buf
    });

    let iterations = u32::from_le_bytes({
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        buf
    });

    let mut parallelism_buf = [0u8; 1];
    reader.read_exact(&mut parallelism_buf)?;
    let parallelism = parallelism_buf[0];

    let mut salt = [0u8; SALT_LEN];
    reader.read_exact(&mut salt)?;

    let mut nonce_bytes = [0u8; 24];
    reader.read_exact(&mut nonce_bytes)?;

    let nonce = Nonce::from_slice(&nonce_bytes)?;

    Ok(FileHeader {
        version,
        kdf_algorithm,
        memory_kib,
        iterations,
        parallelism: parallelism as u32,
        salt,
        nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header() -> FileHeader {
        FileHeader {
            version: VERSION,
            kdf_algorithm: KDF_ALGORITHM_ARGON2ID,
            memory_kib: 65536,
            iterations: 3,
            parallelism: 1,
            salt: [0xAB; SALT_LEN],
            nonce: Nonce::from_slice(&[0xCD; 24]).unwrap(),
        }
    }

    #[test]
    fn header_roundtrip() {
        let header = make_header();
        let mut buf = Vec::new();
        write_header(&mut buf, &header).unwrap();
        assert_eq!(buf.len(), 71);

        let mut cursor = std::io::Cursor::new(&buf);
        let read = read_header(&mut cursor).unwrap();
        assert_eq!(read.version, header.version);
        assert_eq!(read.kdf_algorithm, header.kdf_algorithm);
        assert_eq!(read.memory_kib, header.memory_kib);
        assert_eq!(read.iterations, header.iterations);
        assert_eq!(read.parallelism, header.parallelism);
        assert_eq!(read.salt, header.salt);
        assert_eq!(read.nonce.as_ref(), header.nonce.as_ref());
    }

    #[test]
    fn header_starts_with_magic() {
        let header = make_header();
        let mut buf = Vec::new();
        write_header(&mut buf, &header).unwrap();
        assert_eq!(&buf[0..4], &MAGIC);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = vec![0u8; 71];
        buf[0..4].copy_from_slice(b"XXXX");
        let mut cursor = std::io::Cursor::new(&buf);
        let err = read_header(&mut cursor).unwrap_err();
        assert!(matches!(err, crate::error::Error::InvalidFormat(_)));
    }

    #[test]
    fn rejects_bad_version() {
        let header = make_header();
        let mut buf = Vec::new();
        write_header(&mut buf, &header).unwrap();
        buf[4] = 99;
        let mut cursor = std::io::Cursor::new(&buf);
        let err = read_header(&mut cursor).unwrap_err();
        assert!(matches!(err, crate::error::Error::InvalidFormat(_)));
    }

    #[test]
    fn rejects_bad_kdf_algorithm() {
        let header = make_header();
        let mut buf = Vec::new();
        write_header(&mut buf, &header).unwrap();
        buf[5] = 42;
        let mut cursor = std::io::Cursor::new(&buf);
        let err = read_header(&mut cursor).unwrap_err();
        assert!(matches!(err, crate::error::Error::InvalidFormat(_)));
    }

    #[test]
    fn rejects_truncated_header() {
        let header = make_header();
        let mut buf = Vec::new();
        write_header(&mut buf, &header).unwrap();
        buf.truncate(30);
        let mut cursor = std::io::Cursor::new(&buf);
        assert!(read_header(&mut cursor).is_err());
    }
}
