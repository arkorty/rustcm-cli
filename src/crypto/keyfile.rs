use crate::error::Result;
use std::io::Write;

pub const KEY_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct KeyFile;

impl KeyFile {
    pub fn write<W: Write>(writer: &mut W, key: &[u8; KEY_LEN]) -> Result<()> {
        writer.write_all(key)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyfile_roundtrip() {
        let key = [0x42u8; KEY_LEN];
        let mut buf = Vec::new();
        KeyFile::write(&mut buf, &key).unwrap();
        assert_eq!(buf.len(), KEY_LEN);
        assert_eq!(buf, key.as_slice());
    }

    #[test]
    fn keyfile_writes_exact_32_bytes() {
        let key = [0xFFu8; KEY_LEN];
        let mut buf = Vec::new();
        KeyFile::write(&mut buf, &key).unwrap();
        assert_eq!(buf.len(), 32);
    }
}
