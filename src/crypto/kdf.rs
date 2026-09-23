use crate::error::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use orion::util::secure_rand_bytes;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;

pub fn generate_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    secure_rand_bytes(&mut salt)?;
    Ok(salt)
}

pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(KEY_LEN))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2.hash_password_into(password, salt, &mut key)?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_is_deterministic() {
        let salt = [7u8; SALT_LEN];
        let k1 = derive_key(b"password", &salt, 8, 2, 1).unwrap();
        let k2 = derive_key(b"password", &salt, 8, 2, 1).unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn different_passwords_give_different_keys() {
        let salt = [7u8; SALT_LEN];
        let k1 = derive_key(b"password1", &salt, 8, 2, 1).unwrap();
        let k2 = derive_key(b"password2", &salt, 8, 2, 1).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn different_salts_give_different_keys() {
        let salt1 = [7u8; SALT_LEN];
        let salt2 = [8u8; SALT_LEN];
        let k1 = derive_key(b"password", &salt1, 8, 2, 1).unwrap();
        let k2 = derive_key(b"password", &salt2, 8, 2, 1).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn key_length_is_32_bytes() {
        let salt = [0u8; SALT_LEN];
        let k = derive_key(b"pw", &salt, 8, 2, 1).unwrap();
        assert_eq!(k.len(), KEY_LEN);
    }

    #[test]
    fn generate_salt_produces_unique_values() {
        let s1 = generate_salt().unwrap();
        let s2 = generate_salt().unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn generate_salt_is_correct_length() {
        let s = generate_salt().unwrap();
        assert_eq!(s.len(), SALT_LEN);
    }

    #[test]
    fn empty_password_works() {
        let salt = [1u8; SALT_LEN];
        let k = derive_key(b"", &salt, 8, 2, 1).unwrap();
        assert_eq!(k.len(), KEY_LEN);
    }
}
