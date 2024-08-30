use colored::Colorize;
use orion::{aead, kdf};
use std::process::exit;

use crate::utils::into_match;

pub fn encrypt(plaintext: String, secret_key: orion::kdf::SecretKey) -> Vec<u8> {
    let plaintext = plaintext.into_bytes();
    match aead::seal(&secret_key, &plaintext) {
        Ok(temp) => {
            println!("{} Data was encrypted", "Success:".bright_green());
            temp
        }
        Err(_) => {
            eprintln!("{} Could not encrypt the data", "Error:".bright_red());
            exit(1);
        }
    }
}

pub fn decrypt(ciphertext: Vec<u8>, secret_key: orion::kdf::SecretKey) -> String {
    let plaintext = match aead::open(&secret_key, &ciphertext) {
        Ok(temp) => {
            println!("{} Data was decrypted", "Success:".bright_green());
            temp
        }
        Err(_) => {
            eprintln!(
                "{} Failed to decrypt the file, please check the password",
                "Error:".bright_red()
            );
            exit(1);
        }
    };
    match String::from_utf8(plaintext) {
        Ok(temp) => temp,
        Err(_) => {
            eprintln!("{} Could not convert to String", "Error:".bright_red());
            exit(1);
        }
    }
}

pub fn get_secret_key(salt_bytes: [u8; 32], password: String) -> orion::kdf::SecretKey {
    let password = into_match(
        kdf::Password::from_slice(password.as_bytes()),
        "Error: Could not use the password",
    );
    let salt = into_match(
        kdf::Salt::from_slice(&salt_bytes),
        "Error: Could not create the salt",
    );
    into_match(
        kdf::derive_key(&password, &salt, 3, 8, 32),
        "Error: Could not generate the secret key",
    )
}

pub fn get_salt_bytes() -> [u8; 32] {
    let mut salt_bytes = [0u8; 32];
    match orion::util::secure_rand_bytes(&mut salt_bytes) {
        Ok(_) => (),
        Err(_) => {
            eprintln!(
                "{} Could not generate the random bytes for the salt",
                "Error:".bright_red()
            );
            exit(1);
        }
    };
    salt_bytes
}
