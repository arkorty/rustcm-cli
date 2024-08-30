use colored::Colorize;
use std::fs::{read_to_string, File};
use std::io::{Read, Write};
use std::process::exit;

use crate::utils::into_match;

pub fn write_plain(path: String, plaintext: String) {
    let mut file = into_match(
        File::create(&path),
        &format!("Error: Could not create {}", path),
    );
    into_match(
        file.write(&plaintext.into_bytes()),
        &format!("Error: Could not write the data to {}", path),
    );
    into_match(
        file.flush(),
        &format!("Error: Could not flush data to {}", path),
    );
}

pub fn write_cipher(path: String, salt_bytes: [u8; 32], ciphertext: Vec<u8>) {
    let mut file = into_match(
        File::create(&path),
        &format!("Error: Could not create {}", path),
    );
    into_match(
        file.write(&salt_bytes),
        &format!("Error: Could write the salt to {}", path),
    );
    into_match(
        file.write(&ciphertext),
        &format!("Error: Could not write the ciphertext to {}", path),
    );
    into_match(
        file.flush(),
        &format!("Error: Could not flush data to {}", path),
    );
}

pub fn read_plain(path: String) -> String {
    into_match(
        read_to_string(&path),
        &format!("Error: Could not read {}", path),
    )
}

pub fn read_cipher(path: String) -> (Vec<u8>, Vec<u8>) {
    let mut file = into_match(
        File::open(&path),
        &format!("Error: Could not open {}", path),
    );
    let metadata = into_match(
        File::metadata(&file),
        &format!("Error: Could not read the metadata off of {}", path),
    );
    let mut data: Vec<u8> = vec![0u8; metadata.len() as usize];
    match file.read(&mut data) {
        Ok(_) => (),
        Err(_) => {
            eprintln!("{} Could not read {}", "Error:".bright_red(), path);
            exit(1);
        }
    };

    let mut salt_bytes: Vec<u8> = vec![0u8; 32];
    salt_bytes.clone_from_slice(&data[..32]);
    let mut cypher: Vec<u8> = vec![0u8; (metadata.len() - 32) as usize];
    cypher.clone_from_slice(&data[32..]);

    (salt_bytes, cypher)
}
