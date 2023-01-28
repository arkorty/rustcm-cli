// Program: rustcm-cli (0.1.0-alpha)
// License: GNU GPL version 3
// Author:  Arkaprabha Chakraborty
//
// Copyright (C) 2023 Arkaprabha Chakraborty

use orion::{aead, kdf};
use passterm;
use std::env::args;
use std::fs::read_to_string;
use std::fs::File;
use std::io::{stdout, Read, Write};

const PROGRAM_NAME: &str = "rustcm-cli";
const PROGRAM_VERSION: &str = "0.1.0-alpha";

pub fn get_password(prompt: &str) -> String {
    print!("{}", prompt);
    stdout().flush().unwrap();
    let password: String = passterm::read_password().unwrap();
    println!();
    password
}

pub fn encrypt(plaintext: String, secret_key: orion::kdf::SecretKey) -> Vec<u8> {
    let plaintext = plaintext.into_bytes();
    let ciphertext: Vec<u8> =
        aead::seal(&secret_key, &plaintext).expect("Error: Could not encrypt the data");

    ciphertext
}

pub fn get_secret_key(presalt: [u8; 32], password: String) -> orion::kdf::SecretKey {
    let password = kdf::Password::from_slice(password.as_bytes()).unwrap();
    let salt = kdf::Salt::from_slice(&presalt).unwrap();
    let secret_key =
        kdf::derive_key(&password, &salt, 3, 8, 32).expect("Error: Could not create secret key");

    secret_key
}

pub fn get_presalt() -> [u8; 32] {
    let mut presalt = [0u8; 32];
    orion::util::secure_rand_bytes(&mut presalt).expect("Error: Could not get presalt");

    presalt
}

pub fn get_salt(presalt: [u8; 32]) -> orion::kdf::Salt {
    let salt = kdf::Salt::from_slice(&presalt).expect("Error: Could not create salt");

    salt
}

pub fn write_plain(path: String, plaintext: String) {
    let mut file = File::create(path).expect("Error: Could not create the file");
    file.write(&plaintext.into_bytes())
        .expect("Error: Could not write_cipher plaintext to the file");
    file.flush().unwrap();
}

pub fn write_cipher(path: String, presalt: [u8; 32], ciphertext: Vec<u8>) {
    let mut file = File::create(path).expect("Error: Could not create the file");
    file.write(&presalt).unwrap();
    file.write(&ciphertext)
        .expect("Error: Could not write_cipher presalt to the file");
    file.flush().unwrap();
}

pub fn read_plain(path: String) -> String {
    read_to_string(path).unwrap()
}

pub fn read_cipher(path: String) -> (Vec<u8>, Vec<u8>) {
    let mut file = File::open(path).expect("Error: Could not open the file");
    let metadata = File::metadata(&file).expect("Error: Could not read the metadata off the file");
    let mut data: Vec<u8> = vec![0u8; metadata.len() as usize];
    file.read(&mut data)
        .expect("Error: Could not read from the file");

    let mut presalt: Vec<u8> = vec![0u8; 32];
    presalt.clone_from_slice(&data[..32]);
    let mut cypher: Vec<u8> = vec![0u8; (metadata.len() - 32) as usize];
    cypher.clone_from_slice(&data[32..]);

    (presalt, cypher)
}

pub fn decrypt(ciphertext: Vec<u8>, secret_key: orion::kdf::SecretKey) -> String {
    let plaintext = match aead::open(&secret_key, &ciphertext) {
        Ok(text) => text,
        Err(_) => panic!("Error: Could not decrypt the file"),
    };

    let plaintext = String::from_utf8(plaintext).expect("Error: Could not convert to String");

    plaintext
}

pub fn convert_to_array<T>(v: Vec<T>) -> [T; 32]
where
    T: Copy,
{
    let slice = v.as_slice();
    let array: [T; 32] = match slice.try_into() {
        Ok(bytes) => bytes,
        Err(_) => panic!(
            "Error: Expected a Vec of length {} but it was {}",
            32,
            v.len()
        ),
    };

    array
}

fn main() {
    let mut args = args();
    while args.next() != None {
        let arg_str = args.next().unwrap();
        if arg_str.eq("--help") || arg_str.eq("-h") {
            println!(
                "{PROGRAM_NAME} {PROGRAM_VERSION}
Rust Simple Text Cipher Machine. Encrypts or decrypts files using the ChaCha20-Poly1305 algorithm.

USAGE:
    rustcm-cli [COMMAND]

COMMAND:
    -h, --help
        Prints this help message

    -v, --version
        Prints the version information

    -e, --encrypt <input-path> <output-path>
        Runs the program in encryption mode.

    -d, --decrypt <input-path> <output-path>
        Runs the program in decryption mode."
            );
        } else if arg_str.eq("--version") || arg_str.eq("-v") {
            println!(
                "rustcm-cli (0.1.0)
Copyright (C) 2023 Arkaprabha Chakraborty
License GPLv3: GNU GPL version 3
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by Arkaprabha Chakraborty"
            )
        }
        if arg_str.eq("--encrypt") || arg_str.eq("-e") {
            let password: String = get_password("Password: ");
            let path: String = args.next().unwrap();
            let output: String = args.next().unwrap();
            let plaintext: String = read_plain(path.clone());
            let presalt = get_presalt();
            let secret_key = get_secret_key(presalt, password.clone());
            let ciphertext = encrypt(plaintext, secret_key);
            write_cipher(output, presalt, ciphertext);
        } else if arg_str.eq("--decrypt") || arg_str.eq("-d") {
            let password: String = get_password("Password: ");
            let path: String = args.next().unwrap();
            let output: String = args.next().unwrap();
            let (presalt, ciphertext) = read_cipher(path.clone());
            let presalt: [u8; 32] = convert_to_array(presalt);
            let secret_key = get_secret_key(presalt, password);
            let plaintext = decrypt(ciphertext, secret_key);
            write_plain(output, plaintext);
        }
    }
}
