// Program: rustcm-cli (0.1.0-alpha)
// License: GNU GPL version 3
// Author:  Arkaprabha Chakraborty
//
// Copyright (C) 2023 Arkaprabha Chakraborty

use orion::{aead, kdf};
use passterm::read_password;
use std::env::args;
use std::fs::read_to_string;
use std::fs::File;
use std::io::{stdout, Read, Write};
use std::process::exit;

const PROGRAM_NAME: &str = "rustcm-cli";
const PROGRAM_VERSION: &str = "0.1.0-alpha";

pub fn get_password(prompt: &str) -> String {
    print!("{}", prompt);
    into_match(stdout().flush(), "Error: Could not flush date to stdout");
    let password = into_match(read_password(), "Error: Could not read the password");
    println!();

    password
}

pub fn encrypt(plaintext: String, secret_key: orion::kdf::SecretKey) -> Vec<u8> {
    let plaintext = plaintext.into_bytes();
    match aead::seal(&secret_key, &plaintext) {
        Ok(temp) => {
            println!("Success: Data was encrypted");
            temp
        }
        Err(_) => {
            eprintln!("Error: Could not encrypt the data");
            exit(0);
        }
    }
}

pub fn get_secret_key(salt_bytes: [u8; 32], password: String) -> orion::kdf::SecretKey {
    let password = into_match(
        kdf::Password::from_slice(password.as_bytes()),
        "Error: Could not create the password",
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
            eprintln!("Error: Could not generate the random bytes for the salt");
            exit(0);
        }
    };

    salt_bytes
}

pub fn into_match<T, E>(res: Result<T, E>, estr: &str) -> T {
    let ok_val: T = match res {
        Ok(temp) => temp,
        Err(_) => {
            eprintln!("{estr}");
            exit(0)
        }
    };

    ok_val
}

pub fn get_salt(salt_bytes: [u8; 32]) -> orion::kdf::Salt {
    let salt = into_match(
        kdf::Salt::from_slice(&salt_bytes),
        "Error: Could not generate the salt",
    );

    salt
}

pub fn write_plain(path: String, plaintext: String) {
    let mut file = into_match(File::create(&path), "Error: Could not create {path}");
    into_match(
        file.write(&plaintext.into_bytes()),
        "Error: Could not write the data to {path}",
    );
    into_match(file.flush(), "Error: Could not flush data to {path}");
}

pub fn write_cipher(path: String, salt_bytes: [u8; 32], ciphertext: Vec<u8>) {
    let mut file = into_match(File::create(&path), "Error: Could not create {path}");
    into_match(
        file.write(&salt_bytes),
        "Error: Could write the salt to {path}",
    );
    into_match(
        file.write(&ciphertext),
        "Error: Could not write the ciphertext to {path}",
    );
    into_match(file.flush(), "Error: Could not flush data to {path}");
}

pub fn read_plain(path: String) -> String {
    into_match(read_to_string(&path), "Error: Could not read the {path}")
}

pub fn read_cipher(path: String) -> (Vec<u8>, Vec<u8>) {
    let mut file = into_match(File::open(&path), "Error: Could not open {path}");
    let metadata = into_match(
        File::metadata(&file),
        "Error: Could not read the metadata off of {path}",
    );
    let mut data: Vec<u8> = vec![0u8; metadata.len() as usize];
    match file.read(&mut data) {
        Ok(_) => (),
        Err(_) => {
            eprintln!("Error: Could not read {path}");
            exit(0);
        }
    };

    let mut salt_bytes: Vec<u8> = vec![0u8; 32];
    salt_bytes.clone_from_slice(&data[..32]);
    let mut cypher: Vec<u8> = vec![0u8; (metadata.len() - 32) as usize];
    cypher.clone_from_slice(&data[32..]);

    (salt_bytes, cypher)
}

pub fn decrypt(ciphertext: Vec<u8>, secret_key: orion::kdf::SecretKey) -> String {
    let plaintext = match aead::open(&secret_key, &ciphertext) {
        Ok(temp) => {
            println!("Success: Data was decrypted");
            temp
        }
        Err(_) => {
            eprintln!("Error: Failed to decrypt the file, please check the password");
            exit(0);
        }
    };
    String::from_utf8(plaintext).expect("Error: Could not convert to String")
}

pub fn to_array(v: Vec<u8>) -> [u8; 32] {
    let slice = v.as_slice();
    let array: [u8; 32] = match slice.try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            eprintln!(
                "Error: Expected a vector of length {} but it was {}",
                32,
                v.len()
            );
            exit(0);
        }
    };

    array
}

fn main() {
    let mut args = args();
    while args.next() != None {
        let arg_str: String = match args.next() {
            Some(temp) => temp,
            None => exit(0),
        };

        match arg_str.as_str() {
            "--help" | "-h" => {
                match args.next() {
                    Some(_) => {
                        eprintln!("Error: Too many arguments");
                        exit(0);
                    }
                    None => (),
                };

                println!(
                    "{PROGRAM_NAME} {PROGRAM_VERSION}
Rust Simple Text Cipher Machine.

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
                exit(0);
            }

            "--version" | "-v" => {
                match args.next() {
                    Some(_) => {
                        eprintln!("Error: Too many arguments");
                        exit(0);
                    }
                    None => (),
                };

                println!(
                    "rustcm-cli (0.1.0-alpha)
Copyright (C) 2023 Arkaprabha Chakraborty
License GPLv3: GNU GPL version 3
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by Arkaprabha Chakraborty"
                );
                exit(0);
            }
            "--encrypt" | "-e" => {
                let path: String = match args.next() {
                    Some(temp) => temp,
                    None => {
                        eprintln!("Error: Was expecting two arguments but received none");
                        exit(0);
                    }
                };

                let output: String = match args.next() {
                    Some(temp) => temp,
                    None => {
                        eprintln!("Error: Was expecting two arguments but received one");
                        exit(0);
                    }
                };

                match args.next() {
                    Some(_) => {
                        eprintln!("Error: Too many arguments");
                        exit(0);
                    }
                    None => (),
                };

                let plaintext: String = read_plain(path);
                let salt_bytes = get_salt_bytes();
                let password: String = get_password("Password: ");
                let secret_key = get_secret_key(salt_bytes, password);
                let ciphertext = encrypt(plaintext, secret_key);

                write_cipher(output, salt_bytes, ciphertext);

                exit(0);
            }
            "--decrypt" | "-d" => {
                let path: String = match args.next() {
                    Some(temp) => temp,
                    None => {
                        eprintln!("Error: Was expecting two arguments but received none");
                        exit(0);
                    }
                };

                let output: String = match args.next() {
                    Some(temp) => temp,
                    None => {
                        eprintln!("Error: Was expecting two arguments but received one");
                        exit(0);
                    }
                };

                match args.next() {
                    Some(_) => {
                        eprintln!("Error: Too many arguments");
                        exit(0);
                    }
                    None => (),
                };

                let (salt_bytes, ciphertext) = read_cipher(path);
                let salt_bytes: [u8; 32] = to_array(salt_bytes);
                let password: String = get_password("Password: ");
                let secret_key = get_secret_key(salt_bytes, password);
                let plaintext = decrypt(ciphertext, secret_key);

                write_plain(output, plaintext);

                exit(0);
            }
            _ => {
                eprintln!("Error: Unrecognized argument");
                exit(0);
            }
        };
    }
}
