// Program: rustcm-cli (0.1.3-alpha)
// License: GNU GPL version 3
// Author:  Arkaprabha Chakraborty
//
// Copyright (C) 2023 Arkaprabha Chakraborty

use colored::Colorize;
use orion::{aead, kdf};
use passterm::prompt_password_tty;
use std::env::args;
use std::fs::{read_to_string, File};
use std::io::{stdout, Read, Write};
use std::process::exit;

const PROGRAM_NAME: &str = "rustcm-cli";
const PROGRAM_VERSION: &str = "0.1.3-alpha";

pub fn get_password(prompt: &str) -> String {
    into_match(
        stdout().flush(),
        format!("{} Could not flush date to stdout", "Error".bright_red()).as_str(),
    );
    let password = into_match(
        prompt_password_tty(Some(prompt)),
        format!("{} Could not read the password", "Error".bright_red()).as_str(),
    );
    //println!();

    password
}

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

pub fn get_secret_key(salt_bytes: [u8; 32], password: String) -> orion::kdf::SecretKey {
    let password = into_match(
        kdf::Password::from_slice(password.as_bytes()),
        format!("{} Could not use the password", "Error:".bright_red()).as_str(),
    );
    let salt = into_match(
        kdf::Salt::from_slice(&salt_bytes),
        format!("{} Could not create the salt", "Error:".bright_red()).as_str(),
    );
    into_match(
        kdf::derive_key(&password, &salt, 3, 8, 32),
        format!(
            "{} Could not generate the secret key",
            "Error:".bright_red()
        )
        .as_str(),
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

pub fn into_match<T, E>(res: Result<T, E>, estr: &str) -> T {
    let ok_val: T = match res {
        Ok(temp) => temp,
        Err(_) => {
            eprintln!("{estr}");
            exit(1)
        }
    };

    ok_val
}

pub fn get_salt(salt_bytes: [u8; 32]) -> orion::kdf::Salt {
    let salt = into_match(
        kdf::Salt::from_slice(&salt_bytes),
        format!("{} Could not generate the salt", "Error:".bright_red()).as_str(),
    );

    salt
}

pub fn write_plain(path: String, plaintext: String) {
    let mut file = into_match(
        File::create(&path),
        format!("{} Could not create {path}", "Error".bright_red()).as_str(),
    );
    into_match(
        file.write(&plaintext.into_bytes()),
        format!(
            "{} Could not write the data to {path}",
            "Error".bright_red()
        )
        .as_str(),
    );
    into_match(
        file.flush(),
        format!("{} Could not flush data to {path}", "Error".bright_red()).as_str(),
    );
}

pub fn write_cipher(path: String, salt_bytes: [u8; 32], ciphertext: Vec<u8>) {
    let mut file = into_match(
        File::create(&path),
        format!("{} Could not create {path}", "Error".bright_red()).as_str(),
    );
    into_match(
        file.write(&salt_bytes),
        format!("{} Could write the salt to {path}", "Error".bright_red()).as_str(),
    );
    into_match(
        file.write(&ciphertext),
        format!(
            "{} Could not write the ciphertext to {path}",
            "Error:".bright_red()
        )
        .as_str(),
    );
    into_match(
        file.flush(),
        format!("{} Could not flush data to {path}", "Error:".bright_red()).as_str(),
    );
}

pub fn read_plain(path: String) -> String {
    into_match(
        read_to_string(&path),
        format!("{} Could not read {path}", "Error:".bright_red()).as_str(),
    )
}

pub fn read_cipher(path: String) -> (Vec<u8>, Vec<u8>) {
    let mut file = into_match(
        File::open(&path),
        format!("{} Could not open {path}", "Error:".bright_red()).as_str(),
    );
    let metadata = into_match(
        File::metadata(&file),
        format!(
            "{} Could not read the metadata off of {path}",
            "Error:".bright_red()
        )
        .as_str(),
    );
    let mut data: Vec<u8> = vec![0u8; metadata.len() as usize];
    match file.read(&mut data) {
        Ok(_) => (),
        Err(_) => {
            eprintln!("{} Could not read {path}", "Error:".bright_red());
            exit(1);
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

pub fn to_array(v: Vec<u8>) -> [u8; 32] {
    let slice = v.as_slice();
    let array: [u8; 32] = match slice.try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            eprintln!(
                "{} Expected a vector of length {} but it was {}",
                "Error:".bright_red(),
                32,
                v.len()
            );
            exit(1);
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
                        eprintln!("{} Too many arguments", "Error:".bright_red());
                        exit(1);
                    }
                    None => (),
                };

                println!(
                    "{} {}
Rust Simple Text Cipher Machine.

USAGE:
    {} [COMMAND]

COMMAND:
    {}, {}
        Prints this help message

    {}, {}
        Prints the version information

    {}, {} {} {}
        Runs the program in encryption mode

    {}, {} {} {}
        Runs the program in decryption mode",
                    PROGRAM_NAME.bright_yellow(),
                    PROGRAM_VERSION.bright_blue(),
                    PROGRAM_NAME.bright_yellow(),
                    "-h".bright_cyan(),
                    "--help".bright_cyan(),
                    "-v".bright_cyan(),
                    "--version".bright_cyan(),
                    "-e".bright_cyan(),
                    "--encrypt".bright_cyan(),
                    "<path-to-input>".bright_magenta(),
                    "<path-to-output>".bright_magenta(),
                    "-d".bright_cyan(),
                    "--decrypt".bright_cyan(),
                    "<path-to-input>".bright_magenta(),
                    "<path-to-output>".bright_magenta(),
                );
                exit(0);
            }

            "--version" | "-v" => {
                match args.next() {
                    Some(_) => {
                        eprintln!("{} Too many arguments", "Error:".bright_red());
                        exit(1);
                    }
                    None => (),
                };

                println!(
                    "{} ({})
Copyright (C) 2023 Arkaprabha Chakraborty
License GPLv3: GNU GPL version 3
This is free software: you are free to change and redistribute it.
There is {}, to the extent permitted by law.

Written by Arkaprabha Chakraborty",
                    PROGRAM_NAME.bright_yellow(),
                    PROGRAM_VERSION.bright_blue(),
                    "NO WARRANTY".bright_red()
                );
                exit(0);
            }
            "--encrypt" | "-e" => {
                let path: String = match args.next() {
                    Some(temp) => temp,
                    None => {
                        eprintln!(
                            "{} Was expecting two arguments but received none",
                            "Error:".bright_red()
                        );
                        exit(1);
                    }
                };

                let output: String = match args.next() {
                    Some(temp) => temp,
                    None => {
                        eprintln!(
                            "{} Was expecting two arguments but received one",
                            "Error:".bright_red()
                        );
                        exit(1);
                    }
                };

                match args.next() {
                    Some(_) => {
                        eprintln!("{} Too many arguments", "Error:".bright_red());
                        exit(1);
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
                        eprintln!(
                            "{} Was expecting two arguments but received none",
                            "Error:".bright_red()
                        );
                        exit(1);
                    }
                };

                let output: String = match args.next() {
                    Some(temp) => temp,
                    None => {
                        eprintln!(
                            "{} Was expecting two arguments but received one",
                            "Error:".bright_red()
                        );
                        exit(1);
                    }
                };

                match args.next() {
                    Some(_) => {
                        eprintln!("{} Too many arguments", "Error:".bright_red());
                        exit(1);
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
                eprintln!("{} Unrecognized argument", "Error:".bright_red());
                exit(1);
            }
        };
    }
}
