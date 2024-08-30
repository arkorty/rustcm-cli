use colored::Colorize;
use std::env::args;
use std::process::exit;

use rustcm_cli::{
    crypto::{decrypt, encrypt, get_salt_bytes, get_secret_key},
    io::{read_cipher, read_plain, write_cipher, write_plain},
    utils::{get_password, into_match, to_array},
};

const PROGRAM_NAME: &str = "rustcm-cli";
const PROGRAM_VERSION: &str = "0.1.3-alpha";

fn main() {
    let mut args = args();
    args.next();

    let arg_str: String = match args.next() {
        Some(temp) => temp,
        None => {
            eprintln!(
                "{} No arguments provided. Use --help for usage information.",
                "Error:".bright_red()
            );
            exit(1);
        }
    };

    match arg_str.as_str() {
        "--help" | "-h" => handle_help(),
        "--version" | "-v" => handle_version(),
        "--encrypt" | "-e" => handle_encrypt(&mut args),
        "--decrypt" | "-d" => handle_decrypt(&mut args),
        _ => {
            eprintln!("{} Unrecognized argument", "Error:".bright_red());
            exit(1);
        }
    };
}

fn handle_help() {
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

fn handle_version() {
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

fn handle_encrypt(args: &mut std::env::Args) {
    let (path, output) = get_args(args);
    let plaintext: String = read_plain(path);
    let salt_bytes = get_salt_bytes();
    let password: String = get_password("Password: ");
    let secret_key = get_secret_key(salt_bytes, password);
    let ciphertext = encrypt(plaintext, secret_key);
    write_cipher(output, salt_bytes, ciphertext);
    println!(
        "{} Encryption completed successfully",
        "Success:".bright_green()
    );
    exit(0);
}

fn handle_decrypt(args: &mut std::env::Args) {
    let (path, output) = get_args(args);
    let (salt_bytes, ciphertext) = read_cipher(path);
    let salt_bytes: [u8; 32] = to_array(salt_bytes);
    let password: String = get_password("Password: ");
    let secret_key = get_secret_key(salt_bytes, password);
    let plaintext = decrypt(ciphertext, secret_key);
    write_plain(output, plaintext);
    println!(
        "{} Decryption completed successfully",
        "Success:".bright_green()
    );
    exit(0);
}

fn get_args(args: &mut std::env::Args) -> (String, String) {
    let path: String = into_match(
        Err(args.next()),
        "Error: Was expecting two arguments but received none",
    );
    let output: String = into_match(
        Err(args.next()),
        "Error: Was expecting two arguments but received one",
    );
    if args.next().is_some() {
        eprintln!("{} Too many arguments", "Error:".bright_red());
        exit(1);
    }
    (path, output)
}
