use colored::Colorize;
use passterm::prompt_password_tty;
use std::io::stdout;
use std::io::Write;
use std::process::exit;

pub fn get_password(prompt: &str) -> String {
    into_match(stdout().flush(), "Error: Could not flush date to stdout");
    let password = into_match(
        prompt_password_tty(Some(prompt)),
        "Error: Could not read the password",
    );
    password
}

pub fn into_match<T, E>(res: Result<T, E>, estr: &str) -> T {
    match res {
        Ok(temp) => temp,
        Err(_) => {
            eprintln!("{}", estr.bright_red());
            exit(1)
        }
    }
}

pub fn to_array(v: Vec<u8>) -> [u8; 32] {
    let slice = v.as_slice();
    match slice.try_into() {
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
    }
}
