use crate::error::Result;
use passterm::prompt_password_tty;

const PASSWORD_PROMPT: &str = "Password: ";
const CONFIRM_PROMPT: &str = "Confirm password: ";

fn read_password(prompt: &str) -> Result<String> {
    Ok(prompt_password_tty(Some(prompt))?)
}

pub fn read_password_single() -> Result<String> {
    read_password(PASSWORD_PROMPT)
}

pub fn read_password_double() -> Result<String> {
    let pass1 = read_password(PASSWORD_PROMPT)?;
    let pass2 = read_password(CONFIRM_PROMPT)?;
    if pass1 != pass2 {
        return Err(crate::error::Error::PasswordMismatch);
    }
    Ok(pass1)
}
