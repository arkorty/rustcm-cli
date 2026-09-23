use thiserror::Error;

/// Exit codes following Unix convention:
/// 0 = success
/// 1 = general runtime error (I/O, crypto, argon2)
/// 2 = usage error (handled by clap)
/// 3 = authentication failure (wrong password, corrupted, truncated)
/// 4 = user input error (password mismatch, invalid key file)
#[allow(dead_code)]
pub mod exit_code {
    pub const SUCCESS: i32 = 0;
    pub const GENERAL: i32 = 1;
    pub const USAGE: i32 = 2;
    pub const AUTH: i32 = 3;
    pub const USER_INPUT: i32 = 4;
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Crypto(#[from] orion::errors::UnknownCryptoError),

    #[error("{0}")]
    Argon2(String),

    #[error("{0}")]
    InvalidFormat(String),

    #[error("authentication failed: wrong password, corrupted data, or truncated stream")]
    AuthFailed,

    #[error("passwords do not match")]
    PasswordMismatch,

    #[error("invalid key file: expected {0} bytes, got different length")]
    InvalidKeyFile(usize),

    #[error("stream truncated: missing final chunk")]
    StreamTruncated,

    #[error("{0}")]
    InvalidChunkSize(String),

    #[error("{0}")]
    PasswordPrompt(String),
}

impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::AuthFailed | Error::StreamTruncated | Error::InvalidFormat(_) => exit_code::AUTH,
            Error::PasswordMismatch | Error::InvalidKeyFile(_) | Error::PasswordPrompt(_) => {
                exit_code::USER_INPUT
            }
            _ => exit_code::GENERAL,
        }
    }
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Error::Argon2(e.to_string())
    }
}

impl From<passterm::PromptError> for Error {
    fn from(e: passterm::PromptError) -> Self {
        Error::PasswordPrompt(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_maps_to_general_exit() {
        let e: Error = std::io::Error::new(std::io::ErrorKind::NotFound, "x").into();
        assert_eq!(e.exit_code(), exit_code::GENERAL);
    }

    #[test]
    fn auth_failure_exit_code() {
        assert_eq!(Error::AuthFailed.exit_code(), exit_code::AUTH);
    }

    #[test]
    fn stream_truncated_exit_code() {
        assert_eq!(Error::StreamTruncated.exit_code(), exit_code::AUTH);
    }

    #[test]
    fn invalid_format_exit_code() {
        let e = Error::InvalidFormat("x".into());
        assert_eq!(e.exit_code(), exit_code::AUTH);
    }

    #[test]
    fn password_mismatch_exit_code() {
        assert_eq!(Error::PasswordMismatch.exit_code(), exit_code::USER_INPUT);
    }

    #[test]
    fn invalid_key_file_exit_code() {
        let e = Error::InvalidKeyFile(10);
        assert_eq!(e.exit_code(), exit_code::USER_INPUT);
    }

    #[test]
    fn argon2_error_exit_code() {
        let e = Error::Argon2("x".into());
        assert_eq!(e.exit_code(), exit_code::GENERAL);
    }

    #[test]
    fn error_display_messages() {
        assert_eq!(
            Error::AuthFailed.to_string(),
            "authentication failed: wrong password, corrupted data, or truncated stream"
        );
        assert_eq!(
            Error::PasswordMismatch.to_string(),
            "passwords do not match"
        );
        assert_eq!(
            Error::StreamTruncated.to_string(),
            "stream truncated: missing final chunk"
        );
    }
}
