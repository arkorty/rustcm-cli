use crate::error::Result;
use std::io::{Read, Write};

/// Open an input source: file or stdin.
pub fn open_input(path: Option<&std::path::Path>) -> Result<Box<dyn Read>> {
    match path {
        Some(p) => Ok(Box::new(std::fs::File::open(p)?)),
        None => Ok(Box::new(std::io::stdin())),
    }
}

/// Open an output sink: file or stdout.
pub fn open_output(path: Option<&std::path::Path>) -> Result<Box<dyn Write>> {
    match path {
        Some(p) => Ok(Box::new(std::fs::File::create(p)?)),
        None => Ok(Box::new(std::io::stdout())),
    }
}
