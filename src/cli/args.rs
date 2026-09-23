use clap::Subcommand;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt data (stdin to stdout by default)
    Encrypt {
        #[arg(short = 'i', long = "input", value_name = "FILE")]
        input: Option<PathBuf>,

        #[arg(short = 'o', long = "output", value_name = "FILE")]
        output: Option<PathBuf>,

        #[arg(short = 'k', long = "key-file", value_name = "FILE")]
        key_file: Option<PathBuf>,

        #[arg(long = "chunk-size", default_value_t = 65536)]
        chunk_size: usize,

        #[arg(long = "memory-kib", default_value_t = 65536)]
        memory_kib: u32,

        #[arg(long = "iterations", default_value_t = 3)]
        iterations: u32,

        #[arg(long = "parallelism", default_value_t = 1)]
        parallelism: u32,
    },

    /// Decrypt data (stdin to stdout by default)
    Decrypt {
        #[arg(short = 'i', long = "input", value_name = "FILE")]
        input: Option<PathBuf>,

        #[arg(short = 'o', long = "output", value_name = "FILE")]
        output: Option<PathBuf>,

        #[arg(short = 'k', long = "key-file", value_name = "FILE")]
        key_file: Option<PathBuf>,
    },

    /// Generate a key file from a password
    GenKey {
        #[arg(short = 'o', long = "output", value_name = "FILE")]
        output: PathBuf,

        #[arg(long = "memory-kib", default_value_t = 65536)]
        memory_kib: u32,

        #[arg(long = "iterations", default_value_t = 3)]
        iterations: u32,

        #[arg(long = "parallelism", default_value_t = 1)]
        parallelism: u32,
    },
}

#[derive(Debug, clap::Parser)]
#[command(
    name = "rscm",
    version = "0.2.0",
    about = "Rust Simple Cipher Machine - streaming authenticated encryption"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}
