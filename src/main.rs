use clap::Parser;
use rscm::cli::args::{Cli, Command};
use rscm::cli::output;
use rscm::crypto::format::{read_header, write_header, FileHeader};
use rscm::crypto::kdf::{derive_key, generate_salt, KEY_LEN, SALT_LEN};
use rscm::crypto::keyfile::KeyFile;
use rscm::crypto::streaming::decrypt_stream;
use rscm::io::{open_input, open_output};
use rscm::password::prompt::{read_password_double, read_password_single};
use std::io::{Read, Write};
use std::path::PathBuf;

struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Encrypt {
            input,
            output,
            key_file,
            chunk_size,
            memory_kib,
            iterations,
            parallelism,
        } => run_encrypt(
            input,
            output,
            key_file,
            chunk_size,
            KdfParams {
                memory_kib,
                iterations,
                parallelism,
            },
        ),
        Command::Decrypt {
            input,
            output,
            key_file,
        } => run_decrypt(input, output, key_file),
        Command::GenKey {
            output,
            memory_kib,
            iterations,
            parallelism,
        } => run_gen_key(
            output,
            KdfParams {
                memory_kib,
                iterations,
                parallelism,
            },
        ),
    };

    if let Err(e) = result {
        output::error(e.to_string());
        std::process::exit(e.exit_code());
    }
}

fn resolve_key(
    key_file: &Option<PathBuf>,
    salt: Option<&[u8; SALT_LEN]>,
    kdf: &KdfParams,
    double: bool,
) -> rscm::error::Result<[u8; KEY_LEN]> {
    if let Some(path) = key_file {
        let mut file = std::fs::File::open(path)?;
        let mut key = [0u8; KEY_LEN];
        file.read_exact(&mut key)?;
        if file.read(&mut [0u8; 1])? != 0 {
            return Err(rscm::error::Error::InvalidKeyFile(0));
        }
        Ok(key)
    } else {
        let password = if double {
            read_password_double()?
        } else {
            read_password_single()?
        };
        let salt = salt.ok_or(rscm::error::Error::InvalidFormat(
            "missing salt for password derivation".into(),
        ))?;
        let key = derive_key(
            password.as_bytes(),
            salt,
            kdf.memory_kib,
            kdf.iterations,
            kdf.parallelism,
        )?;
        Ok(*key)
    }
}

fn run_encrypt(
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    key_file: Option<PathBuf>,
    chunk_size: usize,
    kdf: KdfParams,
) -> rscm::error::Result<()> {
    let salt = generate_salt()?;
    let key = resolve_key(&key_file, Some(&salt), &kdf, true)?;

    let mut reader = open_input(input.as_deref())?;
    let mut writer = open_output(output.as_deref())?;

    use orion::aead::streaming::{StreamSealer, StreamTag};
    use orion::aead::SecretKey;

    let secret_key = SecretKey::from_slice(&key)?;
    let (mut sealer, nonce) = StreamSealer::new(&secret_key)?;

    let header = FileHeader {
        version: 1,
        kdf_algorithm: 1,
        memory_kib: kdf.memory_kib,
        iterations: kdf.iterations,
        parallelism: kdf.parallelism,
        salt,
        nonce,
    };
    write_header(&mut writer, &header)?;

    // Double-buffered streaming: seal `curr` while `next` holds freshly read data.
    let mut buf_a = vec![0u8; chunk_size];
    let mut buf_b = vec![0u8; chunk_size];
    let (mut curr, mut next): (&mut [u8], &mut [u8]) = (&mut buf_a, &mut buf_b);

    let mut curr_n = reader.read(curr)?;

    if curr_n == 0 {
        let sealed = sealer.seal_chunk(&[], &StreamTag::Finish)?;
        writer.write_all(&(sealed.len() as u32).to_le_bytes())?;
        writer.write_all(&sealed)?;
    } else {
        loop {
            let next_n = reader.read(next)?;
            let tag = if next_n == 0 {
                StreamTag::Finish
            } else {
                StreamTag::Message
            };
            let sealed = sealer.seal_chunk(&curr[..curr_n], &tag)?;
            writer.write_all(&(sealed.len() as u32).to_le_bytes())?;
            writer.write_all(&sealed)?;
            if tag == StreamTag::Finish {
                break;
            }
            std::mem::swap(&mut curr, &mut next);
            curr_n = next_n;
        }
    }
    writer.flush()?;
    Ok(())
}

fn run_decrypt(
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    key_file: Option<PathBuf>,
) -> rscm::error::Result<()> {
    let mut reader = open_input(input.as_deref())?;

    let mut header_buf = [0u8; 71];
    reader.read_exact(&mut header_buf)?;
    let mut header_cursor = std::io::Cursor::new(&header_buf);
    let header = read_header(&mut header_cursor)?;

    let kdf = KdfParams {
        memory_kib: header.memory_kib,
        iterations: header.iterations,
        parallelism: header.parallelism as u32,
    };
    let key = resolve_key(&key_file, Some(&header.salt), &kdf, false)?;

    let mut writer = open_output(output.as_deref())?;

    decrypt_stream(&mut *reader, &mut *writer, &key, &header.nonce)
        .map_err(|_| rscm::error::Error::AuthFailed)?;
    Ok(())
}

fn run_gen_key(output_path: PathBuf, kdf: KdfParams) -> rscm::error::Result<()> {
    let password = read_password_double()?;
    // gen-key writes the raw derived key; a random salt is used for derivation
    // but is not needed later since the key file stores the final key directly.
    let salt = generate_salt()?;
    let key = derive_key(
        password.as_bytes(),
        &salt,
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
    )?;

    let mut file = std::fs::File::create(&output_path)?;
    KeyFile::write(&mut file, &key)?;
    file.flush()?;
    Ok(())
}
