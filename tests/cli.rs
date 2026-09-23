//! CLI integration tests (UAT).
//!
//! These tests exercise the compiled `rscm` binary end-to-end:
//! pipe purity, exit codes, round-trips, tamper/truncation detection.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// Path to the compiled binary under test.
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_rscm")
}

/// A unique temporary directory that is removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rscm-test-{}-{}", label, nanos));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Generate a 32-byte key file. Different `name` values produce different keys.
fn make_key(dir: &TempDir, name: &str) -> PathBuf {
    let path = dir.join(name);
    let seed: u8 = name
        .bytes()
        .fold(0u8, |acc, b| acc.wrapping_add(b).wrapping_mul(31));
    let key: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(seed))
        .collect();
    std::fs::write(&path, &key).unwrap();
    path
}

/// Run the binary with the given args, capturing stdout/stderr.
fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to spawn rscm")
}

/// Run with stdin piped from `input`, capturing stdout/stderr.
fn run_with_stdin(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn rscm");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input)
        .expect("failed to write stdin");
    child.wait_with_output().expect("failed to wait")
}

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

#[test]
fn success_exits_zero() {
    let dir = TempDir::new("exit0");
    let key = make_key(&dir, "key");
    let out = run_with_stdin(&["encrypt", "-k", key.to_str().unwrap()], b"data");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn usage_error_exits_two() {
    let out = run(&["no-such-command"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn io_error_exits_one() {
    // decrypt with missing file → exit 1
    let out = run(&["decrypt", "-i", "/nonexistent/file.rscm"]);
    assert_eq!(out.status.code(), Some(1));

    // encrypt with missing input file + key file → exit 1 (file open fails before prompt)
    let dir = TempDir::new("io1");
    let key = make_key(&dir, "key");
    let out = run(&[
        "encrypt",
        "-i",
        "/nonexistent/file.txt",
        "-k",
        key.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn auth_failure_exits_three() {
    let dir = TempDir::new("exit3");
    let key1 = make_key(&dir, "key1");
    let key2 = make_key(&dir, "key2");

    // Encrypt with key1
    let enc = run_with_stdin(&["encrypt", "-k", key1.to_str().unwrap()], b"secret data");
    assert_eq!(enc.status.code(), Some(0));

    // Decrypt with wrong key → exit 3
    let dec = run_with_stdin(&["decrypt", "-k", key2.to_str().unwrap()], &enc.stdout);
    assert_eq!(
        dec.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&dec.stderr)
    );
}

#[test]
fn truncated_file_exits_three() {
    let dir = TempDir::new("trunc");
    let key = make_key(&dir, "key");

    let enc = run_with_stdin(&["encrypt", "-k", key.to_str().unwrap()], b"some data here");
    assert_eq!(enc.status.code(), Some(0));

    // Truncate the ciphertext
    let truncated = &enc.stdout[..enc.stdout.len().saturating_sub(5)];
    let dec = run_with_stdin(&["decrypt", "-k", key.to_str().unwrap()], truncated);
    assert_eq!(
        dec.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&dec.stderr)
    );
}

#[test]
fn corrupted_data_exits_three() {
    let dir = TempDir::new("corrupt");
    let key = make_key(&dir, "key");

    let mut enc =
        run_with_stdin(&["encrypt", "-k", key.to_str().unwrap()], b"important data").stdout;
    // Flip a byte past the 71-byte header
    let idx = 80;
    if enc.len() > idx {
        enc[idx] ^= 0xFF;
    }
    let dec = run_with_stdin(&["decrypt", "-k", key.to_str().unwrap()], &enc);
    assert_eq!(
        dec.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&dec.stderr)
    );
}

// ---------------------------------------------------------------------------
// stdout purity (Unix philosophy)
// ---------------------------------------------------------------------------

#[test]
fn stdout_contains_only_data_on_encrypt() {
    let dir = TempDir::new("pure-enc");
    let key = make_key(&dir, "key");

    let out = run_with_stdin(&["encrypt", "-k", key.to_str().unwrap()], b"hello");
    assert_eq!(out.status.code(), Some(0));
    assert!(
        out.stderr.is_empty(),
        "stderr should be empty: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // stdout must start with RSCM magic, not any text
    assert_eq!(&out.stdout[0..4], b"RSCM");
    // No printable status text in stdout
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains("Success"), "no status in stdout");
    assert!(!text.contains("encrypted"), "no status in stdout");
}

#[test]
fn stdout_contains_only_data_on_decrypt() {
    let dir = TempDir::new("pure-dec");
    let key = make_key(&dir, "key");

    let enc = run_with_stdin(&["encrypt", "-k", key.to_str().unwrap()], b"hello world");
    let dec = run_with_stdin(&["decrypt", "-k", key.to_str().unwrap()], &enc.stdout);
    assert_eq!(dec.status.code(), Some(0));
    assert!(
        dec.stderr.is_empty(),
        "stderr should be empty: {}",
        String::from_utf8_lossy(&dec.stderr)
    );
    assert_eq!(dec.stdout, b"hello world");
}

#[test]
fn stderr_has_no_ansi_when_not_tty() {
    let dir = TempDir::new("no-ansi");
    let key = make_key(&dir, "key");

    // Force an error; stderr is a pipe (not TTY) in tests → no ANSI escapes.
    let out = run(&["decrypt", "-i", "/nonexistent", "-k", key.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.starts_with("error: "),
        "should use error prefix: {stderr}"
    );
    assert!(
        !stderr.contains('\x1b'),
        "no ANSI escapes when not a TTY: {stderr:?}"
    );
}

#[test]
fn silent_by_default_on_success() {
    let dir = TempDir::new("silent");
    let key = make_key(&dir, "key");

    let enc = run_with_stdin(&["encrypt", "-k", key.to_str().unwrap()], b"data");
    assert!(
        enc.stderr.is_empty(),
        "encrypt stderr: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let dec = run_with_stdin(&["decrypt", "-k", key.to_str().unwrap()], &enc.stdout);
    assert!(
        dec.stderr.is_empty(),
        "decrypt stderr: {}",
        String::from_utf8_lossy(&dec.stderr)
    );
}

// ---------------------------------------------------------------------------
// Round-trips
// ---------------------------------------------------------------------------

#[test]
fn pipe_roundtrip_text() {
    let dir = TempDir::new("pipe-text");
    let key = make_key(&dir, "key");

    let enc = run_with_stdin(&["encrypt", "-k", key.to_str().unwrap()], b"hello world");
    let dec = run_with_stdin(&["decrypt", "-k", key.to_str().unwrap()], &enc.stdout);
    assert_eq!(dec.status.code(), Some(0));
    assert_eq!(dec.stdout, b"hello world");
}

#[test]
fn pipe_roundtrip_binary() {
    let dir = TempDir::new("pipe-bin");
    let key = make_key(&dir, "key");

    // All byte values 0..=255 repeated
    let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let enc = run_with_stdin(&["encrypt", "-k", key.to_str().unwrap()], &data);
    let dec = run_with_stdin(&["decrypt", "-k", key.to_str().unwrap()], &enc.stdout);
    assert_eq!(dec.status.code(), Some(0));
    assert_eq!(dec.stdout, data);
}

#[test]
fn pipe_roundtrip_empty() {
    let dir = TempDir::new("pipe-empty");
    let key = make_key(&dir, "key");

    let enc = run_with_stdin(&["encrypt", "-k", key.to_str().unwrap()], b"");
    assert_eq!(enc.status.code(), Some(0));
    // Header (71) + 4-byte length + empty sealed chunk (Finish tag overhead)
    assert!(enc.stdout.len() > 71);

    let dec = run_with_stdin(&["decrypt", "-k", key.to_str().unwrap()], &enc.stdout);
    assert_eq!(dec.status.code(), Some(0));
    assert_eq!(dec.stdout, b"");
}

#[test]
fn file_roundtrip() {
    let dir = TempDir::new("file-rt");
    let key = make_key(&dir, "key");
    let plain = dir.join("plain.bin");
    let enc_path = dir.join("enc.rscm");
    let dec_path = dir.join("dec.bin");

    let data: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&plain, &data).unwrap();

    let enc = run(&[
        "encrypt",
        "-i",
        plain.to_str().unwrap(),
        "-o",
        enc_path.to_str().unwrap(),
        "-k",
        key.to_str().unwrap(),
    ]);
    assert_eq!(
        enc.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let dec = run(&[
        "decrypt",
        "-i",
        enc_path.to_str().unwrap(),
        "-o",
        dec_path.to_str().unwrap(),
        "-k",
        key.to_str().unwrap(),
    ]);
    assert_eq!(
        dec.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&dec.stderr)
    );

    let result = std::fs::read(&dec_path).unwrap();
    assert_eq!(result, data);
}

#[test]
fn stdin_to_file_and_back() {
    let dir = TempDir::new("stdin-file");
    let key = make_key(&dir, "key");
    let enc_path = dir.join("out.rscm");
    let dec_path = dir.join("back.bin");

    // stdin → file
    let enc = run_with_stdin(
        &[
            "encrypt",
            "-k",
            key.to_str().unwrap(),
            "-o",
            enc_path.to_str().unwrap(),
        ],
        b"streamed content",
    );
    assert_eq!(enc.status.code(), Some(0));
    assert!(enc.stdout.is_empty(), "no stdout when -o is given");

    // file → stdout (pipe)
    let dec = run(&[
        "decrypt",
        "-i",
        enc_path.to_str().unwrap(),
        "-k",
        key.to_str().unwrap(),
    ]);
    assert_eq!(dec.status.code(), Some(0));
    assert_eq!(dec.stdout, b"streamed content");

    // file → file
    let dec2 = run(&[
        "decrypt",
        "-i",
        enc_path.to_str().unwrap(),
        "-o",
        dec_path.to_str().unwrap(),
        "-k",
        key.to_str().unwrap(),
    ]);
    assert_eq!(dec2.status.code(), Some(0));
    assert_eq!(std::fs::read(&dec_path).unwrap(), b"streamed content");
}

#[test]
fn custom_chunk_size_roundtrip() {
    let dir = TempDir::new("chunk");
    let key = make_key(&dir, "key");

    let data: Vec<u8> = (0..10_000u32).map(|i| (i % 256) as u8).collect();
    let enc = run_with_stdin(
        &[
            "encrypt",
            "-k",
            key.to_str().unwrap(),
            "--chunk-size",
            "4096",
        ],
        &data,
    );
    assert_eq!(enc.status.code(), Some(0));
    let dec = run_with_stdin(&["decrypt", "-k", key.to_str().unwrap()], &enc.stdout);
    assert_eq!(dec.status.code(), Some(0));
    assert_eq!(dec.stdout, data);
}

#[test]
fn large_file_roundtrip() {
    let dir = TempDir::new("large");
    let key = make_key(&dir, "key");
    let plain = dir.join("big.bin");
    let enc_path = dir.join("big.enc");
    let dec_path = dir.join("big.dec");

    // 5 MB of pseudo-random data
    let data: Vec<u8> = (0..5_242_880u32)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
        .collect();
    std::fs::write(&plain, &data).unwrap();

    let enc = run(&[
        "encrypt",
        "-i",
        plain.to_str().unwrap(),
        "-o",
        enc_path.to_str().unwrap(),
        "-k",
        key.to_str().unwrap(),
    ]);
    assert_eq!(enc.status.code(), Some(0));

    let dec = run(&[
        "decrypt",
        "-i",
        enc_path.to_str().unwrap(),
        "-o",
        dec_path.to_str().unwrap(),
        "-k",
        key.to_str().unwrap(),
    ]);
    assert_eq!(dec.status.code(), Some(0));

    let result = std::fs::read(&dec_path).unwrap();
    assert_eq!(result.len(), data.len());
    assert_eq!(result, data);
}

// ---------------------------------------------------------------------------
// Ciphertext properties
// ---------------------------------------------------------------------------

#[test]
fn ciphertext_starts_with_rscm_magic() {
    let dir = TempDir::new("magic");
    let key = make_key(&dir, "key");
    let enc = run_with_stdin(&["encrypt", "-k", key.to_str().unwrap()], b"data");
    assert_eq!(&enc.stdout[0..4], b"RSCM");
    // version byte = 1
    assert_eq!(enc.stdout[4], 1);
    // kdf algorithm byte = 1 (Argon2id)
    assert_eq!(enc.stdout[5], 1);
}

#[test]
fn ciphertext_is_larger_than_plaintext() {
    let dir = TempDir::new("overhead");
    let key = make_key(&dir, "key");
    let enc = run_with_stdin(&["encrypt", "-k", key.to_str().unwrap()], b"hi");
    // 71-byte header + 4-byte chunk len + sealed chunk (2 + 16 tag bytes min)
    assert!(enc.stdout.len() > 71 + 4 + 2 + 16);
}

#[test]
fn encryption_is_nondeterministic() {
    let dir = TempDir::new("nondet");
    let key = make_key(&dir, "key");
    let enc1 = run_with_stdin(&["encrypt", "-k", key.to_str().unwrap()], b"same data");
    let enc2 = run_with_stdin(&["encrypt", "-k", key.to_str().unwrap()], b"same data");
    // Fresh random salt + nonce each time → different ciphertext
    assert_ne!(enc1.stdout, enc2.stdout);
}

#[test]
fn rejects_non_rscm_input() {
    let dir = TempDir::new("badmagic");
    let key = make_key(&dir, "key");
    // Must be >= 71 bytes so the header read succeeds and magic validation triggers.
    let mut junk = vec![0x00u8; 71];
    junk[0..4].copy_from_slice(b"NOPE");
    let dec = run_with_stdin(&["decrypt", "-k", key.to_str().unwrap()], &junk);
    assert_eq!(
        dec.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&dec.stderr)
    );
    let stderr = String::from_utf8_lossy(&dec.stderr);
    assert!(stderr.contains("magic"), "should mention magic: {stderr}");
}

// ---------------------------------------------------------------------------
// Help / version
// ---------------------------------------------------------------------------

#[test]
fn help_flag_works() {
    let out = run(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("rscm"));
    assert!(text.contains("encrypt"));
    assert!(text.contains("decrypt"));
    assert!(text.contains("gen-key"));
}

#[test]
fn version_flag_works() {
    let out = run(&["--version"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("0.2.0"));
}

#[test]
fn subcommand_help_works() {
    for sub in ["encrypt", "decrypt", "gen-key"] {
        let out = run(&[sub, "--help"]);
        assert_eq!(out.status.code(), Some(0), "help for {sub}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains(sub), "help text mentions {sub}");
    }
}

#[test]
fn no_verbose_flag() {
    let out = run(&["encrypt", "--help"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains("verbose"), "verbose flag should not exist");
    assert!(!text.contains("quiet"), "quiet flag should not exist");
}

// ---------------------------------------------------------------------------
// Error message format
// ---------------------------------------------------------------------------

#[test]
fn errors_use_error_prefix() {
    let dir = TempDir::new("errfmt");
    let key = make_key(&dir, "key");
    let cases: Vec<(Vec<&str>, i32)> = vec![
        (vec!["decrypt", "-i", "/no/such/file"], 1),
        (
            vec![
                "encrypt",
                "-i",
                "/no/such/file",
                "-k",
                key.to_str().unwrap(),
            ],
            1,
        ),
    ];
    for (args, expected_code) in cases {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(expected_code));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.starts_with("error: "),
            "expected 'error: ' prefix, got: {stderr}"
        );
    }
}
