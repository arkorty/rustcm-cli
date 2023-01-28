# Rust Simple Text Cipher Machine

### About

It does precisely what the name indicates, i.e., encryption and decryption of files using the ChaCha20-Poly1305 authenticated streaming cipher algorithm. The program is still in its alpha (incomplete) stage.

### Build

* Have Cargo (Rust-langs' package manager) installed.

* `cargo build --release` to build. You will find the program binary in the `./target/release` directory.

### Usage

* `./rustcm-cli --help` prints the help message.

* `./rustcm-cli --version` prints the version information.

* `./rustcm-cli --encrypt <input-path> <output-path>` reads the input file, encrypts the data, and writes to the output file.

* `./rustcm-cli --decrypt <input-path> <output-path>` reads the input file, decrypts the data, and writes to the output file.

### Disclaimer

Do not use this for any high value information. I won't be held accountable for any damage caused to you by this program. Please use at your own discretion.

### License

Distributed under the GPLv3 License. See `LICENSE` for more information.

### Contributors

* [ME](https://github.com/arkorty)
