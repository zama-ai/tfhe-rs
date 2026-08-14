//! Test compatibility between x86_64 and wasm one-time-pad transciphering
//!
//! - Generate a pad server-side with the OPRF and decrypt it in rust
//! - Load the pad in js, encrypt a few inputs of different widths with it
//! - Load the stream ciphertexts in rust, transcipher them and check the values
//!
//! This is mimics the production input flow, minus the parties: a single process here holds
//! both the client key and the server key, so it plays the KMS (releasing the
//! decrypted pad) as well as the coprocessor (transciphering the inputs). In
//! production those are distinct, and the pad reaches the client encrypted under
//! its own public key.
//!
//! What this pins down is that bit `i` of the pad as decrypted on x86 is bit `i`
//! of the pad as consumed by the wasm cipher. A disagreement there would not
//! fail loudly, it would transcipher into a well-formed but wrong ciphertext.

#![cfg(feature = "integer")]

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::shortint::parameters::TranscipheringParameters;
use tfhe::{
    generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint12, FheUint64, HlTranscipherer,
    OneTimePadFheSecretMask, Seed, StreamCiphertext, TranscipherSession,
};

const SIZE_LIMIT: u64 = 1024 * 1024 * 1024;

/// 16 bytes, enough for the 64 + 12 + 1 bits the client consumes below.
const PAD_BITS: u64 = 128;

/// Asymmetric values, so a byte- or bit-order mistake cannot round-trip by luck.
/// Kept in sync with `index.js`.
const CLEAR_A: u64 = 0xDEAD_BEEF_CAFE_BABE;
const CLEAR_B: u16 = 0x0A5C;
const CLEAR_C: bool = true;

fn encrypt_inputs_in_wasm(path: &Path) {
    println!("Encrypting inputs in wasm");
    let mut child = Command::new("node")
        .arg("index.js")
        .current_dir(path)
        .spawn()
        .expect("Failed to run node script");

    let exit_status = child.wait().unwrap();
    if let Some(exit_code) = exit_status.code() {
        if exit_code == 0 {
            return;
        }
    }

    panic!("node script returned a non-0 code.");
}

fn read_stream_ciphertext(path: &Path, name: &str) -> StreamCiphertext {
    let mut f = File::open(path.join(name)).unwrap();
    safe_deserialize(&mut f, SIZE_LIMIT).unwrap()
}

#[test]
fn test_transciphering_compat_with_wasm() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut test_path = PathBuf::from(manifest_dir);
    test_path.push("tests");
    test_path.push("transciphering_wasm_x86_test");

    println!("Generating keys");
    let (client_key, server_key) = generate_keys(
        ConfigBuilder::default().enable_transciphering(TranscipheringParameters::SameAsCompute),
    );
    set_server_key(server_key);

    println!("Generating pad with the OPRF");
    let fhe_mask = OneTimePadFheSecretMask::random(Seed(0), PAD_BITS).unwrap();
    let plain_mask = fhe_mask.decrypt(&client_key);

    let mut f_pad = File::create(test_path.join("pad.bin")).unwrap();
    safe_serialize(&plain_mask, &mut f_pad, SIZE_LIMIT).unwrap();

    encrypt_inputs_in_wasm(&test_path);

    let input_a = read_stream_ciphertext(&test_path, "input_a.bin");
    let input_b = read_stream_ciphertext(&test_path, "input_b.bin");
    let input_c = read_stream_ciphertext(&test_path, "input_c.bin");

    // The counters must be exactly where the client left them, since all three
    // inputs were drawn from one pad in order.
    assert_eq!(input_a.encryption_counter(), 0);
    assert_eq!(input_b.encryption_counter(), 64);
    assert_eq!(input_c.encryption_counter(), 76); // Clear b is encrypted as FheUint12

    println!("Transciphering");
    let mut session = TranscipherSession::one_time_pad(fhe_mask).unwrap();
    let out_a: FheUint64 = session.transcipher(&input_a).unwrap();
    let out_b: FheUint12 = session.transcipher(&input_b).unwrap();
    let out_c: FheBool = session.transcipher(&input_c).unwrap();

    let dec_a: u64 = out_a.decrypt(&client_key);
    let dec_b: u16 = out_b.decrypt(&client_key);
    let dec_c: bool = out_c.decrypt(&client_key);

    assert_eq!(dec_a, CLEAR_A);
    assert_eq!(dec_b, CLEAR_B);
    assert_eq!(dec_c, CLEAR_C);
    println!("transciphering matched the values encrypted in wasm");
}
