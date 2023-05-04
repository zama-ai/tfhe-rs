mod padding;
mod boolean_ops;
mod sha256;

use std::io;
use tfhe::boolean::prelude::*;
use padding::pad_sha256_input;
use sha256::{sha256_fhe, bools_to_hex};

fn main() {
    // INTRODUCE INPUT FROM STDIN

    let mut input = String::new();
    println!("Write input to hash:");

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    input = input.trim_end_matches('\n').to_string();

    println!("You entered: \"{}\"", input);

    // CLIENT PADS DATA AND ENCRYPTS IT

    let (ck, sk) = gen_keys();

    let padded_input = pad_sha256_input(&input);
    let encrypted_input = encrypt_bools(&padded_input, &ck);

    // SERVER COMPUTES OVER THE ENCRYPTED PADDED DATA

    println!("Computing the hash");
    let encrypted_output = sha256_fhe(encrypted_input, &sk);

    // CLIENT DECRYPTS THE OUTPUT

    let output = decrypt_bools(&encrypted_output, &ck);
    let outhex = bools_to_hex(output);

    println!("{}", outhex);
}

fn encrypt_bools(bools: &Vec<bool>, ck: &ClientKey) -> Vec<Ciphertext> {
    let mut ciphertext = vec![];

    for bool in bools {
        ciphertext.push(ck.encrypt(*bool));
    }
    ciphertext
}

fn decrypt_bools(ciphertext: &Vec<Ciphertext>, ck: &ClientKey) -> Vec<bool> {
    let mut bools = vec![];

    for cipher in ciphertext {
        bools.push(ck.decrypt(&cipher));
    }
    bools
}
