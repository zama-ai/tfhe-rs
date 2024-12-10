// This module implements the main sha256 homomorphic function using parallel processing when
// possible and some helper functions

use crate::boolean_ops::{
    add, ch, csa, maj, sigma0, sigma1, sigma_upper_case_0, sigma_upper_case_1, trivial_bools,
};
use std::array;
use tfhe::boolean::prelude::*;

pub fn sha256_fhe(
    padded_input: Vec<Ciphertext>,
    ladner_fischer: bool,
    sk: &ServerKey,
) -> Vec<Ciphertext> {
    assert_eq!(
        padded_input.len() % 512,
        0,
        "padded input length is not a multiple of 512"
    );

    // Initialize hash values
    let mut hash: [[Ciphertext; 32]; 8] = [
        trivial_bools(&hex_to_bools(0x6a09e667), sk),
        trivial_bools(&hex_to_bools(0xbb67ae85), sk),
        trivial_bools(&hex_to_bools(0x3c6ef372), sk),
        trivial_bools(&hex_to_bools(0xa54ff53a), sk),
        trivial_bools(&hex_to_bools(0x510e527f), sk),
        trivial_bools(&hex_to_bools(0x9b05688c), sk),
        trivial_bools(&hex_to_bools(0x1f83d9ab), sk),
        trivial_bools(&hex_to_bools(0x5be0cd19), sk),
    ];

    let chunks = padded_input.chunks_exact(512);

    for chunk in chunks {
        // Compute the 64 words
        let mut w = initialize_w(sk);

        for i in 0..16 {
            w[i].clone_from_slice(&chunk[i * 32..(i + 1) * 32]);
        }

        for i in (16..64).step_by(2) {
            let u = i + 1;

            let (word_i, word_u) = rayon::join(
                || {
                    let (s0, s1) = rayon::join(|| sigma0(&w[i - 15], sk), || sigma1(&w[i - 2], sk));

                    let (sum, carry) = csa(&s0, &w[i - 7], &w[i - 16], sk);
                    let (sum, carry) = csa(&s1, &sum, &carry, sk);
                    add(&sum, &carry, ladner_fischer, sk)
                },
                || {
                    let (s0, s1) = rayon::join(|| sigma0(&w[u - 15], sk), || sigma1(&w[u - 2], sk));

                    let (sum, carry) = csa(&s0, &w[u - 7], &w[u - 16], sk);
                    let (sum, carry) = csa(&s1, &sum, &carry, sk);
                    add(&sum, &carry, ladner_fischer, sk)
                },
            );

            w[i] = word_i;
            w[u] = word_u;
        }

        let mut a = hash[0].clone();
        let mut b = hash[1].clone();
        let mut c = hash[2].clone();
        let mut d = hash[3].clone();
        let mut e = hash[4].clone();
        let mut f = hash[5].clone();
        let mut g = hash[6].clone();
        let mut h = hash[7].clone();

        // Compression loop
        for i in 0..64 {
            let (temp1, temp2) = rayon::join(
                || {
                    let ((sum, carry), s1) = rayon::join(
                        || {
                            let ((sum, carry), ch) = rayon::join(
                                || csa(&h, &w[i], &trivial_bools(&hex_to_bools(K[i]), sk), sk),
                                || ch(&e, &f, &g, sk),
                            );
                            csa(&sum, &carry, &ch, sk)
                        },
                        || sigma_upper_case_1(&e, sk),
                    );

                    let (sum, carry) = csa(&sum, &carry, &s1, sk);
                    add(&sum, &carry, ladner_fischer, sk)
                },
                || {
                    add(
                        &sigma_upper_case_0(&a, sk),
                        &maj(&a, &b, &c, sk),
                        ladner_fischer,
                        sk,
                    )
                },
            );

            let (temp_e, temp_a) = rayon::join(
                || add(&d, &temp1, ladner_fischer, sk),
                || add(&temp1, &temp2, ladner_fischer, sk),
            );

            h = g;
            g = f;
            f = e;
            e = temp_e;
            d = c;
            c = b;
            b = a;
            a = temp_a;
        }

        hash[0] = add(&hash[0], &a, ladner_fischer, sk);
        hash[1] = add(&hash[1], &b, ladner_fischer, sk);
        hash[2] = add(&hash[2], &c, ladner_fischer, sk);
        hash[3] = add(&hash[3], &d, ladner_fischer, sk);
        hash[4] = add(&hash[4], &e, ladner_fischer, sk);
        hash[5] = add(&hash[5], &f, ladner_fischer, sk);
        hash[6] = add(&hash[6], &g, ladner_fischer, sk);
        hash[7] = add(&hash[7], &h, ladner_fischer, sk);
    }

    // Concatenate the final hash values to produce a 256-bit hash
    let mut output = vec![];

    for item in &hash {
        for j in item.iter().take(32) {
            output.push(j.clone());
        }
    }

    output
}

// Initialize the 64 words with trivial encryption
fn initialize_w(sk: &ServerKey) -> [[Ciphertext; 32]; 64] {
    array::from_fn(|_| trivial_bools(&[false; 32], sk))
}

// To represent decrypted digest bools as hexadecimal String
pub fn bools_to_hex(bools: Vec<bool>) -> String {
    let mut hex_string = String::new();
    let mut byte = 0u8;
    let mut counter = 0;

    for bit in bools {
        byte <<= 1;
        if bit {
            byte |= 1;
        }

        counter += 1;

        if counter == 8 {
            hex_string.push_str(&format!("{:02x}", byte));
            byte = 0;
            counter = 0;
        }
    }

    // Handle any remaining bits in case the bools vector length is not a multiple of 8
    if counter > 0 {
        byte <<= 8 - counter;
        hex_string.push_str(&format!("{:02x}", byte));
    }

    hex_string
}

// To represent constant values as bool arrays
fn hex_to_bools(hex_value: u32) -> [bool; 32] {
    let mut bool_array = [false; 32];
    let mut mask = 0x8000_0000;

    for item in &mut bool_array {
        *item = (hex_value & mask) != 0;
        mask >>= 1;
    }

    bool_array
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn to_bool_array(arr: [i32; 32]) -> [bool; 32] {
        let mut bool_arr = [false; 32];
        for i in 0..32 {
            if arr[i] == 1 {
                bool_arr[i] = true;
            }
        }
        bool_arr
    }

    #[test]
    fn test_bools_to_hex() {
        let bools = to_bool_array([
            1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            0, 1, 0,
        ]);
        let hex_bools = bools_to_hex(bools.to_vec());

        assert_eq!(hex_bools, "90befffa");
    }

    #[test]
    fn test_hex_to_bools() {
        let hex = 0x428a2f98;
        let result = hex_to_bools(hex);
        let expected = to_bool_array([
            0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1,
            0, 0, 0,
        ]);

        assert_eq!(result, expected);
    }
}
