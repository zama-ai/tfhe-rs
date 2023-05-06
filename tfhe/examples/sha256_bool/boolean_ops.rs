// This module contains all the operations and functions used in the sha256 function, implemented with homomorphic boolean
// operations. Both the bitwise operations, which serve as the building blocks for other functions, and the adders employ
// parallel processing techniques.

use rayon::prelude::*;
use tfhe::boolean::prelude::{BinaryBooleanGates, Ciphertext, ServerKey};

// Implementation of a Carry Save Adder, which computes sum and carry sequences very efficiently. We then add the final
// sum and carry values to obtain the result. CSAs are useful to speed up sequential additions
pub fn csa(a: &[Ciphertext; 32], b: &[Ciphertext; 32], c: &[Ciphertext; 32], sk: &ServerKey) -> ([Ciphertext; 32], [Ciphertext; 32]) {

    let (carry, sum) = rayon::join(
        || {
            maj(&a, &b, &c, sk)
        },
        || {
            xor(&a, &xor(&b, &c, sk), sk)
        },
    );

    // perform a left shift by one to discard the carry-out and set the carry-in to 0
    let mut shifted_carry = trivial_bools(&[false; 32], sk);
    for (i, elem) in carry.into_iter().enumerate() {
        if i == 0 {
            continue;
        } else {
            shifted_carry[i-1] = elem;
        }
    }

    (sum, shifted_carry)
}

pub fn add(a: &[Ciphertext; 32], b: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let (propagate, generate) = rayon::join(
        || xor(a, b, sk),
        || and(a, b, sk)
    );

    #[cfg(feature = "sha256_bool_ladner_fischer")]
    let carry = ladner_fischer(&propagate, &generate, sk);

    #[cfg(not(feature = "sha256_bool_ladner_fischer"))]
    let carry = brent_kung(&propagate, &generate, sk);

    let sum = xor(&propagate, &carry, sk);

    sum
}

// Implementation of the Brent Kung parallel prefix algorithm
// This function computes the carry signals in parallel while minimizing the number of homomorphic operations
#[cfg(not(feature = "sha256_bool_ladner_fischer"))]
fn brent_kung(propagate: &[Ciphertext; 32], generate: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let mut propagate = propagate.clone();
    let mut generate = generate.clone();

    for d in 0..5 { // first 5 stages
        let stride = 1 << d;

        let indices: Vec<(usize, usize)> = (0..32 - stride)
            .rev()
            .step_by(2 * stride)
            .map(|i| i + 1 - stride)
            .enumerate()
            .collect();

        let updates: Vec<(usize, Ciphertext, Ciphertext)> = indices.into_par_iter().map(|(n, index)| {

            let new_p;
            let new_g;

            if n == 0 { // grey cell
                new_p = propagate[index].clone();
                new_g = sk.or(&generate[index], &sk.and(&generate[index + stride], &propagate[index]));

            } else { // black cell
                new_p = sk.and(&propagate[index], &propagate[index + stride]);
                new_g = sk.or(&generate[index], &sk.and(&generate[index + stride], &propagate[index]));
            }

            (index, new_p, new_g)
        }).collect();

        for (index, new_p, new_g) in updates {
            propagate[index] = new_p;
            generate[index] = new_g;
        }

        if d == 4 {
            let mut cells = 0;
            for d_2 in 0..4 { // last 4 stages
                let stride = 1 << (4 - d_2 - 1);
                cells += 1 << d_2;

                let indices: Vec<(usize, usize)> = (0..cells).map(|cell| {
                    (cell, stride + 2*stride*cell)
                }).collect();

                let updates: Vec<(usize, Ciphertext)> = indices.into_par_iter().map(|(_, index)| {
                    let new_g = sk.or(&generate[index], &sk.and(&generate[index+stride], &propagate[index]));

                    (index, new_g)
                }).collect();

                for (index, new_g) in updates {
                    generate[index] = new_g;
                }
            }
        }
    }

    let mut carry = trivial_bools(&[false; 32], sk);
    for bit in 0..31 {
        carry[bit] = generate[bit + 1].clone();
    }

    carry
}

// Implementation of the Ladner Fischer parallel prefix algorithm
// This function may perform better than the previous one when many threads are available as it has less stages
#[cfg(feature = "sha256_bool_ladner_fischer")]
fn ladner_fischer(propagate: &[Ciphertext; 32], generate: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let mut propagate = propagate.clone();
    let mut generate = generate.clone();

    for d in 0..5 {
        let stride = 1 << d;

        let indices: Vec<(usize, usize)> = (0..32 - stride)
            .rev()
            .step_by(2 * stride)
            .flat_map(|i| (0..stride).map(move |count| (i, count)))
            .collect();

        let updates: Vec<(usize, Ciphertext, Ciphertext)> = indices
            .into_par_iter()
            .map(|(i, count)| {
                let index = i - count; // current column

                let p = propagate[i + 1].clone(); // propagate from a previous column
                let g = generate[i + 1].clone(); // generate from a previous column
                let new_p;
                let new_g;

                if index < 32 - (2 * stride) { // black cell
                    new_p = sk.and(&propagate[index], &p);
                    new_g = sk.or(&generate[index], &sk.and(&g, &propagate[index]));

                } else { // grey cell
                    new_p = propagate[index].clone();
                    new_g = sk.or(&generate[index], &sk.and(&g, &propagate[index]));
                }
                (index, new_p, new_g)
            })
            .collect();

        for (index, new_p, new_g) in updates {
            propagate[index] = new_p;
            generate[index] = new_g;
        }
    }

    let mut carry = trivial_bools(&[false; 32], sk);
    for bit in 0..31 {
        carry[bit] = generate[bit + 1].clone();
    }

    carry
}

// 2 (homomorphic) bitwise ops
pub fn sigma0(x: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let a = rotate_right(x, 7, sk);
    let b = rotate_right(x, 18, sk);
    let c = shift_right(x, 3, sk);
    xor(&xor(&a, &b, sk), &c, sk)
}

pub fn sigma1(x: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let a = rotate_right(x, 17, sk);
    let b = rotate_right(x, 19, sk);
    let c = shift_right(x, 10, sk);
    xor(&xor(&a, &b, sk), &c, sk)
}

pub fn sigma_upper_case_0(x: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let a = rotate_right(x, 2, sk);
    let b = rotate_right(x, 13, sk);
    let c = rotate_right(x, 22, sk);
    xor(&xor(&a, &b, sk), &c, sk)
}

pub fn sigma_upper_case_1(x: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let a = rotate_right(x, 6, sk);
    let b = rotate_right(x, 11, sk);
    let c = rotate_right(x, 25, sk);
    xor(&xor(&a, &b, sk), &c, sk)
}

// 0 bitwise ops
fn rotate_right(x: &[Ciphertext; 32], n: usize, sk: &ServerKey) -> [Ciphertext; 32] {
    let mut result = trivial_bools(&[false; 32], sk);
    for i in 0..32 {
        result[(i + n) % 32] = x[i].clone();
    }
    result
}

fn shift_right(x: &[Ciphertext; 32], n: usize, sk: &ServerKey) -> [Ciphertext; 32] {
    let mut result = trivial_bools(&[false; 32], sk);
    for i in 0..(32 - n) {
        result[i + n] = x[i].clone();
    }
    result
}

// 1 bitwise op
pub fn ch(x: &[Ciphertext; 32], y: &[Ciphertext; 32], z: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    mux(x, y, z, sk)
}

// 4 bitwise ops
pub fn maj(x: &[Ciphertext; 32], y: &[Ciphertext; 32], z: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {

    let (lhs, rhs) = rayon::join(
        || and(x, &xor(y, z, sk), sk),
        || and(y, z, sk),
    );
    xor(&lhs, &rhs, sk)
}

// Parallelized homomorphic bitwise ops
// Building block for most of the previous functions
fn xor(a: &[Ciphertext; 32], b: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let result: Vec<Ciphertext> = (0..32)
        .into_par_iter()
        .map(|i| sk.xor(&a[i], &b[i]))
        .collect();

    let mut array = trivial_bools(&[false; 32], sk);
    for (i, elem) in result.into_iter().enumerate() {
        array[i] = elem;
    }

    array
}

fn and(a: &[Ciphertext; 32], b: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {

    let result: Vec<Ciphertext> = (0..32)
        .into_par_iter()
        .map(|i| sk.and(&a[i], &b[i]))
        .collect();

    let mut array = trivial_bools(&[false; 32], sk);
    for (i, elem) in result.into_iter().enumerate() {
        array[i] = elem;
    }

    array
}

fn mux(condition: &[Ciphertext; 32], then: &[Ciphertext; 32], otherwise: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let result: Vec<Ciphertext> = (0..32)
        .into_par_iter()
        .map(|i| sk.mux(&condition[i], &then[i], &otherwise[i]))
        .collect();

    let mut array = trivial_bools(&[false; 32], sk);
    for (i, elem) in result.into_iter().enumerate() {
        array[i] = elem;
    }

    array
}

// Trivial encryption of 32 bools
pub fn trivial_bools(bools: &[bool; 32], sk: &ServerKey) -> [Ciphertext; 32] {

    [
        sk.trivial_encrypt(bools[0]), sk.trivial_encrypt(bools[1]), sk.trivial_encrypt(bools[2]), sk.trivial_encrypt(bools[3]),
        sk.trivial_encrypt(bools[4]), sk.trivial_encrypt(bools[5]), sk.trivial_encrypt(bools[6]), sk.trivial_encrypt(bools[7]),
        sk.trivial_encrypt(bools[8]), sk.trivial_encrypt(bools[9]), sk.trivial_encrypt(bools[10]), sk.trivial_encrypt(bools[11]),
        sk.trivial_encrypt(bools[12]), sk.trivial_encrypt(bools[13]), sk.trivial_encrypt(bools[14]), sk.trivial_encrypt(bools[15]),
        sk.trivial_encrypt(bools[16]), sk.trivial_encrypt(bools[17]), sk.trivial_encrypt(bools[18]), sk.trivial_encrypt(bools[19]),
        sk.trivial_encrypt(bools[20]), sk.trivial_encrypt(bools[21]), sk.trivial_encrypt(bools[22]), sk.trivial_encrypt(bools[23]),
        sk.trivial_encrypt(bools[24]), sk.trivial_encrypt(bools[25]), sk.trivial_encrypt(bools[26]), sk.trivial_encrypt(bools[27]),
        sk.trivial_encrypt(bools[28]), sk.trivial_encrypt(bools[29]), sk.trivial_encrypt(bools[30]), sk.trivial_encrypt(bools[31]),
    ]
}

#[cfg(test)]
mod tests {
    use tfhe::boolean::prelude::*;
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
    fn encrypt(bools: &[bool; 32], ck: &ClientKey) -> [Ciphertext; 32] {
        [
            ck.encrypt(bools[0]), ck.encrypt(bools[1]), ck.encrypt(bools[2]), ck.encrypt(bools[3]),
            ck.encrypt(bools[4]), ck.encrypt(bools[5]), ck.encrypt(bools[6]), ck.encrypt(bools[7]),
            ck.encrypt(bools[8]), ck.encrypt(bools[9]), ck.encrypt(bools[10]), ck.encrypt(bools[11]),
            ck.encrypt(bools[12]), ck.encrypt(bools[13]), ck.encrypt(bools[14]), ck.encrypt(bools[15]),
            ck.encrypt(bools[16]), ck.encrypt(bools[17]), ck.encrypt(bools[18]), ck.encrypt(bools[19]),
            ck.encrypt(bools[20]), ck.encrypt(bools[21]), ck.encrypt(bools[22]), ck.encrypt(bools[23]),
            ck.encrypt(bools[24]), ck.encrypt(bools[25]), ck.encrypt(bools[26]), ck.encrypt(bools[27]),
            ck.encrypt(bools[28]), ck.encrypt(bools[29]), ck.encrypt(bools[30]), ck.encrypt(bools[31]),
        ]
    }
    fn decrypt(bools: &[Ciphertext; 32], ck: &ClientKey) -> [bool; 32] {
        [
            ck.decrypt(&bools[0]), ck.decrypt(&bools[1]), ck.decrypt(&bools[2]), ck.decrypt(&bools[3]),
            ck.decrypt(&bools[4]), ck.decrypt(&bools[5]), ck.decrypt(&bools[6]), ck.decrypt(&bools[7]),
            ck.decrypt(&bools[8]), ck.decrypt(&bools[9]), ck.decrypt(&bools[10]), ck.decrypt(&bools[11]),
            ck.decrypt(&bools[12]), ck.decrypt(&bools[13]), ck.decrypt(&bools[14]), ck.decrypt(&bools[15]),
            ck.decrypt(&bools[16]), ck.decrypt(&bools[17]), ck.decrypt(&bools[18]), ck.decrypt(&bools[19]),
            ck.decrypt(&bools[20]), ck.decrypt(&bools[21]), ck.decrypt(&bools[22]), ck.decrypt(&bools[23]),
            ck.decrypt(&bools[24]), ck.decrypt(&bools[25]), ck.decrypt(&bools[26]), ck.decrypt(&bools[27]),
            ck.decrypt(&bools[28]), ck.decrypt(&bools[29]), ck.decrypt(&bools[30]), ck.decrypt(&bools[31]),
        ]
    }


    #[test]
    fn test_add_modulo_2_32() {
        let (ck, sk) = gen_keys();

        let a = encrypt(&to_bool_array([0,1,0,1,1,0,1,1,1,1,1,0,0,0,0,0,1,1,0,0,1,1,0,1,0,0,0,1,1,0,0,1,]), &ck);
        let b = encrypt(&to_bool_array([0,0,1,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,0,0,1,1,1,0,0,1,0,1,0,1,1,]), &ck);
        let c = encrypt(&to_bool_array([0,0,0,1,1,1,1,1,1,0,0,0,0,1,0,1,1,1,0,0,1,0,0,1,1,0,0,0,1,1,0,0,]), &ck);
        let d = encrypt(&to_bool_array([0,1,0,0,0,0,1,0,1,0,0,0,1,0,1,0,0,0,1,0,1,1,1,1,1,0,0,1,1,0,0,0,]), &ck);
        let e = encrypt(&to_bool_array([0,1,1,0,1,0,0,0,0,1,1,0,0,1,0,1,0,1,1,0,1,1,0,0,0,1,1,0,1,1,0,0,]), &ck);

        let (sum, carry) = csa(&c, &d, &e, &sk);
        let (sum, carry) = csa(&b, &sum, &carry, &sk);
        let (sum, carry) = csa(&a, &sum, &carry, &sk);
        let output = add(&sum, &carry, &sk);

        let result = decrypt(&output, &ck);
        let expected = to_bool_array([0,1,0,1,1,0,1,1,1,1,0,1,1,1,0,1,0,1,0,1,1,0,0,1,1,1,0,1,0,1,0,0,]);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_sigma0() {
        let (ck, sk) = gen_keys();

        let input = encrypt(&to_bool_array([0,1,1,0,1,1,1,1,0,0,1,0,0,0,0,0,0,1,1,1,0,1,1,1,0,1,1,0,1,1,1,1,]), &ck);
        let output = sigma0(&input, &sk);
        let result = decrypt(&output, &ck);
        let expected = to_bool_array([1,1,0,0,1,1,1,0,1,1,1,0,0,0,0,1,1,0,0,1,0,1,0,1,1,1,0,0,1,0,1,1,]);

        assert_eq!(result, expected);
    } //the other sigmas are implemented in the same way

    #[test]
    fn test_ch() {
    let (ck, sk) = gen_keys();

    let e = encrypt(&to_bool_array([0,1,0,1,0,0,0,1,0,0,0,0,1,1,1,0,0,1,0,1,0,0,1,0,0,1,1,1,1,1,1,1,]), &ck);
    let f = encrypt(&to_bool_array([1,0,0,1,1,0,1,1,0,0,0,0,0,1,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,1,0,0,]), &ck);
    let g = encrypt(&to_bool_array([0,0,0,1,1,1,1,1,1,0,0,0,0,0,1,1,1,1,0,1,1,0,0,1,1,0,1,0,1,0,1,1,]), &ck);

    let output = ch(&e, &f, &g, &sk);
    let result = decrypt(&output, &ck);
    let expected = to_bool_array([0,0,0,1,1,1,1,1,1,0,0,0,0,1,0,1,1,1,0,0,1,0,0,1,1,0,0,0,1,1,0,0,]);

    assert_eq!(result, expected);
}

    #[test]
    fn test_maj() {
        let (ck, sk) = gen_keys();

        let a = encrypt(&to_bool_array([0,1,1,0,1,0,1,0,0,0,0,0,1,0,0,1,1,1,1,0,0,1,1,0,0,1,1,0,0,1,1,1,]), &ck);
        let b = encrypt(&to_bool_array([1,0,1,1,1,0,1,1,0,1,1,0,0,1,1,1,1,0,1,0,1,1,1,0,1,0,0,0,0,1,0,1,]), &ck);
        let c = encrypt(&to_bool_array([0,0,1,1,1,1,0,0,0,1,1,0,1,1,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,0,]), &ck);

        let output = maj(&a, &b, &c, &sk);
        let result = decrypt(&output, &ck);
        let expected = to_bool_array([0,0,1,1,1,0,1,0,0,1,1,0,1,1,1,1,1,1,1,0,0,1,1,0,0,1,1,0,0,1,1,1,]);

        assert_eq!(result, expected);
    }
}
