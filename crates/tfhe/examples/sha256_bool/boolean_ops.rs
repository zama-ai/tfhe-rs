// This module contains all the operations and functions used in the sha256 function, implemented
// with homomorphic boolean operations. Both the bitwise operations, which serve as the building
// blocks for other functions, and the adders employ parallel processing techniques.

use rayon::prelude::*;
use std::array;
use tfhe::boolean::prelude::{BinaryBooleanGates, Ciphertext, ServerKey};

// Implementation of a Carry Save Adder, which computes sum and carry sequences very efficiently. We
// then add the final sum and carry values to obtain the result. CSAs are useful to speed up
// sequential additions
pub fn csa(
    a: &[Ciphertext; 32],
    b: &[Ciphertext; 32],
    c: &[Ciphertext; 32],
    sk: &ServerKey,
) -> ([Ciphertext; 32], [Ciphertext; 32]) {
    let (carry, sum) = rayon::join(|| maj(a, b, c, sk), || xor(a, &xor(b, c, sk), sk));

    // perform a left shift by one to discard the carry-out and set the carry-in to 0
    let mut shifted_carry = trivial_bools(&[false; 32], sk);
    for (i, elem) in carry.into_iter().enumerate() {
        if i == 0 {
            continue;
        } else {
            shifted_carry[i - 1] = elem;
        }
    }

    (sum, shifted_carry)
}

pub fn add(
    a: &[Ciphertext; 32],
    b: &[Ciphertext; 32],
    ladner_fischer_opt: bool,
    sk: &ServerKey,
) -> [Ciphertext; 32] {
    let (propagate, generate) = rayon::join(|| xor(a, b, sk), || and(a, b, sk));

    let carry = if ladner_fischer_opt {
        ladner_fischer(&propagate, &generate, sk)
    } else {
        brent_kung(&propagate, &generate, sk)
    };

    xor(&propagate, &carry, sk)
}

// Implementation of the Brent Kung parallel prefix algorithm
// This function computes the carry signals in parallel while minimizing the number of homomorphic
// operations
fn brent_kung(
    propagate: &[Ciphertext; 32],
    generate: &[Ciphertext; 32],
    sk: &ServerKey,
) -> [Ciphertext; 32] {
    let mut propagate = propagate.clone();
    let mut generate = generate.clone();

    for d in 0..5 {
        // first 5 stages
        let stride = 1 << d;

        let indices: Vec<(usize, usize)> = (0..32 - stride)
            .rev()
            .step_by(2 * stride)
            .map(|i| i + 1 - stride)
            .enumerate()
            .collect();

        let updates: Vec<(usize, Ciphertext, Ciphertext)> = indices
            .into_par_iter()
            .map(|(n, index)| {
                let new_p;
                let new_g;

                if n == 0 {
                    // grey cell
                    new_p = propagate[index].clone();
                    new_g = sk.or(
                        &generate[index],
                        &sk.and(&generate[index + stride], &propagate[index]),
                    );
                } else {
                    // black cell
                    new_p = sk.and(&propagate[index], &propagate[index + stride]);
                    new_g = sk.or(
                        &generate[index],
                        &sk.and(&generate[index + stride], &propagate[index]),
                    );
                }

                (index, new_p, new_g)
            })
            .collect();

        for (index, new_p, new_g) in updates {
            propagate[index] = new_p;
            generate[index] = new_g;
        }

        if d == 4 {
            let mut cells = 0;
            for d_2 in 0..4 {
                // last 4 stages
                let stride = 1 << (4 - d_2 - 1);
                cells += 1 << d_2;

                let indices: Vec<(usize, usize)> = (0..cells)
                    .map(|cell| (cell, stride + 2 * stride * cell))
                    .collect();

                let updates: Vec<(usize, Ciphertext)> = indices
                    .into_par_iter()
                    .map(|(_, index)| {
                        let new_g = sk.or(
                            &generate[index],
                            &sk.and(&generate[index + stride], &propagate[index]),
                        );

                        (index, new_g)
                    })
                    .collect();

                for (index, new_g) in updates {
                    generate[index] = new_g;
                }
            }
        }
    }

    let mut carry = trivial_bools(&[false; 32], sk);
    carry[..31].clone_from_slice(&generate[1..(31 + 1)]);

    carry
}

// Implementation of the Ladner Fischer parallel prefix algorithm
// This function may perform better than the previous one when many threads are available as it has
// less stages
fn ladner_fischer(
    propagate: &[Ciphertext; 32],
    generate: &[Ciphertext; 32],
    sk: &ServerKey,
) -> [Ciphertext; 32] {
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

                if index < 32 - (2 * stride) {
                    // black cell
                    new_p = sk.and(&propagate[index], &p);
                    new_g = sk.or(&generate[index], &sk.and(&g, &propagate[index]));
                } else {
                    // grey cell
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
    carry[..31].clone_from_slice(&generate[1..(31 + 1)]);

    carry
}

// 2 (homomorphic) bitwise ops
pub fn sigma0(x: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let a = rotate_right(x, 7);
    let b = rotate_right(x, 18);
    let c = shift_right(x, 3, sk);
    xor(&xor(&a, &b, sk), &c, sk)
}

pub fn sigma1(x: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let a = rotate_right(x, 17);
    let b = rotate_right(x, 19);
    let c = shift_right(x, 10, sk);
    xor(&xor(&a, &b, sk), &c, sk)
}

pub fn sigma_upper_case_0(x: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let a = rotate_right(x, 2);
    let b = rotate_right(x, 13);
    let c = rotate_right(x, 22);
    xor(&xor(&a, &b, sk), &c, sk)
}

pub fn sigma_upper_case_1(x: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let a = rotate_right(x, 6);
    let b = rotate_right(x, 11);
    let c = rotate_right(x, 25);
    xor(&xor(&a, &b, sk), &c, sk)
}

// 0 bitwise ops
fn rotate_right(x: &[Ciphertext; 32], n: usize) -> [Ciphertext; 32] {
    let mut result = x.clone();
    result.rotate_right(n);
    result
}

fn shift_right(x: &[Ciphertext; 32], n: usize, sk: &ServerKey) -> [Ciphertext; 32] {
    let mut result = x.clone();
    result.rotate_right(n);
    result[..n].fill_with(|| sk.trivial_encrypt(false));
    result
}

// 1 bitwise op
pub fn ch(
    x: &[Ciphertext; 32],
    y: &[Ciphertext; 32],
    z: &[Ciphertext; 32],
    sk: &ServerKey,
) -> [Ciphertext; 32] {
    mux(x, y, z, sk)
}

// 4 bitwise ops
pub fn maj(
    x: &[Ciphertext; 32],
    y: &[Ciphertext; 32],
    z: &[Ciphertext; 32],
    sk: &ServerKey,
) -> [Ciphertext; 32] {
    let (lhs, rhs) = rayon::join(|| and(x, &xor(y, z, sk), sk), || and(y, z, sk));
    xor(&lhs, &rhs, sk)
}

// Parallelized homomorphic bitwise ops
// Building block for most of the previous functions
fn xor(a: &[Ciphertext; 32], b: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let mut result = a.clone();
    result
        .par_iter_mut()
        .zip(a.par_iter().zip(b.par_iter()))
        .for_each(|(dst, (lhs, rhs))| *dst = sk.xor(lhs, rhs));
    result
}

fn and(a: &[Ciphertext; 32], b: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let mut result = a.clone();
    result
        .par_iter_mut()
        .zip(a.par_iter().zip(b.par_iter()))
        .for_each(|(dst, (lhs, rhs))| *dst = sk.and(lhs, rhs));
    result
}

fn mux(
    condition: &[Ciphertext; 32],
    then: &[Ciphertext; 32],
    otherwise: &[Ciphertext; 32],
    sk: &ServerKey,
) -> [Ciphertext; 32] {
    let mut result = condition.clone();
    result
        .par_iter_mut()
        .zip(
            condition
                .par_iter()
                .zip(then.par_iter().zip(otherwise.par_iter())),
        )
        .for_each(|(dst, (condition, (then, other)))| *dst = sk.mux(condition, then, other));
    result
}

// Trivial encryption of 32 bools
pub fn trivial_bools(bools: &[bool; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    array::from_fn(|i| sk.trivial_encrypt(bools[i]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::boolean::prelude::*;

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
        array::from_fn(|i| ck.encrypt(bools[i]))
    }

    fn decrypt(bools: &[Ciphertext; 32], ck: &ClientKey) -> [bool; 32] {
        array::from_fn(|i| ck.decrypt(&bools[i]))
    }

    #[test]
    fn test_add_modulo_2_32() {
        let (ck, sk) = gen_keys();

        let a = encrypt(
            &to_bool_array([
                0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
                1, 0, 0, 1,
            ]),
            &ck,
        );
        let b = encrypt(
            &to_bool_array([
                0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
                1, 0, 1, 1,
            ]),
            &ck,
        );
        let c = encrypt(
            &to_bool_array([
                0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0,
                1, 1, 0, 0,
            ]),
            &ck,
        );
        let d = encrypt(
            &to_bool_array([
                0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1,
                1, 0, 0, 0,
            ]),
            &ck,
        );
        let e = encrypt(
            &to_bool_array([
                0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0,
                1, 1, 0, 0,
            ]),
            &ck,
        );

        let (sum, carry) = csa(&c, &d, &e, &sk);
        let (sum, carry) = csa(&b, &sum, &carry, &sk);
        let (sum, carry) = csa(&a, &sum, &carry, &sk);
        let output = add(&sum, &carry, false, &sk);

        let result = decrypt(&output, &ck);
        let expected = to_bool_array([
            0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0,
            1, 0, 0,
        ]);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_sigma0() {
        let (ck, sk) = gen_keys();

        let input = encrypt(
            &to_bool_array([
                0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0,
                1, 1, 1, 1,
            ]),
            &ck,
        );
        let output = sigma0(&input, &sk);
        let result = decrypt(&output, &ck);
        let expected = to_bool_array([
            1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1,
            0, 1, 1,
        ]);

        assert_eq!(result, expected);
    } //the other sigmas are implemented in the same way

    #[test]
    fn test_ch() {
        let (ck, sk) = gen_keys();

        let e = encrypt(
            &to_bool_array([
                0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1,
                1, 1, 1, 1,
            ]),
            &ck,
        );
        let f = encrypt(
            &to_bool_array([
                1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0,
                1, 1, 0, 0,
            ]),
            &ck,
        );
        let g = encrypt(
            &to_bool_array([
                0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0,
                1, 0, 1, 1,
            ]),
            &ck,
        );

        let output = ch(&e, &f, &g, &sk);
        let result = decrypt(&output, &ck);
        let expected = to_bool_array([
            0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1,
            1, 0, 0,
        ]);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_maj() {
        let (ck, sk) = gen_keys();

        let a = encrypt(
            &to_bool_array([
                0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0,
                0, 1, 1, 1,
            ]),
            &ck,
        );
        let b = encrypt(
            &to_bool_array([
                1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0,
                0, 1, 0, 1,
            ]),
            &ck,
        );
        let c = encrypt(
            &to_bool_array([
                0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1,
                0, 0, 1, 0,
            ]),
            &ck,
        );

        let output = maj(&a, &b, &c, &sk);
        let result = decrypt(&output, &ck);
        let expected = to_bool_array([
            0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0,
            1, 1, 1,
        ]);

        assert_eq!(result, expected);
    }
}
