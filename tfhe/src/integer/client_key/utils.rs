use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct RadixDecomposition {
    pub msg_space: usize,
    pub block_number: usize,
}

/// Computes possible radix decompositions
///
/// Takes the number of bit of the message space as input and output a vector containing all the
/// correct
/// possible block decomposition assuming the same message space for all blocks.
/// Lower and upper bounds define the minimal and maximal space to be considered
/// Example: 6,2,4 -> \[\[2,3\], \[3,2\]\] : \[msg_space = 2 bits, block_number = 3\]
///
/// # Example
///
/// ```rust
/// use tfhe::integer::client_key::radix_decomposition;
/// let input_space = 16;
/// let min = 2;
/// let max = 4;
/// let decomp = radix_decomposition(input_space, min, max);
///
/// // Check that 3 possible radix decompositions are provided
/// assert_eq!(decomp.len(), 3);
/// ```
pub fn radix_decomposition(
    input_space: usize,
    min_space: usize,
    max_space: usize,
) -> Vec<RadixDecomposition> {
    let mut out: Vec<RadixDecomposition> = vec![];
    let max = if max_space > input_space {
        input_space
    } else {
        max_space
    };
    for msg_space in min_space..max + 1 {
        let mut block_number = input_space / msg_space;
        //Manual ceil of the division
        if input_space % msg_space != 0 {
            block_number += 1;
        }
        out.push(RadixDecomposition {
            msg_space,
            block_number,
        });
    }
    out
}

// Tools to compute the inverse Chinese Remainder Theorem
pub(crate) fn extended_euclid(f: i64, g: i64) -> (usize, Vec<i64>, Vec<i64>, Vec<i64>, Vec<i64>) {
    let mut s: Vec<i64> = vec![1, 0];
    let mut t: Vec<i64> = vec![0, 1];
    let mut r: Vec<i64> = vec![f, g];
    let mut q: Vec<i64> = vec![0];
    let mut i = 1;
    while r[i] != 0 {
        q.push(r[i - 1] / r[i]); //q[i]
        r.push(r[i - 1] - q[i] * r[i]); //r[i+1]
        s.push(s[i - 1] - q[i] * s[i]); //s[i+1]
        t.push(t[i - 1] - q[i] * t[i]); //t[i+1]
        i += 1;
    }
    let l: usize = i - 1;
    (l, r, s, t, q)
}

pub(crate) fn i_crt(modulus: &[u64], val: &[u64]) -> u64 {
    let big_mod = modulus.iter().product::<u64>();
    let mut c: Vec<u64> = vec![0; val.len()];
    let mut out: u64 = 0;

    for i in 0..val.len() {
        let tmp_mod = big_mod / modulus[i];
        let (l, _, s, _, _) = extended_euclid(tmp_mod as i64, modulus[i] as i64);
        let sl: u64 = if s[l] < 0 {
            //a is positive
            (s[l] % modulus[i] as i64 + modulus[i] as i64) as u64
        } else {
            s[l] as u64
        };
        c[i] = val[i].wrapping_mul(sl);
        c[i] %= modulus[i];

        out = out.wrapping_add(c[i] * tmp_mod);
    }
    out % big_mod
}
