use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey};
use crate::shortint::parameters::TestParameters;
use rand::Rng;
use std::fmt::Write;
use std::sync::Arc;

fn encrypt_bits(cks: &RadixClientKey, bits: &[u64]) -> RadixCiphertext {
    RadixCiphertext::from(
        bits.iter()
            .map(|&bit| cks.encrypt_one_block(bit))
            .collect::<Vec<_>>(),
    )
}

fn decrypt_bits(cks: &RadixClientKey, ct: &RadixCiphertext) -> Vec<u8> {
    ct.blocks
        .iter()
        .map(|block| cks.decrypt_one_block(block) as u8)
        .collect()
}

struct KreyviumRef {
    a: Vec<u64>,
    b: Vec<u64>,
    c: Vec<u64>,
    k: Vec<u64>,
    iv: Vec<u64>,
    cursor_a: usize,
    cursor_b: usize,
    cursor_c: usize,
    cursor_k: usize,
    cursor_iv: usize,
}

impl KreyviumRef {
    fn new(key_bits: &[u64], iv_bits: &[u64]) -> Self {
        let mut a = vec![0u64; 93];
        let mut b = vec![0u64; 84];
        let mut c = vec![0u64; 111];
        let mut k = key_bits.to_vec();
        let mut iv = iv_bits.to_vec();

        assert_eq!(k.len(), 128);
        assert_eq!(iv.len(), 128);

        for i in 0..93 {
            a[i] = key_bits[128 - 93 + i];
        }
        for i in 0..84 {
            b[i] = iv_bits[128 - 84 + i];
        }
        for i in 0..44 {
            c[111 - 44 + i] = iv_bits[i];
        }
        for i in 0..66 {
            c[i + 1] = 1;
        }

        k.reverse();
        iv.reverse();

        let mut kreyvium = Self {
            a,
            b,
            c,
            k,
            iv,
            cursor_a: 0,
            cursor_b: 0,
            cursor_c: 0,
            cursor_k: 0,
            cursor_iv: 0,
        };

        for _ in 0..1152 {
            kreyvium.next_bit();
        }

        kreyvium
    }

    fn next_bit(&mut self) -> u8 {
        let idx_a = |cursor: usize, i: usize| -> usize { (93 + cursor - i - 1) % 93 };
        let idx_b = |cursor: usize, i: usize| -> usize { (84 + cursor - i - 1) % 84 };
        let idx_c = |cursor: usize, i: usize| -> usize { (111 + cursor - i - 1) % 111 };
        let idx_k = |cursor: usize, i: usize| -> usize { (128 + cursor - i - 1) % 128 };
        let idx_iv = |cursor: usize, i: usize| -> usize { (128 + cursor - i - 1) % 128 };

        let k_val = self.k[idx_k(self.cursor_k, 127)];
        let iv_val = self.iv[idx_iv(self.cursor_iv, 127)];

        let a1 = self.a[idx_a(self.cursor_a, 65)];
        let a2 = self.a[idx_a(self.cursor_a, 92)];
        let a3 = self.a[idx_a(self.cursor_a, 91)];
        let a4 = self.a[idx_a(self.cursor_a, 90)];
        let a5 = self.a[idx_a(self.cursor_a, 68)];

        let b1 = self.b[idx_b(self.cursor_b, 68)];
        let b2 = self.b[idx_b(self.cursor_b, 83)];
        let b3 = self.b[idx_b(self.cursor_b, 82)];
        let b4 = self.b[idx_b(self.cursor_b, 81)];
        let b5 = self.b[idx_b(self.cursor_b, 77)];

        let c1 = self.c[idx_c(self.cursor_c, 65)];
        let c2 = self.c[idx_c(self.cursor_c, 110)];
        let c3 = self.c[idx_c(self.cursor_c, 109)];
        let c4 = self.c[idx_c(self.cursor_c, 108)];
        let c5 = self.c[idx_c(self.cursor_c, 86)];

        let temp_a = a1 ^ a2;
        let temp_b = b1 ^ b2;
        let temp_c = c1 ^ c2 ^ k_val;

        let new_a = (c3 & c4) ^ a5 ^ temp_c;
        let new_b = (a3 & a4) ^ b5 ^ temp_a ^ iv_val;
        let new_c = (b3 & b4) ^ c5 ^ temp_b;

        let out = temp_a ^ temp_b ^ temp_c;

        self.a[self.cursor_a] = new_a;
        self.cursor_a = (self.cursor_a + 1) % 93;

        self.b[self.cursor_b] = new_b;
        self.cursor_b = (self.cursor_b + 1) % 84;

        self.c[self.cursor_c] = new_c;
        self.cursor_c = (self.cursor_c + 1) % 111;

        self.cursor_k = (self.cursor_k + 1) % 128;
        self.cursor_iv = (self.cursor_iv + 1) % 128;

        out as u8
    }
}

fn bits_to_hex(bits: &[u8]) -> String {
    let mut result = String::new();
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (j, &b) in chunk.iter().enumerate() {
            if b == 1 {
                byte |= 1 << j;
            }
        }
        write!(result, "{byte:02X}").unwrap();
    }
    result
}

fn parse_hex_to_bits(s: &str) -> Vec<u64> {
    let mut bits = Vec::new();
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).unwrap();
        for j in 0..8 {
            bits.push(((byte >> j) & 1) as u64);
        }
    }
    bits
}

/// Tests the Rust reference implementation of Kreyvium against a known test vector.
/// This ensures the logic in `KreyviumRef` is correct before comparing it to FHE.
#[test]
fn test_kreyvium_ref_consistency() {
    let key_hex = "0053A6F94C9FF24598EB000000000000";
    let iv_hex = "0D74DB42A91077DE45AC000000000000";
    let expected_out_hex = "D1F0303482061111";

    let key_bits = parse_hex_to_bits(key_hex);
    let iv_bits = parse_hex_to_bits(iv_hex);

    let mut kreyvium = KreyviumRef::new(&key_bits, &iv_bits);
    let mut output_bits = Vec::new();
    for _ in 0..64 {
        output_bits.push(kreyvium.next_bit());
    }

    let hex_string = bits_to_hex(&output_bits);
    assert_eq!(hex_string, expected_out_hex);
}

/// Tests the full FHE Kreyvium implementation against a known standard test vector.
/// This verifies that the homomorphic circuit produces the exact same hex output as standard
/// Kreyvium.
pub fn kreyvium_test_vector_1_test<P, E>(param: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext, usize),
        crate::Result<RadixCiphertext>,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, 1));
    let sks = Arc::new(sks);
    executor.setup(&cks, sks);

    let key_hex = "0053A6F94C9FF24598EB000000000000";
    let iv_hex = "0D74DB42A91077DE45AC000000000000";
    let expected_out_hex = "D1F0303482061111";

    let key_bits = parse_hex_to_bits(key_hex);
    let iv_bits = parse_hex_to_bits(iv_hex);

    let ct_key = encrypt_bits(&cks, &key_bits);
    let ct_iv = encrypt_bits(&cks, &iv_bits);

    let num_steps = 64;
    let output_radix = executor.execute((&ct_key, &ct_iv, num_steps)).unwrap();

    let decrypted_bits = decrypt_bits(&cks, &output_radix);
    let hex_string = bits_to_hex(&decrypted_bits);

    assert_eq!(hex_string, expected_out_hex);
}

/// Fuzzy comparison test between the FHE Kreyvium implementation and the CPU reference.
/// Runs with random Keys and IVs to ensure general correctness beyond standard test vectors.
pub fn kreyvium_comparison_test<P, E>(param: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext, usize),
        crate::Result<RadixCiphertext>,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, 1));
    let sks = Arc::new(sks);
    executor.setup(&cks, sks);

    let num_runs = 1;
    let num_steps = 64 * 50;

    let mut rng = rand::rng();

    for _ in 0..num_runs {
        let mut key_bits = vec![0u64; 128];
        let mut iv_bits = vec![0u64; 128];

        for i in 0..128 {
            key_bits[i] = rng.gen_range(0..2);
            iv_bits[i] = rng.gen_range(0..2);
        }

        let ct_key = encrypt_bits(&cks, &key_bits);
        let ct_iv = encrypt_bits(&cks, &iv_bits);

        let mut ref_kreyvium = KreyviumRef::new(&key_bits, &iv_bits);
        let mut cpu_output = Vec::with_capacity(num_steps);
        for _ in 0..num_steps {
            cpu_output.push(ref_kreyvium.next_bit());
        }

        let output_radix = executor.execute((&ct_key, &ct_iv, num_steps)).unwrap();
        let fhe_output = decrypt_bits(&cks, &output_radix);

        assert_eq!(fhe_output.len(), cpu_output.len());
        assert_eq!(fhe_output, cpu_output);
    }
}
