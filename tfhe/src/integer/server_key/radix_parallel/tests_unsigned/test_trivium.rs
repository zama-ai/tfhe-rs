use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey};
use crate::shortint::parameters::TestParameters;
use rand::Rng;
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

struct TriviumRef {
    a: Vec<u8>,
    b: Vec<u8>,
    c: Vec<u8>,
}

impl TriviumRef {
    fn new(key: &[u8], iv: &[u8]) -> Self {
        let mut a = vec![0u8; 93];
        let mut b = vec![0u8; 84];
        let mut c = vec![0u8; 111];

        for i in 0..80 {
            a[i] = key[79 - i];
            b[i] = iv[79 - i];
        }

        c[108] = 1;
        c[109] = 1;
        c[110] = 1;

        let mut triv = Self { a, b, c };
        for _ in 0..(18 * 64) {
            triv.next();
        }
        triv
    }

    fn next(&mut self) -> u8 {
        let t1 = self.a[65] ^ self.a[92];
        let t2 = self.b[68] ^ self.b[83];
        let t3 = self.c[65] ^ self.c[110];

        let out = t1 ^ t2 ^ t3;

        let a_in = t3 ^ self.a[68] ^ (self.c[108] & self.c[109]);
        let b_in = t1 ^ self.b[77] ^ (self.a[90] & self.a[91]);
        let c_in = t2 ^ self.c[86] ^ (self.b[81] & self.b[82]);

        self.a.pop();
        self.a.insert(0, a_in);
        self.b.pop();
        self.b.insert(0, b_in);
        self.c.pop();
        self.c.insert(0, c_in);

        out
    }
}

#[test]
fn test_trivium_ref_consistency() {
    let key = vec![0u8; 80];
    let iv = vec![0u8; 80];

    let expected_hex = "FBE0BF265859051B";

    let mut trivium = TriviumRef::new(&key, &iv);
    let mut output_bits = Vec::new();
    for _ in 0..64 {
        output_bits.push(trivium.next());
    }

    let packed = get_hexadecimal_string_from_lsb_first_stream(&output_bits);

    assert_eq!(&packed[0..16], expected_hex);
}

fn get_hexadecimal_string_from_lsb_first_stream(a: &[u8]) -> String {
    assert!(a.len().is_multiple_of(8));
    let mut hexadecimal = String::new();
    for test in a.chunks(8) {
        let to_hex = |chunk: &[u8]| -> char {
            let mut val = 0u8;
            if chunk[0] == 1 {
                val |= 1;
            }
            if chunk[1] == 1 {
                val |= 2;
            }
            if chunk[2] == 1 {
                val |= 4;
            }
            if chunk[3] == 1 {
                val |= 8;
            }

            match val {
                0..=9 => (val + b'0') as char,
                10..=15 => (val - 10 + b'A') as char,
                _ => unreachable!(),
            }
        };

        hexadecimal.push(to_hex(&test[4..8]));
        hexadecimal.push(to_hex(&test[0..4]));
    }
    hexadecimal
}

pub fn trivium_test_vector_1_test<P, E>(param: P, mut executor: E)
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

    let key = vec![0u64; 80];
    let iv = vec![0u64; 80];

    let expected_output_0_63 = "FBE0BF265859051B517A2E4E239FC97F563203161907CF2DE7A8790FA1B2E9CDF75292030268B7382B4C1A759AA2599A285549986E74805903801A4CB5A5D4F2";

    let ct_key = encrypt_bits(&cks, &key);
    let ct_iv = encrypt_bits(&cks, &iv);

    let num_steps = 512;
    let output_radix = executor.execute((&ct_key, &ct_iv, num_steps)).unwrap();

    let decrypted_bits = decrypt_bits(&cks, &output_radix);
    let hex_string = get_hexadecimal_string_from_lsb_first_stream(&decrypted_bits);

    assert_eq!(expected_output_0_63, &hex_string[0..64 * 2]);
}

pub fn trivium_test_vector_2_test<P, E>(param: P, mut executor: E)
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

    let mut key = vec![0u64; 80];
    let iv = vec![0u64; 80];
    key[7] = 1;

    let expected_output_0_63 = "38EB86FF730D7A9CAF8DF13A4420540DBB7B651464C87501552041C249F29A64D2FBF515610921EBE06C8F92CECF7F8098FF20CCCC6A62B97BE8EF7454FC80F9";

    let ct_key = encrypt_bits(&cks, &key);
    let ct_iv = encrypt_bits(&cks, &iv);

    let num_steps = 512;
    let output_radix = executor.execute((&ct_key, &ct_iv, num_steps)).unwrap();

    let decrypted_bits = decrypt_bits(&cks, &output_radix);
    let hex_string = get_hexadecimal_string_from_lsb_first_stream(&decrypted_bits);

    assert_eq!(expected_output_0_63, &hex_string[0..64 * 2]);
}

pub fn trivium_test_vector_3_test<P, E>(param: P, mut executor: E)
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

    let key = vec![0u64; 80];
    let mut iv = vec![0u64; 80];
    iv[7] = 1;

    let expected_output_0_63 = "F8901736640549E3BA7D42EA2D07B9F49233C18D773008BD755585B1A8CBAB86C1E9A9B91F1AD33483FD6EE3696D659C9374260456A36AAE11F033A519CBD5D7";

    let ct_key = encrypt_bits(&cks, &key);
    let ct_iv = encrypt_bits(&cks, &iv);

    let num_steps = 512;
    let output_radix = executor.execute((&ct_key, &ct_iv, num_steps)).unwrap();

    let decrypted_bits = decrypt_bits(&cks, &output_radix);
    let hex_string = get_hexadecimal_string_from_lsb_first_stream(&decrypted_bits);

    assert_eq!(expected_output_0_63, &hex_string[0..64 * 2]);
}

pub fn trivium_test_vector_4_test<P, E>(param: P, mut executor: E)
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

    let key_string = "0053A6F94C9FF24598EB";
    let mut key = vec![0u64; 80];
    for i in (0..key_string.len()).step_by(2) {
        let mut val = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            key[8 * (i >> 1) + j] = (val % 2) as u64;
            val >>= 1;
        }
    }

    let iv_string = "0D74DB42A91077DE45AC";
    let mut iv = vec![0u64; 80];
    for i in (0..iv_string.len()).step_by(2) {
        let mut val = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            iv[8 * (i >> 1) + j] = (val % 2) as u64;
            val >>= 1;
        }
    }

    let expected_output_0_63 = "F4CD954A717F26A7D6930830C4E7CF0819F80E03F25F342C64ADC66ABA7F8A8E6EAA49F23632AE3CD41A7BD290A0132F81C6D4043B6E397D7388F3A03B5FE358";

    let ct_key = encrypt_bits(&cks, &key);
    let ct_iv = encrypt_bits(&cks, &iv);

    let num_steps = 512;
    let output_radix = executor.execute((&ct_key, &ct_iv, num_steps)).unwrap();

    let decrypted_bits = decrypt_bits(&cks, &output_radix);
    let hex_string = get_hexadecimal_string_from_lsb_first_stream(&decrypted_bits);

    assert_eq!(expected_output_0_63, &hex_string[0..64 * 2]);
}

pub fn trivium_comparison_test<P, E>(param: P, mut executor: E)
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

    let num_runs = 5;
    let num_steps = 512;

    for i in 0..num_runs {
        let mut rng = rand::rng();
        let plain_key: Vec<u8> = (0..80).map(|_| rng.gen_range(0..=1)).collect();
        let plain_iv: Vec<u8> = (0..80).map(|_| rng.gen_range(0..=1)).collect();

        let key_bits_u64: Vec<u64> = plain_key.iter().map(|&x| x as u64).collect();
        let iv_bits_u64: Vec<u64> = plain_iv.iter().map(|&x| x as u64).collect();

        let ct_key = encrypt_bits(&cks, &key_bits_u64);
        let ct_iv = encrypt_bits(&cks, &iv_bits_u64);

        let mut cpu_trivium = TriviumRef::new(&plain_key, &plain_iv);
        let mut cpu_output = Vec::with_capacity(num_steps);
        for _ in 0..num_steps {
            cpu_output.push(cpu_trivium.next());
        }

        let output_radix = executor.execute((&ct_key, &ct_iv, num_steps)).unwrap();
        let fhe_output = decrypt_bits(&cks, &output_radix);

        assert_eq!(cpu_output.len(), fhe_output.len());
        assert_eq!(cpu_output, fhe_output, "Mismatch at iteration {i}");
    }
}
