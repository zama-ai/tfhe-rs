use tfhe::prelude::*;
use tfhe::{generate_keys, ConfigBuilder, FheBool};

use tfhe_trivium::TriviumStream;

use criterion::Criterion;

pub fn trivium_bool_gen(c: &mut Criterion) {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [false; 80];

    for i in (0..key_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            key[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [false; 80];

    for i in (0..iv_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            iv[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    let cipher_key = key.map(|x| FheBool::encrypt(x, &client_key));

    let mut trivium = TriviumStream::<FheBool>::new(cipher_key, iv, &server_key);

    c.bench_function("trivium bool generate 64 bits", |b| {
        b.iter(|| trivium.next_64())
    });
}

pub fn trivium_bool_warmup(c: &mut Criterion) {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [false; 80];

    for i in (0..key_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            key[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [false; 80];

    for i in (0..iv_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            iv[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    c.bench_function("trivium bool warmup", |b| {
        b.iter(|| {
            let cipher_key = key.map(|x| FheBool::encrypt(x, &client_key));
            let _trivium = TriviumStream::<FheBool>::new(cipher_key, iv, &server_key);
        })
    });
}
