use tfhe::prelude::*;
use tfhe::{generate_keys, ConfigBuilder, FheUint64, FheUint8};

use tfhe_trivium::{TransCiphering, TriviumStreamByte};

use criterion::Criterion;

pub fn trivium_byte_gen(c: &mut Criterion) {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [0u8; 10];

    for i in (0..key_string.len()).step_by(2) {
        key[i >> 1] = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [0u8; 10];

    for i in (0..iv_string.len()).step_by(2) {
        iv[i >> 1] = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
    }

    let cipher_key = key.map(|x| FheUint8::encrypt(x, &client_key));

    let mut trivium = TriviumStreamByte::<FheUint8>::new(cipher_key, iv, &server_key);

    c.bench_function("trivium byte generate 64 bits", |b| {
        b.iter(|| trivium.next_64())
    });
}

pub fn trivium_byte_trans(c: &mut Criterion) {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [0u8; 10];

    for i in (0..key_string.len()).step_by(2) {
        key[i >> 1] = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [0u8; 10];

    for i in (0..iv_string.len()).step_by(2) {
        iv[i >> 1] = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
    }

    let cipher_key = key.map(|x| FheUint8::encrypt(x, &client_key));

    let ciphered_message = FheUint64::try_encrypt(0u64, &client_key).unwrap();
    let mut trivium = TriviumStreamByte::<FheUint8>::new(cipher_key, iv, &server_key);

    c.bench_function("trivium byte transencrypt 64 bits", |b| {
        b.iter(|| trivium.trans_encrypt_64(ciphered_message.clone()))
    });
}

pub fn trivium_byte_warmup(c: &mut Criterion) {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [0u8; 10];

    for i in (0..key_string.len()).step_by(2) {
        key[i >> 1] = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [0u8; 10];

    for i in (0..iv_string.len()).step_by(2) {
        iv[i >> 1] = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
    }

    c.bench_function("trivium byte warmup", |b| {
        b.iter(|| {
            let cipher_key = key.map(|x| FheUint8::encrypt(x, &client_key));
            let _trivium = TriviumStreamByte::<FheUint8>::new(cipher_key, iv, &server_key);
        })
    });
}
