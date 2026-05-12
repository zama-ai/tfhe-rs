//! Temporary apples-to-apples bench for the new
//! `tfhe::transciphering::ciphers::kreyvium` impl. Same key/IV bytes and same
//! 64-bit input/output sizes as `kreyvium_shortint.rs`. Output is wrapped in
//! `FheUint64` to match the existing bench's output type.

use criterion::Criterion;
use tfhe::shortint::parameters::current_params::V1_6_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
use tfhe::transciphering::ciphers::kreyvium::{KreyviumEncryptedKey, KreyviumFheStream};
use tfhe::transciphering::Transcipherer;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint64};

fn make_keys() -> (
    tfhe::ServerKey,
    tfhe::shortint::ClientKey,
    tfhe::shortint::ServerKey,
) {
    let config = ConfigBuilder::default()
        .use_custom_parameters(V1_6_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128)
        .build();
    let (hl_ck, hl_sk) = generate_keys(config);
    let short_ck: tfhe::shortint::ClientKey = (*hl_ck.as_ref()).clone().into();
    let short_sk: tfhe::shortint::ServerKey = (*hl_sk.as_ref()).clone().into();
    (hl_sk, short_ck, short_sk)
}

fn make_inputs() -> ([u64; 128], [u64; 128]) {
    let key_string = "0053A6F94C9FF24598EB000000000000".to_string();
    let mut key = [0u64; 128];
    for i in (0..key_string.len()).step_by(2) {
        let mut val = u64::from_str_radix(&key_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            key[8 * (i >> 1) + j] = val % 2;
            val >>= 1;
        }
    }

    let iv_string = "0D74DB42A91077DE45AC000000000000".to_string();
    let mut iv = [0u64; 128];
    for i in (0..iv_string.len()).step_by(2) {
        let mut val = u64::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            iv[8 * (i >> 1) + j] = val % 2;
            val >>= 1;
        }
    }

    (key, iv)
}

pub fn kreyvium_transciphering_warmup(c: &mut Criterion) {
    let (_hl_sk, short_ck, short_sk) = make_keys();
    let (key, iv) = make_inputs();

    c.bench_function("kreyvium 2_2 warmup", |b| {
        b.iter(|| {
            let enc_key: KreyviumEncryptedKey = key.map(|x| short_ck.encrypt(x)).into();
            let _engine = KreyviumFheStream::new(enc_key, iv, &short_sk);
        })
    });
}

pub fn kreyvium_transciphering_gen(c: &mut Criterion) {
    let (_hl_sk, short_ck, short_sk) = make_keys();
    let (key, iv) = make_inputs();

    let enc_key: KreyviumEncryptedKey = key.map(|x| short_ck.encrypt(x)).into();
    let mut engine = KreyviumFheStream::new(enc_key, iv, &short_sk);

    c.bench_function("kreyvium 2_2 generate 64 bits", |b| {
        b.iter(|| engine.next_keystream_bits(&short_sk, 64))
    });
}

pub fn kreyvium_transciphering_trans(c: &mut Criterion) {
    let (hl_sk, short_ck, short_sk) = make_keys();
    let (key, iv) = make_inputs();

    // Same semantic input as the app bench (all-zero sym-cipher bytes); new
    // API consumes them as clear bytes. Result wrapped in FheUint64 to match
    // the app bench's output type.
    let sym_cipher = [0u8; 8];

    let enc_key: KreyviumEncryptedKey = key.map(|x| short_ck.encrypt(x)).into();
    let mut engine = KreyviumFheStream::new(enc_key, iv, &short_sk);

    // FheUint64::try_from reads the global HL server key.
    set_server_key(hl_sk);

    c.bench_function("kreyvium 2_2 transencrypt 64 bits", |b| {
        b.iter(|| {
            let blocks = engine.trans_cipher(&short_sk, &sym_cipher);
            FheUint64::try_from(blocks).unwrap()
        })
    });
}
