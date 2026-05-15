//! Sibling of `kreyvium_shortint_transciphering.rs` benching the PDF-style
//! fast pipeline (`KreyviumFastFheStream`). Reuses `make_keys` / `make_inputs`
//! from that module; bench names use `... fast ...` so criterion reports them
//! next to the existing ones.

use criterion::Criterion;
use tfhe::transciphering::ciphers::kreyvium::{
    encrypt_fast_bit, KreyviumFastEncryptedKey, KreyviumFastFheStream,
};
use tfhe::transciphering::Transcipherer;
use tfhe::{set_server_key, FheUint64};

use super::kreyvium_shortint_transciphering::{make_inputs, make_keys};

pub fn kreyvium_fast_transciphering_warmup(c: &mut Criterion) {
    let (_hl_sk, short_ck, short_sk) = make_keys();
    let (key, iv) = make_inputs();

    c.bench_function("kreyvium 2_2 fast warmup", |b| {
        b.iter(|| {
            let enc_key: KreyviumFastEncryptedKey =
                key.map(|x| encrypt_fast_bit(&short_ck, x)).into();
            let _engine = KreyviumFastFheStream::new(enc_key, iv, &short_sk);
        })
    });
}

pub fn kreyvium_fast_transciphering_gen(c: &mut Criterion) {
    let (_hl_sk, short_ck, short_sk) = make_keys();
    let (key, iv) = make_inputs();

    let enc_key: KreyviumFastEncryptedKey = key.map(|x| encrypt_fast_bit(&short_ck, x)).into();
    let mut engine = KreyviumFastFheStream::new(enc_key, iv, &short_sk);

    c.bench_function("kreyvium 2_2 fast generate 64 bits", |b| {
        b.iter(|| engine.next_keystream_bits(&short_sk, 64))
    });
}

pub fn kreyvium_fast_transciphering_trans(c: &mut Criterion) {
    let (hl_sk, short_ck, short_sk) = make_keys();
    let (key, iv) = make_inputs();

    let sym_cipher = [0u8; 8];

    let enc_key: KreyviumFastEncryptedKey = key.map(|x| encrypt_fast_bit(&short_ck, x)).into();
    let mut engine = KreyviumFastFheStream::new(enc_key, iv, &short_sk);

    set_server_key(hl_sk);

    c.bench_function("kreyvium 2_2 fast transencrypt 64 bits", |b| {
        b.iter(|| {
            let blocks = engine.trans_cipher(&short_sk, &sym_cipher);
            FheUint64::try_from(blocks).unwrap()
        })
    });
}
