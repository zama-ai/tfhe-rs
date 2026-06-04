//! Sibling of `kreyvium_shortint_transciphering.rs` benching the PDF-style
//! fast pipeline (`KreyviumFastFheStream`) under its dedicated parameter set
//! (`kreyvium_params.json`). Only warmup and keystream generation are benched
//! for now: the full transciphering output lives in the dedicated kreyvium
//! params and would need a switch to the eval params to be usable.

use criterion::Criterion;
use tfhe::transciphering::ciphers::kreyvium::{
    KreyviumFastEncryptedKey, KreyviumFastFheStream, PARAM_KREYVIUM_1_0_KS32_TUNIFORM_2M128,
};
use tfhe::transciphering::Transcipherer;

use super::kreyvium_shortint_transciphering::make_inputs;

fn make_kreyvium_keys() -> (tfhe::shortint::ClientKey, tfhe::shortint::ServerKey) {
    let short_ck = tfhe::shortint::ClientKey::new(PARAM_KREYVIUM_1_0_KS32_TUNIFORM_2M128);
    let short_sk = tfhe::shortint::ServerKey::new(&short_ck);
    (short_ck, short_sk)
}

pub fn kreyvium_fast_transciphering_warmup(c: &mut Criterion) {
    let (short_ck, short_sk) = make_kreyvium_keys();
    let (key, iv) = make_inputs();

    c.bench_function("kreyvium 1_0 fast warmup", |b| {
        b.iter(|| {
            let enc_key: KreyviumFastEncryptedKey = key.map(|x| short_ck.encrypt(x)).into();
            let _engine = KreyviumFastFheStream::new(enc_key, iv, &short_sk);
        })
    });
}

pub fn kreyvium_fast_transciphering_gen(c: &mut Criterion) {
    let (short_ck, short_sk) = make_kreyvium_keys();
    let (key, iv) = make_inputs();

    let enc_key: KreyviumFastEncryptedKey = key.map(|x| short_ck.encrypt(x)).into();
    let mut engine = KreyviumFastFheStream::new(enc_key, iv, &short_sk);

    c.bench_function("kreyvium 1_0 fast generate 64 bits", |b| {
        b.iter(|| engine.next_keystream_bits(&short_sk, 64))
    });
}
