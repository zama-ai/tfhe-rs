//! Sibling of `kreyvium_shortint_transciphering.rs` benching the PDF-style
//! fast pipeline (`KreyviumFastFheStream`). Runs warmup and 64-bit keystream
//! generation under each dedicated parameter set. Only warmup and keystream
//! generation are benched for now: the full transciphering output lives in
//! the dedicated kreyvium params and would need a switch to the eval params
//! to be usable.

use criterion::Criterion;
use tfhe::shortint::parameters::KeySwitch32PBSParameters;
use tfhe::transciphering::ciphers::kreyvium::{
    KreyviumFastEncryptedKey, KreyviumFastFheStream, PARAM_KREYVIUM_1_0_KS32_TUNIFORM_K5_2M127,
    PARAM_KREYVIUM_1_0_KS32_TUNIFORM_K5_2M128, PARAM_KREYVIUM_1_0_KS32_TUNIFORM_K7_2M128,
};
use tfhe::transciphering::Transcipherer;

use super::kreyvium_shortint_transciphering::make_inputs;

fn make_kreyvium_keys(
    params: KeySwitch32PBSParameters,
) -> (tfhe::shortint::ClientKey, tfhe::shortint::ServerKey) {
    let short_ck = tfhe::shortint::ClientKey::new(params);
    let short_sk = tfhe::shortint::ServerKey::new(&short_ck);
    (short_ck, short_sk)
}

fn bench_warmup(c: &mut Criterion, label: &str, params: KeySwitch32PBSParameters) {
    let (short_ck, short_sk) = make_kreyvium_keys(params);
    let (key, iv) = make_inputs();

    c.bench_function(&format!("kreyvium 1_0 fast {label} warmup"), |b| {
        b.iter(|| {
            let enc_key: KreyviumFastEncryptedKey = key.map(|x| short_ck.encrypt(x)).into();
            let _engine = KreyviumFastFheStream::new(enc_key, iv, &short_sk);
        })
    });
}

fn bench_gen(c: &mut Criterion, label: &str, params: KeySwitch32PBSParameters) {
    let (short_ck, short_sk) = make_kreyvium_keys(params);
    let (key, iv) = make_inputs();

    let enc_key: KreyviumFastEncryptedKey = key.map(|x| short_ck.encrypt(x)).into();
    let mut engine = KreyviumFastFheStream::new(enc_key, iv, &short_sk);

    c.bench_function(&format!("kreyvium 1_0 fast {label} generate 64 bits"), |b| {
        b.iter(|| engine.next_keystream_bits(&short_sk, 64))
    });
}

pub fn kreyvium_fast_transciphering_warmup_k5_2m128(c: &mut Criterion) {
    bench_warmup(c, "k5 2^-128", PARAM_KREYVIUM_1_0_KS32_TUNIFORM_K5_2M128);
}

pub fn kreyvium_fast_transciphering_gen_k5_2m128(c: &mut Criterion) {
    bench_gen(c, "k5 2^-128", PARAM_KREYVIUM_1_0_KS32_TUNIFORM_K5_2M128);
}

pub fn kreyvium_fast_transciphering_warmup_k5_2m127(c: &mut Criterion) {
    bench_warmup(c, "k5 2^-127", PARAM_KREYVIUM_1_0_KS32_TUNIFORM_K5_2M127);
}

pub fn kreyvium_fast_transciphering_gen_k5_2m127(c: &mut Criterion) {
    bench_gen(c, "k5 2^-127", PARAM_KREYVIUM_1_0_KS32_TUNIFORM_K5_2M127);
}

pub fn kreyvium_fast_transciphering_warmup_k7_2m128(c: &mut Criterion) {
    bench_warmup(c, "k7 2^-128", PARAM_KREYVIUM_1_0_KS32_TUNIFORM_K7_2M128);
}

pub fn kreyvium_fast_transciphering_gen_k7_2m128(c: &mut Criterion) {
    bench_gen(c, "k7 2^-128", PARAM_KREYVIUM_1_0_KS32_TUNIFORM_K7_2M128);
}
