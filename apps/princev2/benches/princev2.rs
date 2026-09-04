//! Benchmarks for homomorphic PRINCEv2 encryption and decryption
//!
//! Times one full call of `encrypt` and one of `decrypt`, i.e., transciphering one block of
//! 64 bits in either direction.

use criterion::{criterion_group, criterion_main, Criterion};

use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
use tfhe::shortint::prelude::*;

use tfhe_princev2::encryption::{decrypt_u2l_as_u64, encrypt_u64_as_u2l};
use tfhe_princev2::{decrypt, encrypt};

criterion_group!(benches, bench_transciphering);
criterion_main!(benches);

type Block = [Ciphertext; 32];

// KAT structure for the Prince v2 cipher
struct Kat {
    name: &'static str,
    ptxt: u64,
    k0: u64,
    k1: u64,
    ctxt: u64,
}

static KAT_LN2: Kat = Kat {
    // ptxt, k0, k1 are the first three u64 words of ln(2) fractional part.
    // ctxt was computed with the Sagemaths reference implementation and cross-checked here.
    name: "PRINCEv2 KAT from ln(2)",
    ptxt: 0xb17217f7d1cf79ab,
    k0: 0xc9e3b39803f2f6af,
    k1: 0x40f343267298b62d,
    ctxt: 0x40ac916b4598216d,
};

/// Run benches for PRINCEv2 transciphering.
fn bench_transciphering(c: &mut Criterion) {
    let (client_key, server_key): (ClientKey, ServerKey) = // Params: Need 4-bits msg + nu >= 4
        tfhe::shortint::gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);

    let ct_k0: Block = encrypt_u64_as_u2l(&client_key, KAT_LN2.k0);
    let ct_k1: Block = encrypt_u64_as_u2l(&client_key, KAT_LN2.k1);
    let ct_m: Block = encrypt_u64_as_u2l(&client_key, KAT_LN2.ptxt);
    let ct_c: Block = encrypt_u64_as_u2l(&client_key, KAT_LN2.ctxt);

    let ct_enc: Block = encrypt(&server_key, &ct_m, &ct_k0, &ct_k1);
    let pt_enc: u64 = decrypt_u2l_as_u64(&client_key, &ct_enc);
    assert_eq!(
        pt_enc, KAT_LN2.ctxt,
        "{} failed: ptxt={:#018x}, k0={:#018x}, k1={:#018x}, expected={:#018x}, got={:#018x}",
        KAT_LN2.name, KAT_LN2.ptxt, KAT_LN2.k0, KAT_LN2.k1, KAT_LN2.ctxt, pt_enc
    );

    let ct_dec: Block = decrypt(&server_key, &ct_c, &ct_k0, &ct_k1);
    let pt_dec: u64 = decrypt_u2l_as_u64(&client_key, &ct_dec);
    assert_eq!(
        pt_dec, KAT_LN2.ptxt,
        "{} failed: ctxt={:#018x}, k0={:#018x}, k1={:#018x}, expected={:#018x}, got={:#018x}",
        KAT_LN2.name, KAT_LN2.ctxt, KAT_LN2.k0, KAT_LN2.k1, KAT_LN2.ptxt, pt_dec
    );

    let mut group = c.benchmark_group("princev2");
    group.sample_size(10);
    group.bench_function("PRINCEv2 Encryption of one message block", |b| {
        b.iter(|| encrypt(&server_key, &ct_m, &ct_k0, &ct_k1));
    });
    group.bench_function("PRINCEv2 Decryption of one message block", |b| {
        b.iter(|| decrypt(&server_key, &ct_c, &ct_k0, &ct_k1));
    });
    group.finish();
}
