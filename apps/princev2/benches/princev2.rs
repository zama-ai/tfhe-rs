//! Benchmarks for homomorphic PRINCEv2 encryption (and decryption)
//!
//! Times one full call of `pv2_encrypt`, i.e., transciphering one block of 64 bits.
//! Note that decryption `pv2_decrypt` follows exactly the same logic as encryption with different
//! constants, hence it is not benched separately.

use criterion::{criterion_group, criterion_main, Criterion};

use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
use tfhe::shortint::prelude::*;

use tfhe_princev2::{pv2_encrypt, u64_to_vec_u2, vec_u2_to_u64};

// [NB] We don't expect pv2_decrypt() to behave differently from pv2_encrypt()
criterion_group!(pv2_benches, bench_pv2_encrypt);
criterion_main!(pv2_benches);

// KAT structure for Pv2 cipher
struct Pv2Kat {
    name: &'static str,
    ptxt: u64,
    k0: u64,
    k1: u64,
    ctxt: u64,
}

static PV2_KAT_LN2: Pv2Kat = Pv2Kat {
    // ptxt, k0, k1 are the first three u64 words of ln(2) fractional part.
    // ctxt was computed with the Sagemaths reference implementation and cross-checked here.
    name: "PRINCEv2 KAT from ln(2)",
    ptxt: 0xb17217f7d1cf79ab,
    k0: 0xc9e3b39803f2f6af,
    k1: 0x40f343267298b62d,
    ctxt: 0x40ac916b4598216d,
};

/// Encrypt a u64 as 32 ciphertexts, each holding a 2-bit nibble in the low bits of the FHE message
/// space. Most significant bits of the input are at index 0 in the output
fn encrypt_u64_as_vec_u2l(s_key: &ClientKey, x: u64) -> [Ciphertext; 32] {
    let x_u2: [u8; 32] = u64_to_vec_u2(x);
    let ct: Vec<Ciphertext> = x_u2
        .into_iter()
        .map(|u2| s_key.encrypt(u2 as u64))
        .collect();
    ct.try_into().unwrap()
}

/// Reverse of function encrypt_u64_as_vec_u2l()
fn decrypt_vec_u2l_as_u64(s_key: &ClientKey, v: &[Ciphertext; 32]) -> u64 {
    let x_u2: [u8; 32] = std::array::from_fn(|n| s_key.decrypt_message_and_carry(&v[n]) as u8);
    let x: u64 = vec_u2_to_u64(x_u2);
    x
}

/// Run benches for PRINCEv2 transciphering.
fn bench_pv2_encrypt(c: &mut Criterion) {
    let (s_key, ev_key): (ClientKey, ServerKey) = // Params: Need 4-bits msg + nu >= 4
        tfhe::shortint::gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);

    // Encryptions of inputs (k0,k1,m)
    let ct_k0: [Ciphertext; 32] = encrypt_u64_as_vec_u2l(&s_key, PV2_KAT_LN2.k0);
    let ct_k1: [Ciphertext; 32] = encrypt_u64_as_vec_u2l(&s_key, PV2_KAT_LN2.k1);
    let ct_m: [Ciphertext; 32] = encrypt_u64_as_vec_u2l(&s_key, PV2_KAT_LN2.ptxt);

    // PRINCEv2 Enc in FHE
    let mut ct_out: [Ciphertext; 32] = std::array::from_fn(|_| ev_key.create_trivial(0)); // [NB] shortint::create_trivial() vs boolean::trivial_encrypt()
    c.bench_function("PRINCEv2 Trans-Encryption of one message block", |b| {
        b.iter(|| {
            pv2_encrypt(&ev_key, &mut ct_out, &ct_m, &ct_k0, &ct_k1);
        });
    });

    // Testing the (de-)encrypted result
    let pt_out: u64 = decrypt_vec_u2l_as_u64(&s_key, &ct_out);
    assert_eq!(
        pt_out,
        PV2_KAT_LN2.ctxt,
        "{} failed: ptxt={:#018x}, k0={:#018x}, k1={:#018x}, expected={:#018x}, got={:#018x}",
        PV2_KAT_LN2.name,
        PV2_KAT_LN2.ptxt,
        PV2_KAT_LN2.k0,
        PV2_KAT_LN2.k1,
        PV2_KAT_LN2.ctxt,
        pt_out
    );
}
