//! Known-answer tests against the PRINCEv2 paper test vectors.
//!
//! These tests run a full homomorphic PRINCEv2 encryption/decryption and assert that the decrypted
//! ciphertext matches the values from PRINCEv2 specifications [BEK+20, Appendix B].
//!
//! [BEK+20] Dusan Božilov, Maria Eichlseder, Miroslav Kneževic, Baptiste Lambin, Gregor Leander,
//! Thorben Moos, Ventzislav Nikov, Shahram Rasoolzadeh, Yosuke Todo, and Friedrich Wiemer.
//! PRINCEv2: More security for (almost) no overhead. In Selected Areas in Cryptography (SAC 2020),
//! volume 12804 of LNCS, pp.483--511, Springer, 2020. DOI:10.1007/978-3-030-81652-0_19.

use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
use tfhe::shortint::prelude::*;

use tfhe_princev2::{pv2_decrypt, pv2_encrypt, u64_to_vec_u2, vec_u2_to_u64};

// KAT structure for Pv2 cipher
struct Pv2Kat {
    name: &'static str,
    ptxt: u64,
    k0: u64,
    k1: u64,
    ctxt: u64,
}

/// Test vectors from [BEK+20, Appendix B]
static PV2_KATS_TABLE: [Pv2Kat; 5] = [
    Pv2Kat {
        name: "PRINCEv2 KAT #1",
        ptxt: 0x0000000000000000,
        k0: 0x0000000000000000,
        k1: 0x0000000000000000,
        ctxt: 0x0125fc7359441690,
    },
    Pv2Kat {
        name: "PRINCEv2 KAT #2",
        ptxt: 0xffffffffffffffff,
        k0: 0x0000000000000000,
        k1: 0x0000000000000000,
        ctxt: 0x832bd46f108e7857,
    },
    Pv2Kat {
        name: "PRINCEv2 KAT #3",
        ptxt: 0x0000000000000000,
        k0: 0xffffffffffffffff,
        k1: 0x0000000000000000,
        ctxt: 0xee873b2ec447944d,
    },
    Pv2Kat {
        name: "PRINCEv2 KAT #4",
        ptxt: 0x0000000000000000,
        k0: 0x0000000000000000,
        k1: 0xffffffffffffffff,
        ctxt: 0x0ac6f9cd6e6f275d,
    },
    Pv2Kat {
        name: "PRINCEv2 KAT #5",
        ptxt: 0x0123456789abcdef,
        k0: 0x0123456789abcdef,
        k1: 0xfedcba9876543210,
        ctxt: 0x603cd95fa72a8704,
    },
];

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

/// Run KATs homomorphically for PRINCEv2 Encryption.
/// [Note] Takes approximately 21s / KAT on 8 cores.
#[test]
fn pv2_enc_kat() {
    let (s_key, ev_key): (ClientKey, ServerKey) = // Params: Need 4-bits msg + nu >= 4
        tfhe::shortint::gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);

    for tkat in &PV2_KATS_TABLE {
        // Encryptions of inputs (k0,k1,m)
        let ct_k0: [Ciphertext; 32] = encrypt_u64_as_vec_u2l(&s_key, tkat.k0);
        let ct_k1: [Ciphertext; 32] = encrypt_u64_as_vec_u2l(&s_key, tkat.k1);
        let ct_m: [Ciphertext; 32] = encrypt_u64_as_vec_u2l(&s_key, tkat.ptxt);

        // PRINCEv2 Enc in FHE
        let mut ct_out: [Ciphertext; 32] = std::array::from_fn(|_| ev_key.create_trivial(0)); // [NB] shortint::create_trivial() vs boolean::trivial_encrypt()
        pv2_encrypt(&ev_key, &mut ct_out, &ct_m, &ct_k0, &ct_k1);

        // Testing the (de-)encrypted result
        let pt_out: u64 = decrypt_vec_u2l_as_u64(&s_key, &ct_out);
        assert_eq!(
            pt_out, tkat.ctxt,
            "{} failed: ptxt={:#018x}, k0={:#018x}, k1={:#018x}, expected={:#018x}, got={:#018x}",
            tkat.name, tkat.ptxt, tkat.k0, tkat.k1, tkat.ctxt, pt_out
        );
    }
}

#[test]
fn pv2_dec_kat() {
    let (s_key, ev_key): (ClientKey, ServerKey) = // Params: Need 4-bits msg + nu >= 4
        tfhe::shortint::gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);

    for tkat in &PV2_KATS_TABLE {
        // Encryptions of inputs (k0,k1,m)
        let ct_k0: [Ciphertext; 32] = encrypt_u64_as_vec_u2l(&s_key, tkat.k0);
        let ct_k1: [Ciphertext; 32] = encrypt_u64_as_vec_u2l(&s_key, tkat.k1);
        let ct_c: [Ciphertext; 32] = encrypt_u64_as_vec_u2l(&s_key, tkat.ctxt);

        // PRINCEv2 Dec in FHE
        let mut ct_out: [Ciphertext; 32] = std::array::from_fn(|_| ev_key.create_trivial(0)); // [NB] shortint::create_trivial() vs boolean::trivial_encrypt()
        pv2_decrypt(&ev_key, &mut ct_out, &ct_c, &ct_k0, &ct_k1);

        // Testing the (de-)encrypted result
        let pt_out: u64 = decrypt_vec_u2l_as_u64(&s_key, &ct_out);
        assert_eq!(
            pt_out, tkat.ptxt,
            "{} failed: ctxt={:#018x}, k0={:#018x}, k1={:#018x}, expected={:#018x}, got={:#018x}",
            tkat.name, tkat.ctxt, tkat.k0, tkat.k1, tkat.ptxt, pt_out
        );
    }
}
