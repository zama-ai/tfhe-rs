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

use tfhe_princev2::encryption::{decrypt_u2l_as_u64, encrypt_u64_as_u2l};
use tfhe_princev2::{decrypt, encrypt};

// KAT structure for the Prince v2 cipher
struct Kat {
    name: &'static str,
    ptxt: u64,
    k0: u64,
    k1: u64,
    ctxt: u64,
}

/// Test vectors from [BEK+20, Appendix B]
static KATS_TABLE: [Kat; 5] = [
    Kat {
        name: "PRINCEv2 KAT #1",
        ptxt: 0x0000000000000000,
        k0: 0x0000000000000000,
        k1: 0x0000000000000000,
        ctxt: 0x0125fc7359441690,
    },
    Kat {
        name: "PRINCEv2 KAT #2",
        ptxt: 0xffffffffffffffff,
        k0: 0x0000000000000000,
        k1: 0x0000000000000000,
        ctxt: 0x832bd46f108e7857,
    },
    Kat {
        name: "PRINCEv2 KAT #3",
        ptxt: 0x0000000000000000,
        k0: 0xffffffffffffffff,
        k1: 0x0000000000000000,
        ctxt: 0xee873b2ec447944d,
    },
    Kat {
        name: "PRINCEv2 KAT #4",
        ptxt: 0x0000000000000000,
        k0: 0x0000000000000000,
        k1: 0xffffffffffffffff,
        ctxt: 0x0ac6f9cd6e6f275d,
    },
    Kat {
        name: "PRINCEv2 KAT #5",
        ptxt: 0x0123456789abcdef,
        k0: 0x0123456789abcdef,
        k1: 0xfedcba9876543210,
        ctxt: 0x603cd95fa72a8704,
    },
];

type Block = [Ciphertext; 32];

fn check_kat(
    client_key: &ClientKey,
    server_key: &ServerKey,
    kat: &Kat,
    cipher: fn(&ServerKey, &Block, &Block, &Block) -> Block,
    input: u64,
    expected: u64,
) {
    // Encryptions of inputs (k0,k1,in)
    let ct_k0 = encrypt_u64_as_u2l(client_key, kat.k0);
    let ct_k1 = encrypt_u64_as_u2l(client_key, kat.k1);
    let ct_in = encrypt_u64_as_u2l(client_key, input);

    let ct_out = cipher(server_key, &ct_in, &ct_k0, &ct_k1);

    // Testing the decrypted result
    let pt_out: u64 = decrypt_u2l_as_u64(client_key, &ct_out);
    assert_eq!(
        pt_out, expected,
        "{} failed: in={:#018x}, k0={:#018x}, k1={:#018x}, expected={:#018x}, got={:#018x}",
        kat.name, input, kat.k0, kat.k1, expected, pt_out
    );
}

#[test]
fn enc_kat() {
    let (client_key, server_key): (ClientKey, ServerKey) =
        tfhe::shortint::gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);

    for kat in &KATS_TABLE {
        check_kat(&client_key, &server_key, kat, encrypt, kat.ptxt, kat.ctxt);
    }
}

#[test]
fn dec_kat() {
    let (client_key, server_key): (ClientKey, ServerKey) =
        tfhe::shortint::gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);

    for kat in &KATS_TABLE {
        check_kat(&client_key, &server_key, kat, decrypt, kat.ctxt, kat.ptxt);
    }
}
