use crate::integer::keycache::KEY_CACHE;
use crate::integer::parameters::IntegerCompactCiphertextListExpansionMode;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{gen_keys, CompressedPublicKey, IntegerKeyKind, PublicKey, RadixCiphertext};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;

create_parameterized_test!(big_radix_encrypt_decrypt_128_bits {

        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        },
        no_coverage => {
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            /* PARAM_MESSAGE_3_CARRY_3_KS_PBS, Skipped as the key requires 32GB
            * PARAM_MESSAGE_4_CARRY_4_KS_PBS, Skipped as the key requires 550GB */
        }
    }
);

create_parameterized_test!(
    radix_encrypt_decrypt_compressed_128_bits {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        },
        no_coverage => {
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            /* PARAM_MESSAGE_3_CARRY_3_KS_PBS, Skipped as its slow
            * PARAM_MESSAGE_4_CARRY_4_KS_PBS, Skipped as its slow */
        }
    }
);

create_parameterized_test!(
    big_radix_encrypt_decrypt_compact_128_bits_list {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        },
        no_coverage => {
            TEST_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        }
    }
);

create_parameterized_test!(
    small_radix_encrypt_decrypt_compact_128_bits_list {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M64,
        },
        no_coverage => {
            TEST_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M128,
        }
    }
);

/// Test that the public key can encrypt a 128 bit number
/// in radix decomposition, and that the client key can decrypt it
fn big_radix_encrypt_decrypt_128_bits(param: ClassicPBSParameters) {
    let (cks, _) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let public_key = PublicKey::new(&cks);

    let mut rng = rand::rng();
    let num_block = (128f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

    let clear = rng.gen::<u128>();

    let ct = public_key.encrypt_radix(clear, num_block);

    let dec: u128 = cks.decrypt_radix(&ct);

    assert_eq!(clear, dec);
}

fn radix_encrypt_decrypt_compressed_128_bits(param: ClassicPBSParameters) {
    let (cks, _) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let public_key = CompressedPublicKey::new(&cks);

    let mut rng = rand::rng();
    let num_block = (128f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

    let clear = rng.gen::<u128>();

    let ct = public_key.encrypt_radix(clear, num_block);

    let dec: u128 = cks.decrypt_radix(&ct);

    assert_eq!(clear, dec);
}

fn big_radix_encrypt_decrypt_compact_128_bits_list(params: ClassicPBSParameters) {
    radix_encrypt_decrypt_compact_128_bits_list(params);
}

fn small_radix_encrypt_decrypt_compact_128_bits_list(params: ClassicPBSParameters) {
    radix_encrypt_decrypt_compact_128_bits_list(params);
}

fn radix_encrypt_decrypt_compact_128_bits_list(params: ClassicPBSParameters) {
    let (cks, sks) = gen_keys(params, IntegerKeyKind::Radix);
    let pk = crate::integer::public_key::CompactPublicKey::new(&cks);

    let mut rng = rand::rng();
    let num_block = (128f64 / (params.message_modulus.0 as f64).log(2.0)).ceil() as usize;

    const MAX_CT: usize = 20;

    let mut clear_vec = Vec::with_capacity(MAX_CT);
    for _ in 0..25 {
        let num_ct_for_this_iter = rng.gen_range(1..=MAX_CT);
        clear_vec.truncate(0);
        for _ in 0..num_ct_for_this_iter {
            let clear = rng.gen::<u128>();
            clear_vec.push(clear);
        }

        let mut builder = crate::integer::ciphertext::CompactCiphertextList::builder(&pk);
        builder.extend_with_num_blocks(clear_vec.iter().copied(), num_block);

        let compact_lists = [builder.build(), builder.build_packed().unwrap()];

        assert!(!compact_lists[0].is_packed());
        assert!(compact_lists[1].is_packed());

        for compact_encrypted_list in compact_lists {
            let expander = compact_encrypted_list
                .expand(
                    IntegerCompactCiphertextListExpansionMode::UnpackAndSanitizeIfNecessary(&sks),
                )
                .unwrap();

            let mut ciphertext_vec = Vec::with_capacity(num_ct_for_this_iter);
            for i in 0..num_ct_for_this_iter {
                let radix = expander.get::<RadixCiphertext>(i).unwrap().unwrap();
                assert_eq!(radix.blocks.len(), num_block);
                ciphertext_vec.push(radix);
            }

            for (ciphertext, clear) in ciphertext_vec.iter().zip(clear_vec.iter().copied()) {
                let decrypted: u128 = cks.decrypt_radix(ciphertext);
                assert_eq!(decrypted, clear);
            }
        }
    }
}
