use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;

/// Number of assert in randomized tests
#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 30;
/// Number of sub tests used to increase degree of ciphertexts
#[cfg(not(tarpaulin))]
const NB_SUB_TEST: usize = 40;

// Use lower numbers for coverage to ensure fast tests to counter balance slowdown due to code
// instrumentation
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;
// This constant is tailored to trigger a message extract during operation processing.
// It's applicable for PARAM_MESSAGE_2_CARRY_2_KS_PBS parameters set.
#[cfg(tarpaulin)]
const NB_SUB_TEST: usize = 5;

// Macro to generate tests for all parameter sets
#[cfg(not(tarpaulin))]
macro_rules! create_parameterized_test{
    ($name:ident { $($param:ident),* }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_ $name _ $param:lower>]() {
                $name($param)
            }
            )*
        }
    };
    ($name:ident)=> {
        create_parameterized_test!($name
        {
            TEST_PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_PBS_KS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS_GAUSSIAN_2M128
        });
    };
}

// Test against a small subset of parameters to speed up coverage tests
#[cfg(tarpaulin)]
macro_rules! create_parameterized_test{
    ($name:ident { $($param:ident),* }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_ $name _ $param:lower>]() {
                $name($param)
            }
            )*
        }
    };
    ($name:ident)=> {
        create_parameterized_test!($name
        {
            TEST_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M128
        });
    };
}

create_parameterized_test!(shortint_compact_public_key_base_smart_add);

fn shortint_compact_public_key_base_smart_add(params: ClassicPBSParameters) {
    let keys = KEY_CACHE.get_from_param(params);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    let pk = crate::shortint::CompactPublicKey::new(cks);

    let mut rng = rand::rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = pk.encrypt_slice(&[clear_0]);
        let ctxt_1 = pk.encrypt_slice(&[clear_1]);

        let mut ctxt_0 = ctxt_0
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let ctxt_1 = ctxt_1
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();

        let d = cks.decrypt(&ctxt_0);
        assert_eq!(d, clear_0);
        let d = cks.decrypt(&ctxt_1);
        assert_eq!(d, clear_1);

        let mut ct_res = sks.unchecked_add(&ctxt_0, &ctxt_1);
        let mut clear = clear_0 + clear_1;
        let d = cks.decrypt(&ct_res);
        assert_eq!(d, clear % modulus);

        //add multiple times to raise the degree and test the smart operation
        for _ in 0..NB_SUB_TEST {
            sks.smart_add_assign(&mut ct_res, &mut ctxt_0);
            clear += clear_0;

            let dec_res = cks.decrypt(&ct_res);

            assert_eq!(clear % modulus, dec_res);
        }
    }
}

create_parameterized_test!(shortint_compact_public_key_base_list_smart_sub);

fn shortint_compact_public_key_base_list_smart_sub(params: ClassicPBSParameters) {
    let keys = KEY_CACHE.get_from_param(params);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    let pk = crate::shortint::CompactPublicKey::new(cks);

    let mut rng = rand::rng();

    let modulus = cks.parameters().message_modulus().0;

    let max_ct: usize = 5;

    let mut first_clear_vec = Vec::with_capacity(max_ct);
    let mut second_clear_vec = Vec::with_capacity(max_ct);

    for _ in 0..(NB_TESTS / 2).min(5) {
        let num_ct_for_this_iter = rng.gen_range(1..=max_ct);
        first_clear_vec.truncate(0);
        second_clear_vec.truncate(0);
        for _ in 0..num_ct_for_this_iter {
            let clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen::<u64>() % modulus;

            first_clear_vec.push(clear_0);
            second_clear_vec.push(clear_1);
        }

        let first_compact_list = pk.encrypt_slice(&first_clear_vec);
        let second_compact_list = pk.encrypt_slice(&second_clear_vec);

        let mut first_expanded_vec = first_compact_list
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap();
        let mut second_expanded_vec = second_compact_list
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap();

        // decryption check
        for i in 0..num_ct_for_this_iter {
            let decrypted_0 = cks.decrypt(&first_expanded_vec[i]);
            let decrypted_1 = cks.decrypt(&second_expanded_vec[i]);

            assert_eq!(decrypted_0, first_clear_vec[i]);
            assert_eq!(decrypted_1, second_clear_vec[i]);
        }

        for _ in 0..NB_SUB_TEST {
            for i in 0..num_ct_for_this_iter {
                sks.smart_sub_assign(&mut first_expanded_vec[i], &mut second_expanded_vec[i]);
                first_clear_vec[i] = first_clear_vec[i].wrapping_sub(second_clear_vec[i]);

                let decrypted_0 = cks.decrypt(&first_expanded_vec[i]);
                let decrypted_1 = cks.decrypt(&second_expanded_vec[i]);

                assert_eq!(decrypted_0, first_clear_vec[i] % modulus);
                assert_eq!(decrypted_1, second_clear_vec[i] % modulus);
            }
        }
    }
}
