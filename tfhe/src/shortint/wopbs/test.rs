use crate::shortint::keycache::KEY_CACHE_WOPBS;
use crate::shortint::parameters::parameters_wopbs::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use crate::shortint::wopbs::WopbsKey;
use crate::shortint::{gen_keys, ClassicPBSParameters};
use rand::Rng;

const NB_TESTS: usize = 1;

#[cfg(not(tarpaulin))]
macro_rules! create_parameterized_test{
    ($name:ident { $( ($sks_param:ident, $wopbs_param:ident) ),* }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_ $name _ $wopbs_param:lower>]() {
                $name(($sks_param, $wopbs_param))
            }
            )*
        }
    };
    ($name:ident)=> {
        create_parameterized_test!($name
        {
            (TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS),
            (TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS),
            (TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64, LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS),
            (TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64, LEGACY_WOPBS_PARAM_MESSAGE_4_CARRY_4_KS_PBS)
        });
    };
}

#[cfg(not(tarpaulin))]
macro_rules! create_parameterized_wopbs_only_test{
    ($name:ident { $( $wopbs_param:ident ),* }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_ $name _ $wopbs_param:lower>]() {
                $name($wopbs_param)
            }
            )*
        }
    };
    ($name:ident)=> {
        create_parameterized_wopbs_only_test!($name
        {
            LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            LEGACY_WOPBS_PARAM_MESSAGE_4_CARRY_4_KS_PBS
        });
    };
}

// Test against a small subset of parameters to speed up coverage tests
#[cfg(tarpaulin)]
macro_rules! create_parameterized_test{
    ($name:ident { $( ($sks_param:ident, $wopbs_param:ident) ),* }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_ $name _ $wopbs_param:lower>]() {
                $name(($sks_param, $wopbs_param))
            }
            )*
        }
    };
    ($name:ident)=> {
        create_parameterized_test!($name
        {
            (TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS)
        });
    };
}

#[cfg(tarpaulin)]
macro_rules! create_parameterized_wopbs_only_test{
    ($name:ident { $( $wopbs_param:ident ),* }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_ $name _ $wopbs_param:lower>]() {
                $name($wopbs_param)
            }
            )*
        }
    };
    ($name:ident)=> {
        create_parameterized_wopbs_only_test!($name
        {
            LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS
        });
    };
}

create_parameterized_test!(generate_lut);
create_parameterized_test!(generate_lut_modulus);
#[cfg(not(tarpaulin))]
create_parameterized_wopbs_only_test!(generate_lut_modulus_not_power_of_two);
#[cfg(not(tarpaulin))]
create_parameterized_wopbs_only_test!(generate_lut_wop_only {
    LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_4_CARRY_4_KS_PBS
});

fn generate_lut(params: (ClassicPBSParameters, WopbsParameters)) {
    let keys = KEY_CACHE_WOPBS.get_from_param(params);
    let (cks, sks, wopbs_key) = (keys.client_key(), keys.server_key(), keys.wopbs_key());
    let mut rng = rand::rng();

    let mut tmp = 0;
    for _ in 0..NB_TESTS {
        let message_modulus = params.0.message_modulus.0;
        let m = rng.gen::<u64>() % message_modulus;
        let ct = cks.encrypt(m);
        let lut = wopbs_key.generate_lut(&ct, |x| x % message_modulus);
        let ct_res = wopbs_key.programmable_bootstrapping(sks, &ct, &lut);

        let res = cks.decrypt(&ct_res);
        if res != (m % message_modulus) {
            tmp += 1;
        }
    }
    if 0 != tmp {
        println!("______");
        println!("failure rate {tmp:?}/{NB_TESTS:?}");
        println!("______");
    }
    assert_eq!(0, tmp);
}

#[cfg(not(tarpaulin))]
fn generate_lut_wop_only(params: WopbsParameters) {
    let (cks, sks) = gen_keys(params);
    let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(
        cks.as_view().try_into().unwrap(),
        sks.as_view().try_into().unwrap(),
    );
    let mut rng = rand::rng();

    let mut tmp = 0;
    for _ in 0..NB_TESTS {
        let message_modulus = params.message_modulus.0;
        let m = rng.gen::<u64>() % message_modulus;
        let ct = cks.encrypt(m);
        let lut = wopbs_key.generate_lut(&ct, |x| x % message_modulus);
        let ct_res = wopbs_key.wopbs(&ct, &lut);

        let res = cks.decrypt(&ct_res);
        if res != (m % message_modulus) {
            tmp += 1;
        }
    }
    if 0 != tmp {
        println!("______");
        println!("failure rate {tmp:?}/{NB_TESTS:?}");
        println!("______");
    }
    assert_eq!(0, tmp);
}

fn generate_lut_modulus(params: (ClassicPBSParameters, WopbsParameters)) {
    let keys = KEY_CACHE_WOPBS.get_from_param(params);
    let (cks, sks, wopbs_key) = (keys.client_key(), keys.server_key(), keys.wopbs_key());
    let mut rng = rand::rng();

    for _ in 0..NB_TESTS {
        let message_modulus = MessageModulus(params.0.message_modulus.0 - 1);
        let m = rng.gen::<u64>() % message_modulus.0;

        let ct = cks.encrypt_with_message_modulus(m, message_modulus);

        let ct = wopbs_key.keyswitch_to_wopbs_params(sks, &ct);
        let lut = wopbs_key.generate_lut(&ct, |x| (x * x) % message_modulus.0);
        let ct_res = wopbs_key.wopbs(&ct, &lut);
        let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);

        let res = cks.decrypt(&ct_res);
        assert_eq!(res, (m * m) % message_modulus.0);
    }
}

// Coverage time is taking to long due to key generation (around 400s)
// Keycache cannot be applied without turning the test into a flaky one.
#[cfg(not(tarpaulin))]
fn generate_lut_modulus_not_power_of_two(params: WopbsParameters) {
    let (cks, sks) = gen_keys(params);
    let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(
        cks.as_view().try_into().unwrap(),
        sks.as_view().try_into().unwrap(),
    );

    let mut rng = rand::rng();

    for _ in 0..NB_TESTS {
        let message_modulus = MessageModulus(params.message_modulus.0 - 1);

        let m = rng.gen::<u64>() % message_modulus.0;
        let ct = cks.encrypt_native_crt(m, message_modulus);
        let lut = wopbs_key.generate_lut_native_crt(&ct, |x| (x * x) % message_modulus.0);

        let ct_res = wopbs_key.programmable_bootstrapping_native_crt(&ct, &lut);
        let res = cks.decrypt_message_native_crt(&ct_res, message_modulus);
        assert_eq!(res, (m * m) % message_modulus.0);
    }
}
