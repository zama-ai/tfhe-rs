use crate::integer::key_switching_key::KeySwitchingKey;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::{gen_keys, CompressedPublicKey, IntegerKeyKind, PublicKey, RadixCiphertext};
use crate::integer::{IntegerCiphertext, RadixClientKey};
use crate::shortint::parameters::ShortintKeySwitchingParameters;
use crate::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

macro_rules! create_parametrized_test {
    (
        $name:ident {
            $($(#[$cfg:meta])* $param:ident),*
            $(,)?
        }
    ) => {
        ::paste::paste! {
            $(
                #[test]
                $(#[$cfg])*
                fn [<test_ $name _ $param:lower>]() {
                    $name($param)
                }
            )*
        }
    };
    ($name:ident)=> {
        create_parametrized_test!($name
        {
            coverage => {
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS
            },
            no_coverage => {
                PARAM_MESSAGE_1_CARRY_1_KS_PBS,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                PARAM_MESSAGE_4_CARRY_4_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
            }
        });
    };

    ($name:ident { coverage => {$($param_cover:ident),* $(,)?}, no_coverage => {$($param_no_cover:ident),* $(,)?} }) => {
        ::paste::paste! {
            $(
                #[test]
                #[cfg(tarpaulin)]
                fn [<test_ $name _ $param_cover:lower>]() {
                    $name($param_cover)
                }
            )*
            $(
                #[test]
                #[cfg(not(tarpaulin))]
                fn [<test_ $name _ $param_no_cover:lower>]() {
                    $name($param_no_cover)
                }
            )*
        }
    };
}
macro_rules! create_parametrized_test_classical_params {
    (
        $name:ident
    ) => {
        $crate::integer::tests::create_parametrized_test!($name {
            coverage => {
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            },
            no_coverage => {
                PARAM_MESSAGE_1_CARRY_1_KS_PBS,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                PARAM_MESSAGE_4_CARRY_4_KS_PBS
            }
        });
    };
}
pub(crate) use {create_parametrized_test, create_parametrized_test_classical_params};

#[test]
fn pke_ap() {
    let num_block = 4;

    let param_pke = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let param_fhe = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let param_ksk = ShortintKeySwitchingParameters::new(param_fhe.ks_base_log, param_fhe.ks_level);

    let (cks_pke, sks_pke) = gen_keys(param_pke, IntegerKeyKind::Radix);
    let pk = crate::integer::public_key::CompactPublicKey::new(&cks_pke);

    let (cks_fhe, sks_fhe) = gen_keys(param_fhe, IntegerKeyKind::Radix);

    let ksk = KeySwitchingKey::new((&cks_pke, &sks_pke), (&cks_fhe, &sks_fhe), param_ksk);

    // Encrypt a value and cast
    let ct1 = pk.encrypt_radix_compact(228u8, num_block);
    let ct1_extracted: &RadixCiphertext = &ct1.expand()[0];

    // KSK Cast
    let mut ct2 = ksk.cast(ct1_extracted);

    // PBS to clean
    let acc = sks_fhe.key.generate_lookup_table(|x| x);
    for blocks in ct2.blocks_mut() {
        sks_fhe.key.apply_lookup_table_assign(blocks, &acc)
    }

    // Classical AP: DP, KS, PBS
    sks_fhe.scalar_mul_assign_parallelized(&mut ct2, 255);

    // High level decryption and test
    let clear: u64 = cks_fhe.decrypt_radix(&ct2);
    //let clear: u64 = cks_fhe.decrypt_radix(&ct1_extracted[0]);
    assert_eq!(clear, (228 * 255) % (1 << (num_block + 1)));
}
