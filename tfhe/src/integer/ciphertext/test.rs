use crate::integer::ciphertext::compressed_ciphertext_list::*;
use crate::integer::ciphertext::ReRandomizationContext;
use crate::integer::key_switching_key::{KeySwitchingKeyBuildHelper, KeySwitchingKeyMaterial};
use crate::integer::{
    gen_keys, BooleanBlock, CompactPrivateKey, CompactPublicKey, IntegerKeyKind, RadixCiphertext,
    SignedRadixCiphertext,
};
use crate::shortint::parameters::test_params::{
    TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
};
use crate::shortint::parameters::{CompressionParameters, ReRandomizationParameters};
use crate::shortint::ShortintParameterSet;
use itertools::Itertools;
use rand::Rng;

const NB_TESTS: usize = 10;
const NUM_BLOCKS: usize = 32;

#[test]
fn test_ciphertext_re_randomization_after_compression() {
    let params = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();
    let comp_params = TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let cpk_params = TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;
    let ks_params = TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let rerand_params = ReRandomizationParameters::DedicatedCompactPublicKeyWithKeySwitch {
        dedicated_cpk_params: cpk_params,
        re_rand_ksk_params: ks_params,
    };

    test_ciphertext_re_randomization_afer_compression_impl(params, comp_params, rerand_params);
}

fn test_ciphertext_re_randomization_afer_compression_impl(
    params: ShortintParameterSet,
    comp_params: CompressionParameters,
    rerand_params: ReRandomizationParameters,
) {
    // dbg! create a dedicated function which takes parameters from which it can derive the CPK ?
    let (cpk_params, ks_params) = match rerand_params {
        ReRandomizationParameters::DedicatedCompactPublicKeyWithKeySwitch {
            dedicated_cpk_params,
            re_rand_ksk_params,
        } => (dedicated_cpk_params, Some(re_rand_ksk_params)),
        ReRandomizationParameters::DerivedCompactPublicKeyWithoutKeySwitch => {
            (params.try_into().unwrap(), None)
        }
    };

    let (cks, sks) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

    let private_compression_key = cks.new_compression_private_key(comp_params);

    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&private_compression_key);

    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);
    let ksk_material: Option<KeySwitchingKeyMaterial> = ks_params.map(|ks_params| {
        KeySwitchingKeyBuildHelper::new((&cpk_private_key, None), (&cks, &sks), ks_params).into()
    });
    let ksk_material = ksk_material.as_ref().map(|ksk| ksk.as_view());

    let rerand_domain_separator = *b"TFHE_Rrd";
    let compact_public_encryption_domain_separator = *b"TFHE_Enc";
    let metadata = b"lol".as_slice();

    let mut rng = rand::thread_rng();

    let message_modulus: u128 = cks.parameters().message_modulus().0 as u128;

    // Unsigned
    let modulus = message_modulus.pow(NUM_BLOCKS as u32);
    for _ in 0..NB_TESTS {
        let message = rng.gen::<u128>() % modulus;

        let ct = cks.encrypt_radix(message, NUM_BLOCKS);

        let mut builder = CompressedCiphertextListBuilder::new();

        builder.push(ct);

        let compressed = builder.build(&compression_key);

        let decompressed: RadixCiphertext = compressed.get(0, &decompression_key).unwrap().unwrap();

        let mut re_randomizer_context = ReRandomizationContext::new(
            rerand_domain_separator,
            [metadata],
            compact_public_encryption_domain_separator,
        );

        re_randomizer_context.add_ciphertext(&decompressed);

        let mut seed_gen = re_randomizer_context.finalize();

        let mut re_randomized = decompressed.clone();
        re_randomized
            .re_randomize(&cpk, ksk_material.as_ref(), seed_gen.next_seed().unwrap())
            .unwrap();

        assert_ne!(decompressed, re_randomized);

        let decrypted: u128 = cks.decrypt_radix(&re_randomized);
        assert_eq!(decrypted, message);
    }

    // Signed
    let modulus = message_modulus.pow((NUM_BLOCKS - 1) as u32) as i128;
    for _ in 0..NB_TESTS {
        let message = rng.gen::<i128>() % modulus;

        let ct = cks.encrypt_signed_radix(message, NUM_BLOCKS);

        let mut builder = CompressedCiphertextListBuilder::new();

        builder.push(ct);

        let compressed = builder.build(&compression_key);

        let decompressed: SignedRadixCiphertext =
            compressed.get(0, &decompression_key).unwrap().unwrap();

        let mut re_randomizer_context = ReRandomizationContext::new(
            rerand_domain_separator,
            [metadata],
            compact_public_encryption_domain_separator,
        );

        re_randomizer_context.add_ciphertext(&decompressed);

        let mut seed_gen = re_randomizer_context.finalize();

        let mut re_randomized = decompressed.clone();
        re_randomized
            .re_randomize(&cpk, ksk_material.as_ref(), seed_gen.next_seed().unwrap())
            .unwrap();

        assert_ne!(decompressed, re_randomized);

        let decrypted: i128 = cks.decrypt_signed_radix(&re_randomized);
        assert_eq!(decrypted, message);
    }

    // Boolean
    for _ in 0..NB_TESTS {
        let messages = [false, true];

        let cts = messages
            .iter()
            .map(|message| cks.encrypt_bool(*message))
            .collect_vec();

        let mut builder = CompressedCiphertextListBuilder::new();

        builder.extend(cts.into_iter());

        let compressed = builder.build(&compression_key);

        for (i, message) in messages.iter().enumerate() {
            let decompressed: BooleanBlock =
                compressed.get(i, &decompression_key).unwrap().unwrap();

            let mut re_randomizer_context = ReRandomizationContext::new(
                rerand_domain_separator,
                [metadata],
                compact_public_encryption_domain_separator,
            );

            re_randomizer_context.add_ciphertext(&decompressed);

            let mut seed_gen = re_randomizer_context.finalize();

            let mut re_randomized = decompressed.clone();
            re_randomized
                .re_randomize(&cpk, ksk_material.as_ref(), seed_gen.next_seed().unwrap())
                .unwrap();

            assert_ne!(decompressed, re_randomized);

            let decrypted = cks.decrypt_bool(&decompressed);
            assert_eq!(decrypted, *message);
        }
    }
}
