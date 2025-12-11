use crate::integer::ciphertext::compressed_ciphertext_list::*;
use crate::integer::ciphertext::ReRandomizationContext;
use crate::integer::key_switching_key::{KeySwitchingKeyBuildHelper, KeySwitchingKeyMaterial};
use crate::integer::{
    gen_keys, BooleanBlock, CompactPrivateKey, CompactPublicKey, IntegerKeyKind, RadixCiphertext,
    SignedRadixCiphertext,
};
use crate::shortint::parameters::test_params::TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128;
use crate::shortint::ShortintParameterSet;
use itertools::Itertools;
use rand::Rng;

const NB_TESTS: usize = 10;
const NUM_BLOCKS: usize = 32;

#[test]
fn test_ciphertext_re_randomization_after_compression() {
    let meta_param = TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128;
    let params = meta_param.compute_parameters;
    let comp_params = meta_param.compression_parameters.unwrap();
    let cpk_params = meta_param
        .dedicated_compact_public_key_parameters
        .unwrap()
        .pke_params;
    let ks_params = meta_param
        .dedicated_compact_public_key_parameters
        .unwrap()
        .re_randomization_parameters
        .unwrap();

    let (cks, sks) = gen_keys::<ShortintParameterSet>(params.into(), IntegerKeyKind::Radix);

    let private_compression_key = cks.new_compression_private_key(comp_params);

    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&private_compression_key);

    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);
    let ksk_material: KeySwitchingKeyMaterial =
        KeySwitchingKeyBuildHelper::new((&cpk_private_key, None), (&cks, &sks), ks_params).into();
    let ksk_material = ksk_material.as_view();

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
            .re_randomize(&cpk, &ksk_material, seed_gen.next_seed().unwrap())
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
            .re_randomize(&cpk, &ksk_material, seed_gen.next_seed().unwrap())
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
                .re_randomize(&cpk, &ksk_material, seed_gen.next_seed().unwrap())
                .unwrap();

            assert_ne!(decompressed, re_randomized);

            let decrypted = cks.decrypt_bool(&decompressed);
            assert_eq!(decrypted, *message);
        }
    }
}
