use crate::integer::ciphertext::{
    CompactCiphertextListBuilder, DataKind, IntegerCompactCiphertextListExpansionMode,
};
use crate::integer::key_switching_key::KeySwitchingKey;
use crate::integer::{
    ClientKey, CompactPrivateKey, CompactPublicKey, IntegerCiphertext, ServerKey,
};
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
};
use crate::shortint::parameters::*;
use crate::strings::ciphertext::{ClearString, FheString, GenericPatternRef};

/// Parameters that are compatible with strings and that can be used without casting: both the
/// tested block widths (1 and 2 bits) since the number of blocks per char differs between them
const NO_CASTING_PARAMS: [ClassicPBSParameters; 2] = [
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
];

#[test]
fn test_compact_list_with_string_casting() {
    let pke_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let ksk_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let fhe_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let cks = ClientKey::new(fhe_params);
    let sk = ServerKey::new_radix_server_key(&cks);

    let compact_private_key = CompactPrivateKey::new(pke_params);
    let ksk = KeySwitchingKey::new((&compact_private_key, None), (&cks, &sk), ksk_params);
    let pk = CompactPublicKey::new(&compact_private_key);

    let string = ClearString::new("Hello, world".to_string());
    let string2 = ClearString::new("dlorw, olleH".to_string());

    let mut builder = CompactCiphertextListBuilder::new(&pk);
    builder
        .push(1u32)
        .push(&string)
        .push_string_with_padding(&string2, 19);

    {
        let list = builder.build();
        let expander = list
            .expand(
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()),
            )
            .unwrap();
        let expanded_string: FheString = expander.get(1).unwrap().unwrap();
        let decrypted_string = crate::strings::ClientKey::new(&cks).decrypt_ascii(&expanded_string);
        assert!(!expanded_string.is_padded());
        assert_eq!(&decrypted_string, string.str());

        let expander = list
            .expand(
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()),
            )
            .unwrap();
        let expanded_string: FheString = expander.get(2).unwrap().unwrap();
        let decrypted_string = crate::strings::ClientKey::new(&cks).decrypt_ascii(&expanded_string);
        assert!(expanded_string.is_padded());
        assert_eq!(&decrypted_string, string2.str());
    }

    {
        let list = builder.build_packed().unwrap();
        let expander = list
            .expand(
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()),
            )
            .unwrap();
        let expanded_string: FheString = expander.get(1).unwrap().unwrap();
        let decrypted_string = crate::strings::ClientKey::new(&cks).decrypt_ascii(&expanded_string);
        assert!(!expanded_string.is_padded());
        assert_eq!(&decrypted_string, string.str());

        let expander = list
            .expand(
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()),
            )
            .unwrap();
        let expanded_string: FheString = expander.get(2).unwrap().unwrap();
        let decrypted_string = crate::strings::ClientKey::new(&cks).decrypt_ascii(&expanded_string);
        assert!(expanded_string.is_padded());
        assert_eq!(&decrypted_string, string2.str());
    }
}

#[test]
fn test_compact_list_with_string_no_casting() {
    for fhe_params in NO_CASTING_PARAMS {
        test_compact_list_with_string_no_casting_impl(fhe_params);
    }
}

fn test_compact_list_with_string_no_casting_impl(fhe_params: ClassicPBSParameters) {
    let cks = ClientKey::new(fhe_params);
    let sk = ServerKey::new_radix_server_key(&cks);

    let pk = CompactPublicKey::new(&cks);

    let string = ClearString::new("Hello, world".to_string());
    let string2 = ClearString::new("dlorw, olleH".to_string());

    let mut builder = CompactCiphertextListBuilder::new(&pk);
    builder
        .push(1u32)
        .push(&string)
        .push_string_with_padding(&string2, 19);

    {
        let list = builder.build();
        let expander = list
            .expand(IntegerCompactCiphertextListExpansionMode::UnpackAndSanitizeIfNecessary(&sk))
            .unwrap();
        let expanded_string: FheString = expander.get(1).unwrap().unwrap();
        let decrypted_string = crate::strings::ClientKey::new(&cks).decrypt_ascii(&expanded_string);
        assert!(!expanded_string.is_padded());
        assert_eq!(&decrypted_string, string.str());

        let expander = list
            .expand(IntegerCompactCiphertextListExpansionMode::UnpackAndSanitizeIfNecessary(&sk))
            .unwrap();
        let expanded_string: FheString = expander.get(2).unwrap().unwrap();
        let decrypted_string = crate::strings::ClientKey::new(&cks).decrypt_ascii(&expanded_string);
        assert!(expanded_string.is_padded());
        assert_eq!(&decrypted_string, string2.str());
    }

    {
        let list = builder.build_packed().unwrap();
        let expander = list
            .expand(IntegerCompactCiphertextListExpansionMode::UnpackAndSanitizeIfNecessary(&sk))
            .unwrap();
        let expanded_string: FheString = expander.get(1).unwrap().unwrap();
        let decrypted_string = crate::strings::ClientKey::new(&cks).decrypt_ascii(&expanded_string);
        assert!(!expanded_string.is_padded());
        assert_eq!(&decrypted_string, string.str());

        let expander = list
            .expand(IntegerCompactCiphertextListExpansionMode::UnpackAndSanitizeIfNecessary(&sk))
            .unwrap();
        let expanded_string: FheString = expander.get(2).unwrap().unwrap();
        let decrypted_string = crate::strings::ClientKey::new(&cks).decrypt_ascii(&expanded_string);
        assert!(expanded_string.is_padded());
        assert_eq!(&decrypted_string, string2.str());
    }
}

#[test]
fn test_compact_list_with_malicious_string_casting() {
    let pke_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let ksk_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let fhe_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let cks = ClientKey::new(fhe_params);
    let sk = ServerKey::new_radix_server_key(&cks);

    let compact_private_key = CompactPrivateKey::new(pke_params);
    let ksk = KeySwitchingKey::new((&compact_private_key, None), (&cks, &sk), ksk_params);
    let pk = CompactPublicKey::new(&compact_private_key);

    let mut builder = CompactCiphertextListBuilder::new(&pk);

    let string = "Hello, world!";
    for string_byte in string.as_bytes().iter().copied() {
        let alter = 1 << 7;
        builder.push(alter | string_byte);
    }
    builder.info = vec![DataKind::String {
        n_chars: string.len() as u32,
        padded: false,
    }];

    {
        let list = builder
            .build()
            .expand(
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()),
            )
            .unwrap();
        let expanded_string: FheString = list.get(0).unwrap().unwrap();
        let decrypted_string = crate::strings::ClientKey::new(&cks).decrypt_ascii(&expanded_string);
        assert_eq!(&decrypted_string, &string);
    }

    {
        let list = builder
            .build_packed()
            .unwrap()
            .expand(
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()),
            )
            .unwrap();
        let expanded_string: FheString = list.get(0).unwrap().unwrap();
        let decrypted_string = crate::strings::ClientKey::new(&cks).decrypt_ascii(&expanded_string);
        assert_eq!(&decrypted_string, &string);
    }
}

#[test]
fn test_compact_list_with_malicious_string_no_casting() {
    for fhe_params in NO_CASTING_PARAMS {
        test_compact_list_with_malicious_string_no_casting_impl(fhe_params);
    }
}

fn test_compact_list_with_malicious_string_no_casting_impl(fhe_params: ClassicPBSParameters) {
    let cks = ClientKey::new(fhe_params);
    let sk = ServerKey::new_radix_server_key(&cks);

    let pk = CompactPublicKey::new(&cks);

    let mut builder = CompactCiphertextListBuilder::new(&pk);

    let string = "Hello, world!";
    for string_byte in string.as_bytes().iter().copied() {
        let alter = 1 << 7;
        // A u8 is stored on the same number of blocks as an ascii char
        builder.push(alter | string_byte);
    }
    builder.info = vec![DataKind::String {
        n_chars: string.len() as u32,
        padded: false,
    }];

    {
        let list = builder
            .build()
            .expand(IntegerCompactCiphertextListExpansionMode::UnpackAndSanitizeIfNecessary(&sk))
            .unwrap();
        let expanded_string: FheString = list.get(0).unwrap().unwrap();
        let decrypted_string = crate::strings::ClientKey::new(&cks).decrypt_ascii(&expanded_string);
        assert_eq!(&decrypted_string, &string);
    }

    {
        let list = builder
            .build_packed()
            .unwrap()
            .expand(IntegerCompactCiphertextListExpansionMode::UnpackAndSanitizeIfNecessary(&sk))
            .unwrap();
        let expanded_string: FheString = list.get(0).unwrap().unwrap();
        let decrypted_string = crate::strings::ClientKey::new(&cks).decrypt_ascii(&expanded_string);
        assert_eq!(&decrypted_string, &string);
    }
}

/// Strings coming from a compact list must have the same layout as strings encrypted with the
/// client key, otherwise operations mixing them silently give wrong results.
#[test]
fn test_compact_list_string_interoperability() {
    for fhe_params in NO_CASTING_PARAMS {
        test_compact_list_string_interoperability_impl(fhe_params);
    }
}

fn test_compact_list_string_interoperability_impl(fhe_params: ClassicPBSParameters) {
    let cks = ClientKey::new(fhe_params);
    let sk = ServerKey::new_radix_server_key(&cks);
    let pk = CompactPublicKey::new(&cks);

    let str_cks = crate::strings::ClientKey::new(&cks);
    let str_sk = crate::strings::ServerKey::new(&sk);

    let expected_blocks_per_char = fhe_params
        .message_modulus
        .num_blocks_per_ascii_char()
        .unwrap();

    let clear = ClearString::new("hello".to_string());
    let clear_upper = ClearString::new("HELLO".to_string());

    let direct = str_cks.encrypt_ascii(clear.str(), None);
    assert_eq!(
        direct.chars()[0].ciphertext().blocks().len(),
        expected_blocks_per_char
    );

    let mut builder = CompactCiphertextListBuilder::new(&pk);
    builder
        .push(&clear)
        .push_string_with_padding(&clear, 3)
        .push_string_with_fixed_size(&clear, 8);

    for list in [builder.build(), builder.build_packed().unwrap()] {
        let expander = list
            .expand(IntegerCompactCiphertextListExpansionMode::UnpackAndSanitizeIfNecessary(&sk))
            .unwrap();

        for idx in 0..3 {
            let from_list: FheString = expander.get(idx).unwrap().unwrap();

            assert_eq!(
                from_list.chars()[0].ciphertext().blocks().len(),
                expected_blocks_per_char
            );
            assert_eq!(&str_cks.decrypt_ascii(&from_list), clear.str());

            // Comparison with a clear pattern
            let res = str_sk.eq(&from_list, GenericPatternRef::Clear(&clear));
            assert!(cks.decrypt_bool(&res));
            let res = str_sk.eq(&from_list, GenericPatternRef::Clear(&clear_upper));
            assert!(!cks.decrypt_bool(&res));

            // Comparison with a string encrypted by the client key
            let res = str_sk.eq(&from_list, GenericPatternRef::Enc(&direct));
            assert!(cks.decrypt_bool(&res));
            let res = str_sk.eq(&direct, GenericPatternRef::Enc(&from_list));
            assert!(cks.decrypt_bool(&res));

            // Operation that goes through the uint representation
            let upper = str_sk.to_uppercase(&from_list);
            assert_eq!(&str_cks.decrypt_ascii(&upper), clear_upper.str());
        }
    }
}

/// Checks that the sanitization of the last block of each char clears the most significant bit
/// of the byte whatever the number of bits stored in that block, while keeping the other bits.
#[test]
fn test_compact_list_string_last_block_sanitization() {
    for fhe_params in NO_CASTING_PARAMS {
        test_compact_list_string_last_block_sanitization_impl(fhe_params);
    }
}

fn test_compact_list_string_last_block_sanitization_impl(fhe_params: ClassicPBSParameters) {
    let cks = ClientKey::new(fhe_params);
    let sk = ServerKey::new_radix_server_key(&cks);
    let pk = CompactPublicKey::new(&cks);

    let message_modulus = fhe_params.message_modulus.0;
    let bits_per_block = message_modulus.ilog2();
    let blocks_per_char = fhe_params
        .message_modulus
        .num_blocks_per_ascii_char()
        .unwrap();

    // Digits have their bit 6 cleared, so setting all the bits of the last block has a visible
    // effect on the bits that must be kept (when the last block holds more than 1 bit)
    let string = "0123";
    let clear = ClearString::new(string.to_string());

    let mut builder = CompactCiphertextListBuilder::new(&pk);
    builder.push(&clear);
    assert_eq!(builder.messages.len(), string.len() * blocks_per_char);

    // Set all the bits of the last block of each char
    for char_idx in 0..string.len() {
        builder.messages[char_idx * blocks_per_char + blocks_per_char - 1] = message_modulus - 1;
    }

    let last_block_shift = (blocks_per_char as u32 - 1) * bits_per_block;
    let expected: String = string
        .bytes()
        .map(|byte| {
            // The bits of the last block are set, but bit 7 is cleared by the sanitization
            let altered = byte | (((message_modulus - 1) << last_block_shift) as u8);
            char::from(altered & 0x7F)
        })
        .collect();
    assert!(expected.is_ascii());
    // Sanity check of the test itself: the alteration must be visible on 2 bits blocks
    if bits_per_block == 2 {
        assert_eq!(expected, "pqrs");
    } else {
        assert_eq!(expected, string);
    }

    for list in [builder.build(), builder.build_packed().unwrap()] {
        let expander = list
            .expand(IntegerCompactCiphertextListExpansionMode::UnpackAndSanitizeIfNecessary(&sk))
            .unwrap();
        let from_list: FheString = expander.get(0).unwrap().unwrap();

        for (enc_char, expected_char) in from_list.chars().iter().zip(expected.bytes()) {
            let byte: u8 = cks.decrypt_radix(enc_char.ciphertext());
            assert_eq!(byte, expected_char);
        }
    }
}

#[test]
fn test_strings_keys_reject_incompatible_parameters() {
    // 3 bits per block: a char cannot be split into blocks of equal width
    let cks = ClientKey::new(TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128);
    let sk = ServerKey::new_radix_server_key(&cks);
    assert!(!cks.is_compatible_with_strings());
    assert!(!sk.is_compatible_with_strings());
    assert!(crate::strings::ClientKey::try_new(&cks).is_err());
    assert!(crate::strings::ServerKey::try_new(&sk).is_err());

    // Carry modulus different from the message modulus
    let cks = ClientKey::new(TEST_PARAM_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M128);
    let sk = ServerKey::new_radix_server_key(&cks);
    assert!(!cks.is_compatible_with_strings());
    assert!(!sk.is_compatible_with_strings());
    assert!(crate::strings::ClientKey::try_new(&cks).is_err());
    assert!(crate::strings::ServerKey::try_new(&sk).is_err());

    for fhe_params in NO_CASTING_PARAMS {
        let cks = ClientKey::new(fhe_params);
        let sk = ServerKey::new_radix_server_key(&cks);
        assert!(cks.is_compatible_with_strings());
        assert!(sk.is_compatible_with_strings());
        assert!(crate::strings::ClientKey::try_new(&cks).is_ok());
        assert!(crate::strings::ServerKey::try_new(&sk).is_ok());
    }
}
