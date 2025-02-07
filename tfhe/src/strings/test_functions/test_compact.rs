use crate::integer::ciphertext::{
    CompactCiphertextListBuilder, DataKind, IntegerCompactCiphertextListExpansionMode,
};
use crate::integer::key_switching_key::KeySwitchingKey;
use crate::integer::{ClientKey, CompactPrivateKey, CompactPublicKey, ServerKey};
use crate::shortint::parameters::*;
use crate::strings::ciphertext::{ClearString, FheString};

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
    let fhe_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

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
    let fhe_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let cks = ClientKey::new(fhe_params);
    let sk = ServerKey::new_radix_server_key(&cks);

    let pk = CompactPublicKey::new(&cks);

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
