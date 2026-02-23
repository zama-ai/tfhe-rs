use crate::integer::ciphertext::CompressedCiphertextListBuilder;
use crate::integer::{gen_keys, IntegerKeyKind};
use crate::shortint::parameters::*;
use crate::strings::ciphertext::FheString;
use crate::strings::ClientKey as StringClientKey;
use rand::prelude::*;

#[test]
fn test_compressed_list_with_strings() {
    let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();
    const NB_TESTS: usize = 5;
    const MAX_STRING_SIZE: u32 = 255;
    const MAX_PADDING_SIZE: u32 = 50;

    let (cks, _) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

    let private_compression_key =
        cks.new_compression_private_key(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&private_compression_key);

    let cks = StringClientKey::new(cks);

    let mut rng = rand::rng();

    let printable_ascii_range = 32..=126u8; // Range of printable chars

    for _ in 0..NB_TESTS {
        let len = rng.gen_range(0..MAX_STRING_SIZE);
        let ascci_bytes = (0..len)
            .map(|_| rng.gen_range(printable_ascii_range.clone()))
            .collect::<Vec<_>>();
        let clear_string1 = String::from_utf8(ascci_bytes).unwrap();
        let string1 = cks.encrypt_ascii(&clear_string1, None);

        let len = rng.gen_range(0..MAX_STRING_SIZE);
        let padding = rng.gen_range(0..MAX_PADDING_SIZE);
        let ascci_bytes = (0..len)
            .map(|_| rng.gen_range(printable_ascii_range.clone()))
            .collect::<Vec<_>>();
        let clear_string2 = String::from_utf8(ascci_bytes).unwrap();
        let string2 = cks.encrypt_ascii(&clear_string2, Some(padding));

        let mut builder = CompressedCiphertextListBuilder::new();
        builder.push(string1);
        builder.push(string2);
        let compressed = builder.build(&compression_key);

        let s1: FheString = compressed.get(0, &decompression_key).unwrap().unwrap();
        let decrypted = cks.decrypt_ascii(&s1);
        assert_eq!(decrypted, clear_string1);

        let s2: FheString = compressed.get(1, &decompression_key).unwrap().unwrap();
        let decrypted = cks.decrypt_ascii(&s2);
        assert_eq!(decrypted, clear_string2);
    }
}

#[test]
fn test_compressed_list_empty_string() {
    let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();
    let (cks, _) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

    let private_compression_key =
        cks.new_compression_private_key(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&private_compression_key);

    let cks = StringClientKey::new(cks);

    let clear_empty = String::new();
    let empty = cks.encrypt_ascii(&clear_empty, None);

    let clear_string = String::from("not empty");
    let string = cks.encrypt_ascii(&clear_string, None);

    // Try to compress 2 empty strings with one not empty in the middle
    let mut builder = CompressedCiphertextListBuilder::new();
    builder.push(empty.clone());
    builder.push(string);
    builder.push(empty);
    let compressed = builder.build(&compression_key);

    assert_eq!(compressed.len(), 3);

    let s1: FheString = compressed.get(0, &decompression_key).unwrap().unwrap();
    let decrypted = cks.decrypt_ascii(&s1);
    assert_eq!(decrypted, clear_empty);

    let s2: FheString = compressed.get(1, &decompression_key).unwrap().unwrap();
    let decrypted = cks.decrypt_ascii(&s2);
    assert_eq!(decrypted, clear_string);

    let s3: FheString = compressed.get(2, &decompression_key).unwrap().unwrap();
    let decrypted = cks.decrypt_ascii(&s3);
    assert_eq!(decrypted, clear_empty);
}
