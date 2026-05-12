use rand::{thread_rng, Rng};

use crate::conformance::ListSizeConstraint;
#[cfg(feature = "zk-pok")]
use crate::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
use crate::nist_submission::parameters::{
    NIST_META_PARAMS_2_2, NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::nist_submission::{
    preproc_eval, set_server_key, ClientKey, CompactCiphertextList,
    CompactCiphertextListConformanceParams, CompactPublicKey, CompressedXofKeySet, Config,
    FheUint32, NormalizedHammingWeightBound, SquashedNoiseFheUint, Tag,
};
#[cfg(feature = "zk-pok")]
use crate::nist_submission::{CompactPkeCrs, ZkComputeLoad};

use crate::nist_submission::prelude::*;

pub fn erc20_transfer(
    from_amount: &FheUint32,
    to_amount: &FheUint32,
    amount: &FheUint32,
) -> (FheUint32, FheUint32) {
    let has_enough_funds = (from_amount).ge(amount);
    let amount_to_transfer = amount * FheUint32::cast_from(has_enough_funds);

    let new_to_amount = to_amount + &amount_to_transfer;
    let new_from_amount = from_amount - &amount_to_transfer;

    (new_from_amount, new_to_amount)
}

#[allow(clippy::too_many_arguments, reason = "This is a test")]
fn run_erc20_test(
    mut a: FheUint32,
    mut b: FheUint32,
    mut c: FheUint32,
    clear_a: u32,
    clear_b: u32,
    clear_c: u32,
    ck: &ClientKey,
    pk: &CompactPublicKey,
) {
    let decrypted_a: u32 = a.decrypt(ck);
    let decrypted_b: u32 = b.decrypt(ck);
    let decrypted_c: u32 = c.decrypt(ck);
    assert_eq!(decrypted_a, clear_a, "After expansion: a mismatch");
    assert_eq!(decrypted_b, clear_b, "After expansion: b mismatch");
    assert_eq!(decrypted_c, clear_c, "After expansion: c mismatch");

    preproc_eval(
        &mut [&mut a, &mut b, &mut c],
        b"nist_submission_test_erc20",
        pk,
    )
    .unwrap();

    let decrypted_a: u32 = a.decrypt(ck);
    let decrypted_b: u32 = b.decrypt(ck);
    let decrypted_c: u32 = c.decrypt(ck);
    assert_eq!(decrypted_a, clear_a, "After preproc_eval: a mismatch");
    assert_eq!(decrypted_b, clear_b, "After preproc_eval: b mismatch");
    assert_eq!(decrypted_c, clear_c, "After preproc_eval: c mismatch");

    let (new_from, new_to) = erc20_transfer(&a, &b, &c);

    let has_enough_funds = clear_a >= clear_c;
    let amount_to_transfer = if has_enough_funds { clear_c } else { 0 };
    let expected_from = clear_a.wrapping_sub(amount_to_transfer);
    let expected_to = clear_b.wrapping_add(amount_to_transfer);

    let decrypted_from: u32 = new_from.decrypt(ck);
    let decrypted_to: u32 = new_to.decrypt(ck);
    assert_eq!(
        decrypted_from, expected_from,
        "After erc20_transfer: from mismatch"
    );
    assert_eq!(
        decrypted_to, expected_to,
        "After erc20_transfer: to mismatch"
    );

    let ns_from: SquashedNoiseFheUint = new_from.squash_noise().unwrap();
    let ns_to: SquashedNoiseFheUint = new_to.squash_noise().unwrap();

    let decrypted_ns_from: u32 = ns_from.decrypt(ck);
    let decrypted_ns_to: u32 = ns_to.decrypt(ck);
    assert_eq!(
        decrypted_ns_from, expected_from,
        "After squash_noise: from mismatch"
    );
    assert_eq!(
        decrypted_ns_to, expected_to,
        "After squash_noise: to mismatch"
    );
}

#[test]
fn complete_test() {
    let config = Config::from(NIST_META_PARAMS_2_2);

    let (ck, compressed_key_set) = CompressedXofKeySet::generate(
        config,
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        128,
        NormalizedHammingWeightBound::new(0.75).unwrap(),
        Tag::from("nist_submission"),
    )
    .expect("Failed to generate a CompressedXofKeySet");

    let (pk, sks) = compressed_key_set.decompress().into_raw_parts();

    let mut rng = thread_rng();

    let clear_a: u32 = rng.gen();
    let clear_b: u32 = rng.gen();
    let clear_c: u32 = rng.gen();

    set_server_key(sks);

    let list = CompactCiphertextList::builder(&pk)
        .push(clear_a)
        .push(clear_b)
        .push(clear_c)
        .build();

    let conformance_params =
        CompactCiphertextListConformanceParams::from_parameters_and_size_constraint(
            NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ListSizeConstraint::exact_size(3),
        )
        .allow_unpacked();
    assert!(list.is_conformant(&conformance_params));

    let expanded = list.expand().expect("Failed to expand the compact list");

    let a: FheUint32 = expanded.get(0).unwrap().unwrap();
    let b: FheUint32 = expanded.get(1).unwrap().unwrap();
    let c: FheUint32 = expanded.get(2).unwrap().unwrap();

    run_erc20_test(a, b, c, clear_a, clear_b, clear_c, &ck, &pk);
}

#[cfg(feature = "zk-pok")]
#[test]
fn complete_test_zk() {
    let config = Config::from(NIST_META_PARAMS_2_2);

    let (ck, compressed_key_set) = CompressedXofKeySet::generate(
        config,
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        128,
        NormalizedHammingWeightBound::new(0.75).unwrap(),
        Tag::from("nist_submission"),
    )
    .expect("Failed to generate a CompressedXofKeySet");

    let (pk, sks) = compressed_key_set.decompress().into_raw_parts();

    let mut rng = thread_rng();

    let clear_a: u32 = rng.gen();
    let clear_b: u32 = rng.gen();
    let clear_c: u32 = rng.gen();

    // Intentionally low max_num_bits to test multi-list proofs
    let crs = CompactPkeCrs::from_config(config, 32).expect("Failed to create CRS");

    let proven_list = CompactCiphertextList::builder(&pk)
        .push(clear_a)
        .push(clear_b)
        .push(clear_c)
        .build_with_proof(&crs, b"nist_zk_test", ZkComputeLoad::Proof)
        .expect("Failed to build proven compact list");

    let conformance_params =
        IntegerProvenCompactCiphertextListConformanceParams::from_crs_and_parameters(
            NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            &crs,
        )
        .allow_unpacked();
    assert!(proven_list.is_conformant(&conformance_params));

    set_server_key(sks);

    let expander = proven_list
        .verify_and_expand(&crs, &pk, b"nist_zk_test")
        .expect("Failed to verify and expand proven compact list");

    let a: FheUint32 = expander.get(0).unwrap().unwrap();
    let b: FheUint32 = expander.get(1).unwrap().unwrap();
    let c: FheUint32 = expander.get(2).unwrap().unwrap();

    run_erc20_test(a, b, c, clear_a, clear_b, clear_c, &ck, &pk);
}
