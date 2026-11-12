use crate::high_level_api::nist_submission::{preproc_eval, NistSubmissionReRandomize};
use crate::high_level_api::prelude::*;
use crate::high_level_api::tests::cpk_re_randomization::setup_re_rand_test;
use crate::high_level_api::{CompactPublicKey, CompressedCiphertextListBuilder, FheUint64};
use crate::shortint::parameters::v1_5::meta::cpu::V1_5_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
use crate::{set_server_key, ClientKey};

#[test]
fn test_dyn_rerand() {
    let params = V1_5_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
    let (cks, sks, cpk) = setup_re_rand_test(params);
    set_server_key(sks.decompress());
    execute_dyn_rerand_test(&cks, &cpk);
}

fn execute_dyn_rerand_test(cks: &ClientKey, cpk: &CompactPublicKey) {
    let clear_a = rand::random::<u64>();
    let clear_b = rand::random::<u64>();
    let mut a = FheUint64::encrypt(clear_a, cks);
    let mut b = FheUint64::encrypt(clear_b, cks);

    // Simulate a 256 bits hash added as metadata
    let rand_a: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
    let rand_b: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
    a.re_randomization_metadata_mut().set_data(&rand_a);
    b.re_randomization_metadata_mut().set_data(&rand_b);

    let mut builder = CompressedCiphertextListBuilder::new();
    builder.push(a);
    builder.push(b);
    let list = builder.build().unwrap();

    let mut a: FheUint64 = list.get(0).unwrap().unwrap();
    let mut b: FheUint64 = list.get(1).unwrap().unwrap();

    assert_eq!(a.re_randomization_metadata().data(), &rand_a);
    assert_eq!(b.re_randomization_metadata().data(), &rand_b);

    let mut dyn_cts: Vec<&mut dyn NistSubmissionReRandomize> = vec![&mut a, &mut b];

    preproc_eval(&mut dyn_cts, b"FheUint64+FheUint64".as_slice(), cpk).unwrap();

    assert!(a.re_randomization_metadata().data().is_empty());
    assert!(b.re_randomization_metadata().data().is_empty());

    let c = a + b;
    let dec: u64 = c.decrypt(cks);

    assert_eq!(clear_a.wrapping_add(clear_b), dec);
}

#[cfg(feature = "gpu")]
mod gpu {
    use super::*;
    use crate::shortint::parameters::v1_5::meta::gpu::V1_5_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;

    #[test]
    fn test_gpu_legacy_dyn_rerand() {
        let params =
            V1_5_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
        let (cks, sks, cpk) = setup_re_rand_test(params);
        set_server_key(sks.decompress_to_gpu());
        execute_dyn_rerand_test(&cks, &cpk);
    }
}
