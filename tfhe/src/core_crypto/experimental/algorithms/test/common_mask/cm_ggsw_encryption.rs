use super::super::cm_ggsw_encryption::encrypt_constant_cm_ggsw_ciphertext;
use super::super::*;
use crate::core_crypto::commons::math::random::Uniform;
use crate::core_crypto::prelude::*;

/// Verify that a generator forked for one [`CmGgswCiphertext`] is fully exhausted (both mask
/// and noise sub-generators reach `remaining_bytes() == Some(0)`) after the encryption call.
///
/// Uses hardcoded parameters with a TUniform noise distribution. TUniform has
/// `single_sample_success_probability == 1.0`, which makes exhaustion deterministic.
#[test]
fn cm_ggsw_encryption_generator_exhaustion() {
    let glwe_noise_distribution = DynamicDistribution::new_t_uniform(30);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();
    let glwe_dimension = GlweDimension(3);
    let cm_dimension = CmDimension(2);
    let polynomial_size = PolynomialSize(512);
    let decomp_base_log = DecompositionBaseLog(17);
    let decomp_level_count = DecompositionLevelCount(2);

    let mut rsc = TestResources::new();

    let glwe_secret_keys: Vec<_> = (0..cm_dimension.0)
        .map(|_| {
            allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            )
        })
        .collect();

    let cleartexts: Vec<_> = (0..cm_dimension.0).map(|_| Cleartext(0u64)).collect();

    let mut ggsw = CmGgswCiphertext::new(
        0u64,
        glwe_dimension,
        cm_dimension,
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        ciphertext_modulus,
    );

    // Fork the parent generator for exactly 1 GGSW ciphertext; the resulting bounded child
    // should be completely consumed by the encryption.
    let fork_config = cm_ggsw_ciphertext_list_encryption_fork_config(
        GgswCiphertextCount(1),
        glwe_dimension,
        cm_dimension,
        polynomial_size,
        decomp_level_count,
        Uniform,
        glwe_noise_distribution,
        ciphertext_modulus,
    );

    let mut child = rsc
        .encryption_random_generator
        .try_fork_from_config(fork_config)
        .expect("Failed to fork generator")
        .next()
        .expect("Expected one child generator");

    encrypt_constant_cm_ggsw_ciphertext(
        &glwe_secret_keys,
        &mut ggsw,
        &cleartexts,
        glwe_noise_distribution,
        &mut child,
    );

    assert_eq!(
        child.remaining_bytes(),
        Some(0),
        "Mask generator should be exhausted after GGSW encryption"
    );
    assert_eq!(
        child.noise_generator_mut().remaining_bytes(),
        Some(0),
        "Noise generator should be exhausted after GGSW encryption"
    );
}
