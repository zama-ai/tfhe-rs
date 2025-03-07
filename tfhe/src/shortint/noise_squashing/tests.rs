use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::noise_squashing::{NoiseSquashingKey, NoiseSquashingPrivateKey};
use crate::shortint::parameters::*;
use rand::prelude::*;
use rand::thread_rng;

#[test]
fn test_noise_squashing_ci_run_filter() {
    const TEST_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
        NoiseSquashingParameters = NoiseSquashingParameters {
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(30),
        decomp_base_log: DecompositionBaseLog(24),
        decomp_level_count: DecompositionLevelCount(3),
        modulus_switch_noise_reduction_params: Some(ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: LweCiphertextCount(1449),
            ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
            ms_r_sigma_factor: RSigmaFactor(13.179852282053789f64),
            ms_input_variance: Variance(2.63039184094559E-7f64),
        }),
        ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
    };

    let keycache_entry = KEY_CACHE.get_from_param(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    let (cks, sks) = (keycache_entry.client_key(), keycache_entry.server_key());
    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(
        cks,
        TEST_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    );
    let noise_squashing_key = NoiseSquashingKey::new(cks, &noise_squashing_private_key);

    let mut rng = thread_rng();

    let id_lut = sks.generate_lookup_table(|x| x);

    for _ in 0..100 {
        let msg_1 = rng.gen::<u64>() % cks.parameters.message_modulus().0;
        let msg_2 = rng.gen::<u64>() % cks.parameters.message_modulus().0;

        let mut ct_1 = cks.encrypt(msg_1);
        let mut ct_2 = cks.encrypt(msg_2);

        // Set ciphertext noise level to nominal
        rayon::join(
            || sks.apply_lookup_table_assign(&mut ct_1, &id_lut),
            || sks.apply_lookup_table_assign(&mut ct_2, &id_lut),
        );

        // Pack
        let packed = sks.unchecked_add(
            &sks.unchecked_scalar_mul(&ct_1, sks.message_modulus.0.try_into().unwrap()),
            &ct_2,
        );

        let squashed_noise_ct = noise_squashing_key.squash_ciphertext_noise(&packed, sks);

        let recovered =
            noise_squashing_private_key.decrypt_squashed_noise_ciphertext(&squashed_noise_ct);

        let expected_u128: u128 = (msg_1 * sks.message_modulus.0 + msg_2).into();
        assert_eq!(recovered, expected_u128);
    }
}
