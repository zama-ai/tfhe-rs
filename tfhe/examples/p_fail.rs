use rayon::prelude::*;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::ciphertext::MaxNoiseLevel;
use tfhe::shortint::engine::ShortintEngine;
use tfhe::shortint::gen_keys;
use tfhe::shortint::parameters::multi_bit::MultiBitPBSParameters;
use tfhe::shortint::parameters::{CarryModulus, MessageModulus};

pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M5_5: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(891),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.3292631075564801e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -5.5,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };

pub fn main() {
    let fhe_params = PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M5_5;

    let max_scalar_mul = fhe_params.max_noise_level.get() as u8;

    let expected_fails = 500;

    println!("running");
    //    let num_pbs = (1 << 6) * expected_fails;
    let num_pbs = (2.0_f32.powf(5.5).ceil() as i32) * expected_fails;

    let (cks, sks) = gen_keys(fhe_params);
    let lut = sks.generate_lookup_table(|x| x);

    let start = std::time::Instant::now();

    let actual_fails: u32 = (0..num_pbs)
        .into_par_iter()
        .map(|_i| {
            // let mut engine = ShortintEngine::new();
            // let cks = engine.new_client_key(fhe_params.into());
            // let sks = engine.new_server_key(&cks);

            // let mut ct = engine.encrypt(&cks, 0);

            // let lut = sks.generate_lookup_table(|x| x);

            let mut ct = cks.encrypt(0);

            // Get baseline noise after PBS
            sks.unchecked_scalar_mul_assign(&mut ct, max_scalar_mul);
            sks.apply_lookup_table_assign(&mut ct, &lut);

            // // PBS with baseline noise as input
            // sks.unchecked_scalar_mul_assign(&mut ct, max_scalar_mul);
            // sks.apply_lookup_table_assign(&mut ct, &lut);

            let dec = cks.decrypt(&ct);

            if dec != 0 {
                1
            } else {
                0
            }
        })
        .sum();

    let elapsed = start.elapsed();

    println!("Elapsed: {elapsed:?}");
    println!("Expected fails: {expected_fails}");
    println!("Got fails:      {actual_fails}");
}