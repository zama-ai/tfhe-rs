#![allow(dead_code)]
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::*;

////////LY23///////////
struct ParametersLY23 {
    param: ClassicPBSParameters,
    log_extension_factor: u64,
}

const LY23_1: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_1_CARRY_0_LY23_EXT_FACT_0_64,
    log_extension_factor: 0,
};

const LY23_2: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_1_CARRY_1_LY23_EXT_FACT_0_64,
    log_extension_factor: 0,
};

const LY23_3: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_1_CARRY_2_LY23_EXT_FACT_0_64,
    log_extension_factor: 0,
};

const LY23_4: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_2_CARRY_2_LY23_EXT_FACT_0_64,
    log_extension_factor: 0,
};

const LY23_5: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_2_CARRY_3_LY23_EXT_FACT_1_64,
    log_extension_factor: 1,
};

const LY23_6: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_3_CARRY_3_LY23_EXT_FACT_2_64,
    log_extension_factor: 2,
};

const LY23_7: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_3_CARRY_4_LY23_EXT_FACT_3_64,
    log_extension_factor: 3,
};

const LY23_8: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_4_CARRY_4_LY23_EXT_FACT_4_64,
    log_extension_factor: 4,
};

const PARAM_BENCHES_LY23: [ParametersLY23; 8] = [
    LY23_1, LY23_2, LY23_3, LY23_4, LY23_5, LY23_6, LY23_7, LY23_8,
];

pub fn generate_programmable_bootstrap_glwe_lut<F, Scalar: UnsignedTorus + CastFrom<usize>>(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    message_modulus: usize,
    ciphertext_modulus: tfhe::core_crypto::prelude::CiphertextModulus<Scalar>,
    delta: Scalar,
    f: F,
) -> GlweCiphertextOwned<Scalar>
where
    F: Fn(Scalar) -> Scalar,
{
    // N/(p/2) = size of each block, to correct noise from the input we introduce the
    // notion of box, which manages redundancy to yield a denoised value
    // for several noisy values around a true input value.
    let box_size = polynomial_size.0 / message_modulus;

    // Create the accumulator
    let mut accumulator_scalar = vec![Scalar::ZERO; polynomial_size.0];

    // Fill each box with the encoded denoised value
    for i in 0..message_modulus {
        let index = i * box_size;
        accumulator_scalar[index..index + box_size]
            .iter_mut()
            .for_each(|a| *a = f(Scalar::cast_from(i)) * delta);
    }

    let half_box_size = box_size / 2;

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        // Negate the first half_box_size coefficients to manage negacyclicity and rotate
        for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }
    } else {
        let modulus: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();
        for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg_custom_mod(modulus);
        }
    }

    // Rotate the accumulator
    accumulator_scalar.rotate_left(half_box_size);

    let accumulator_plaintext = PlaintextList::from_container(accumulator_scalar);

    allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &accumulator_plaintext,
        ciphertext_modulus,
    )
}

#[inline(never)]
fn keygen(
    param: ParametersLY23,
) -> (
    LweSecretKeyOwned<u64>,
    GlweSecretKeyOwned<u64>,
    FourierLweBootstrapKeyOwned,
) {
    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    let params = param.param;

    // Create the LweSecretKey
    let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        params.lwe_dimension,
        &mut secret_generator,
    );
    let output_glwe_secret_key: GlweSecretKeyOwned<u64> =
        allocate_and_generate_new_binary_glwe_secret_key(
            params.glwe_dimension,
            params.polynomial_size,
            &mut secret_generator,
        );

    // Create the empty bootstrapping key in the Fourier domain
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        params.lwe_dimension,
        params.glwe_dimension.to_glwe_size(),
        params.polynomial_size,
        params.pbs_base_log,
        params.pbs_level,
    );

    let bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        params.pbs_base_log,
        params.pbs_level,
        params.glwe_noise_distribution,
        params.ciphertext_modulus,
        &mut encryption_generator,
    );

    par_convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);

    (input_lwe_secret_key, output_glwe_secret_key, fourier_bsk)
}

#[inline(never)]
fn run() {
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    let param = LY23_6;

    let params = param.param;

    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;

    let extension_factor = Ly23ExtensionFactor(1 << param.log_extension_factor);
    let extended_polynomial_size = PolynomialSize(polynomial_size.0 * extension_factor.0);

    let (input_lwe_secret_key, output_glwe_secret_key, fourier_bsk) = keygen(param);
    let output_lwe_secret_key = output_glwe_secret_key.as_lwe_secret_key();

    // for param in PARAM_BENCHES_LY23.iter() {
    // }
    // Allocate a new LweCiphertext and encrypt our plaintext
    let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &input_lwe_secret_key,
        Plaintext(0u64),
        params.lwe_noise_distribution,
        params.ciphertext_modulus,
        &mut encryption_generator,
    );

    let total_modulus = params.message_modulus.0 * params.carry_modulus.0;

    let accumulator = generate_programmable_bootstrap_glwe_lut(
        extended_polynomial_size,
        glwe_dimension.to_glwe_size(),
        total_modulus,
        params.ciphertext_modulus,
        (1u64 << 63) >> total_modulus.ilog2(),
        |x| x,
    );

    // Allocate the LweCiphertext to store the result of the PBS
    let mut out_pbs_ct = LweCiphertext::new(
        0u64,
        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
        params.ciphertext_modulus,
    );

    let fft = Fft::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();

    buffers.resize(
        programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<u64>(
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            extension_factor,
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    // let mut thread_buffers = Vec::with_capacity(extension_factor.0);
    // for _ in 0..extension_factor.0 {
    //     let mut buffer = ComputationBuffers::new();
    //     buffer.resize(
    //         add_external_product_assign_mem_optimized_requirement::<u64>(
    //             glwe_dimension.to_glwe_size(),
    //             params.polynomial_size,
    //             fft,
    //         )
    //         .unwrap()
    //         .unaligned_bytes_required(),
    //     );
    //     thread_buffers.push(buffer);
    // }

    // let mut thread_stacks: Vec<_> = thread_buffers.iter_mut().map(|x| x.stack()).collect();

    let start = std::time::Instant::now();
    const LOOPS: u32 = 2000;
    for _ in 0..LOOPS {
        fourier_bsk.as_view().bootstrap_ly23(
            out_pbs_ct.as_mut_view(),
            lwe_ciphertext_in.as_view(),
            accumulator.as_view(),
            extension_factor,
            fft,
            buffers.stack(),
        );
    }
    let elapsed = start.elapsed();

    let elapsed_per_pbs = elapsed / LOOPS;

    println!("Elapsed: {elapsed:?}");
    println!("Runtime per PBS: {elapsed_per_pbs:?}");
}

pub fn main() {
    run()
}
