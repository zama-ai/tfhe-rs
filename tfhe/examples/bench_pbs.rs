use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::*;

#[inline(never)]
fn keygen(params: ClassicPBSParameters) -> (LweSecretKeyOwned<u64>, FourierLweBootstrapKeyOwned) {
    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    // Create the LweSecretKey
    let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        params.lwe_dimension,
        &mut secret_generator,
    );

    // Create the empty bootstrapping key in the Fourier domain
    let fourier_bsk = FourierLweBootstrapKey::new(
        params.lwe_dimension,
        params.glwe_dimension.to_glwe_size(),
        params.polynomial_size,
        params.pbs_base_log,
        params.pbs_level,
    );

    (input_lwe_secret_key, fourier_bsk)
}

#[inline(never)]
fn bench_2_2(
    params: ClassicPBSParameters,
    input_lwe_secret_key: LweSecretKeyOwned<u64>,
    fourier_bsk: FourierLweBootstrapKeyOwned,
) {
    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    // Allocate a new LweCiphertext and encrypt our plaintext
    let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &input_lwe_secret_key,
        Plaintext(0u64),
        params.lwe_noise_distribution,
        tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        &mut encryption_generator,
    );

    let accumulator = GlweCiphertext::new(
        0u64,
        params.glwe_dimension.to_glwe_size(),
        params.polynomial_size,
        tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
    );

    // Allocate the LweCiphertext to store the result of the PBS
    let mut out_pbs_ct = LweCiphertext::new(
        0u64,
        fourier_bsk.output_lwe_dimension().to_lwe_size(),
        tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
    );

    let mut buffers = ComputationBuffers::new();

    let fft = Fft::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();

    buffers.resize(
        programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
            fourier_bsk.glwe_size(),
            fourier_bsk.polynomial_size(),
            fft,
        )
        .unaligned_bytes_required(),
    );

    let loops = 2000;

    let start = std::time::Instant::now();
    for _ in 0..loops {
        programmable_bootstrap_lwe_ciphertext_mem_optimized(
            &lwe_ciphertext_in,
            &mut out_pbs_ct,
            &accumulator.as_view(),
            &fourier_bsk,
            fft,
            buffers.stack(),
        );
    }

    let elapsed = start.elapsed().as_secs_f64();
    let millis_per_pbs = elapsed * 1000.0 / loops as f64;

    println!("{millis_per_pbs} ms per PBS");
}

pub fn main() {
    let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    let (lwe_sk, fbsk) = keygen(params);
    bench_2_2(params, lwe_sk, fbsk)
}
