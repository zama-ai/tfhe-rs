#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{init_parameters_set, write_to_json, CryptoParametersRecord, OperatorType};
use criterion::{black_box, Criterion};
use dyn_stack::PodStack;
use tfhe::core_crypto::fft_impl::fft128::crypto::bootstrap::bootstrap_scratch;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize,
};

fn pbs_128(c: &mut Criterion) {
    let bench_name = "core_crypto::pbs128";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30));

    type Scalar = u128;

    let lwe_dimension = LweDimension(879);
    let glwe_dimension = GlweDimension(2);
    let polynomial_size = PolynomialSize(2048);
    let lwe_noise_distribution = DynamicDistribution::new_t_uniform(46);
    let glwe_noise_distribution = DynamicDistribution::new_t_uniform(30);
    let pbs_base_log = DecompositionBaseLog(32);
    let pbs_level = DecompositionLevelCount(3);
    let ciphertext_modulus = CiphertextModulus::new_native();

    let params_name = "PARAMS_SWITCH_SQUASH";

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let input_lwe_secret_key =
        LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);

    let output_glwe_secret_key = GlweSecretKey::<Vec<Scalar>>::generate_new_binary(
        glwe_dimension,
        polynomial_size,
        &mut secret_generator,
    );

    let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

    let mut bsk = LweBootstrapKey::new(
        Scalar::ZERO,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        pbs_base_log,
        pbs_level,
        lwe_dimension,
        ciphertext_modulus,
    );
    par_generate_lwe_bootstrap_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        &mut bsk,
        glwe_noise_distribution,
        &mut encryption_generator,
    );

    let mut fourier_bsk = Fourier128LweBootstrapKey::new(
        lwe_dimension,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        pbs_base_log,
        pbs_level,
    );
    convert_standard_lwe_bootstrap_key_to_fourier_128(&bsk, &mut fourier_bsk);

    let message_modulus: Scalar = 1 << 4;

    let input_message: Scalar = 3;

    let delta: Scalar = (1 << (Scalar::BITS - 1)) / message_modulus;

    let plaintext = Plaintext(input_message * delta);

    let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
        &input_lwe_secret_key,
        plaintext,
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let accumulator: GlweCiphertextOwned<Scalar> = GlweCiphertextOwned::new(
        Scalar::ONE,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );

    let mut out_pbs_ct: LweCiphertext<Vec<Scalar>> = LweCiphertext::new(
        0,
        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );

    let fft = Fft128::new(polynomial_size);
    let fft = fft.as_view();

    let mut buffers = vec![
        0u8;
        bootstrap_scratch::<Scalar>(
            fourier_bsk.glwe_size(),
            fourier_bsk.polynomial_size(),
            fft
        )
        .unwrap()
        .unaligned_bytes_required()
    ];

    let id = format!("{bench_name}::{params_name}");
    bench_group.bench_function(&id, |b| {
        b.iter(|| {
            fourier_bsk.bootstrap(
                &mut out_pbs_ct,
                &lwe_ciphertext_in,
                &accumulator,
                fft,
                PodStack::new(&mut buffers),
            );
            black_box(&mut out_pbs_ct);
        });
    });

    let params_record = CryptoParametersRecord {
        lwe_dimension: Some(lwe_dimension),
        glwe_dimension: Some(glwe_dimension),
        polynomial_size: Some(polynomial_size),
        lwe_noise_distribution: Some(lwe_noise_distribution),
        glwe_noise_distribution: Some(glwe_noise_distribution),
        pbs_base_log: Some(pbs_base_log),
        pbs_level: Some(pbs_level),
        ciphertext_modulus: Some(ciphertext_modulus),
        ..Default::default()
    };

    let bit_size = (message_modulus as u32).ilog2();
    write_to_json(
        &id,
        params_record,
        params_name,
        "pbs",
        &OperatorType::Atomic,
        bit_size,
        vec![bit_size],
    );
}

#[cfg(feature = "gpu")]
mod cuda {
    use crate::utilities::{write_to_json, CryptoParametersRecord, OperatorType};
    use criterion::{black_box, Criterion};
    use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
    use tfhe::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
    use tfhe::core_crypto::gpu::vec::GpuIndex;
    use tfhe::core_crypto::gpu::{cuda_programmable_bootstrap_128_lwe_ciphertext, CudaStreams};
    use tfhe::core_crypto::prelude::*;
    use tfhe::shortint::parameters::{
        DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
        LweDimension, PolynomialSize,
    };

    fn cuda_pbs_128(c: &mut Criterion) {
        let bench_name = "core_crypto::cuda::pbs128";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(10)
            .measurement_time(std::time::Duration::from_secs(30));

        type Scalar = u128;

        let lwe_dimension = LweDimension(879);
        let glwe_dimension = GlweDimension(2);
        let polynomial_size = PolynomialSize(2048);
        let lwe_noise_distribution = DynamicDistribution::new_t_uniform(46);
        let glwe_noise_distribution = DynamicDistribution::new_t_uniform(30);
        let pbs_base_log = DecompositionBaseLog(32);
        let pbs_level = DecompositionLevelCount(3);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let gpu_index = 0;
        let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

        let params_name = "PARAMS_SWITCH_SQUASH";

        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

        let input_lwe_secret_key =
            LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);

        let output_glwe_secret_key = GlweSecretKey::<Vec<Scalar>>::generate_new_binary(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );

        let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

        let bsk = LweBootstrapKey::new(
            Scalar::ZERO,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            pbs_base_log,
            pbs_level,
            lwe_dimension,
            ciphertext_modulus,
        );
        let bsk_gpu = CudaLweBootstrapKey::from_lwe_bootstrap_key(&bsk, None, &stream);

        let message_modulus: Scalar = 1 << 4;

        let input_message: Scalar = 3;

        let delta: Scalar = (1 << (Scalar::BITS - 1)) / message_modulus;

        let plaintext = Plaintext(input_message * delta);

        let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &input_lwe_secret_key,
            plaintext,
            lwe_noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let lwe_ciphertext_in_gpu =
            CudaLweCiphertextList::from_lwe_ciphertext(&lwe_ciphertext_in, &stream);

        let accumulator: GlweCiphertextOwned<Scalar> = GlweCiphertextOwned::new(
            Scalar::ONE,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            ciphertext_modulus,
        );
        let accumulator_gpu = CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &stream);

        let out_pbs_ct = LweCiphertext::new(
            0,
            output_lwe_secret_key.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );
        let mut out_pbs_ct_gpu = CudaLweCiphertextList::from_lwe_ciphertext(&out_pbs_ct, &stream);

        let id = format!("{bench_name}::{params_name}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    cuda_programmable_bootstrap_128_lwe_ciphertext(
                        &lwe_ciphertext_in_gpu,
                        &mut out_pbs_ct_gpu,
                        &accumulator_gpu,
                        LweCiphertextCount(1),
                        &bsk_gpu,
                        &stream,
                    );
                    black_box(&mut out_pbs_ct_gpu);
                })
            });
        }

        let params_record = CryptoParametersRecord {
            lwe_dimension: Some(lwe_dimension),
            glwe_dimension: Some(glwe_dimension),
            polynomial_size: Some(polynomial_size),
            lwe_noise_distribution: Some(lwe_noise_distribution),
            glwe_noise_distribution: Some(glwe_noise_distribution),
            pbs_base_log: Some(pbs_base_log),
            pbs_level: Some(pbs_level),
            ciphertext_modulus: Some(ciphertext_modulus),
            ..Default::default()
        };

        let bit_size = (message_modulus as u32).ilog2();
        write_to_json(
            &id,
            params_record,
            params_name,
            "pbs",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }

    pub fn cuda_pbs128_group() {
        let mut criterion: Criterion<_> = Criterion::default().configure_from_args();
        cuda_pbs_128(&mut criterion);
    }
}

#[cfg(feature = "gpu")]
use cuda::cuda_pbs128_group;

pub fn pbs128_group() {
    let mut criterion: Criterion<_> = Criterion::default().configure_from_args();
    pbs_128(&mut criterion);
}

#[cfg(feature = "gpu")]
fn go_through_gpu_bench_groups() {
    cuda_pbs128_group();
}

#[cfg(not(feature = "gpu"))]
fn go_through_cpu_bench_groups() {
    pbs128_group();
}
fn main() {
    init_parameters_set();

    #[cfg(feature = "gpu")]
    go_through_gpu_bench_groups();
    #[cfg(not(feature = "gpu"))]
    go_through_cpu_bench_groups();

    Criterion::default().configure_from_args().final_summary();
}
