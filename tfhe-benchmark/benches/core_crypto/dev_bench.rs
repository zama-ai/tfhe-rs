use criterion::{black_box, Criterion, Throughput};
use tfhe::core_crypto::commons::math::ntt::ntt64::Ntt64;
use tfhe::core_crypto::prelude::*;

// PBS 2**64 - 2**32 + 1
// KS 2**64 - 2**32 + 1
// ((24.544282, 2.919442517240005e-40),
// {
//     'l_ks': 3,
//     'l_bs': 1,
//     'k': 1,
//     'N': 2048,
//     'n': 998,
//     'b_ks': 32,
//     'b_bs': 8388608,
//     'bound_n_1': 43,
//     'bound_kN_1': 17,
//     'bound_k_N': 17
// })

// PBS 0b0011_1111_1111_1111_1111_1111_1111_1100_0111_0000_0000_0000_0001
// KS 2^32
// ((25.527282, 1.4062320105749015e-39),
// {
//     'l_ks': 3,
//     'l_bs': 1,
//     'k': 1,
//     'N': 2048,
//     'n': 1038,
//     'b_ks': 64,
//     'b_bs': 4194304,
//     'bound_n_1': 10,
//     'bound_kN_1': 3,
//     'bound_k_N': 3
// })
pub fn main() {
    type Scalar = u64;

    // ~2^50-ish
    let modulus = 0b0011_1111_1111_1111_1111_1111_1111_1100_0111_0000_0000_0000_0001;
    let lwe_dim = LweDimension(1038);
    let glwe_dim = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let ks_level = DecompositionLevelCount(3);
    let ks_base_log = DecompositionBaseLog(64u32.ilog2() as usize);
    let pbs_level = DecompositionLevelCount(1);
    let pbs_base_log = DecompositionBaseLog(4194304u32.ilog2() as usize);
    let lwe_noise = DynamicDistribution::<u64>::new_t_uniform(10);
    let glwe_noise = DynamicDistribution::<u64>::new_t_uniform(3);
    let ks_mod = CiphertextModulus::<u64>::try_new(
        modulus
    )
    .unwrap();
    let pbs_mod = CiphertextModulus::<u64>::try_new(
        modulus
    )
    .unwrap();

    // let modulus = (1u128 << 64) - (1u128 << 32) + 1;

    // let lwe_dim = LweDimension(998);
    // let glwe_dim = GlweDimension(1);
    // let polynomial_size = PolynomialSize(2048);
    // let ks_level = DecompositionLevelCount(3);
    // let ks_base_log = DecompositionBaseLog(32u32.ilog2() as usize);
    // let pbs_level = DecompositionLevelCount(1);
    // let pbs_base_log = DecompositionBaseLog(8388608u32.ilog2() as usize);
    // let lwe_noise = DynamicDistribution::<u64>::new_t_uniform(43);
    // let glwe_noise = DynamicDistribution::<u64>::new_t_uniform(17);
    // let ks_mod = CiphertextModulus::<u64>::try_new(modulus).unwrap();
    // let pbs_mod = CiphertextModulus::<u64>::try_new(modulus).unwrap();

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    // Create the LweSecretKey
    let input_lwe_secret_key =
        allocate_and_generate_new_binary_lwe_secret_key(lwe_dim, &mut secret_generator);
    let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
        allocate_and_generate_new_binary_glwe_secret_key(
            glwe_dim,
            polynomial_size,
            &mut secret_generator,
        );
    let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

    let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
        &output_lwe_secret_key,
        &input_lwe_secret_key,
        ks_base_log,
        ks_level,
        lwe_noise,
        ks_mod,
        &mut encryption_generator,
    );

    // Create the empty bootstrapping key in the Fourier domain
    let ntt_bsk = NttLweBootstrapKey::new(
        modulus as u64 - 1,
        lwe_dim,
        glwe_dim.to_glwe_size(),
        polynomial_size,
        pbs_base_log,
        pbs_level,
        pbs_mod,
    );

    let input_ks_ct: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
        &output_lwe_secret_key,
        Plaintext(0),
        lwe_noise,
        pbs_mod,
        &mut encryption_generator,
    );

    let mut output_ks_ct: LweCiphertextOwned<Scalar> = LweCiphertext::new(
        0,
        input_lwe_secret_key.lwe_dimension().to_lwe_size(),
        ks_mod,
    );

    let accumulator = GlweCiphertext::new(0, glwe_dim.to_glwe_size(), polynomial_size, pbs_mod);

    // Allocate the LweCiphertext to store the result of the PBS
    let mut output_pbs_ct = LweCiphertext::new(
        0,
        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
        pbs_mod,
    );

    let ntt = Ntt64::new(ntt_bsk.ciphertext_modulus(), polynomial_size);
    let ntt = ntt.as_view();

    let mut c = Criterion::default();

    let bench_name = "core_crypto::ks_pbs_ntt";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30));

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized_requirement(
            ntt_bsk.glwe_size(),
            ntt_bsk.polynomial_size(),
            ntt,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    keyswitch_lwe_ciphertext(&ksk_big_to_small, &input_ks_ct, &mut output_ks_ct);
    {
        bench_group.bench_function(bench_name, |b| {
            b.iter(|| {
                programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized(
                    &output_ks_ct,
                    &mut output_pbs_ct,
                    &accumulator.as_view(),
                    &ntt_bsk,
                    ntt,
                    buffers.stack(),
                );
            })
        });
    }
}
