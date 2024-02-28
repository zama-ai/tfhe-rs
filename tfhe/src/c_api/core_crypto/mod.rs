use super::utils::*;
use crate::core_crypto::commons::dispersion::StandardDev;
use crate::core_crypto::commons::math::random::DynamicDistribution as RustDynamicDistribution;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use std::os::raw::c_int;

// f64 will be aligned as a u64, use the same alignement
#[repr(u64)]
#[derive(Clone, Copy)]
pub enum DynamicDistributionTag {
    Gaussian = 0,
    TUniform = 1,
}

impl TryFrom<u64> for DynamicDistributionTag {
    type Error = &'static str;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Gaussian),
            1 => Ok(Self::TUniform),
            _ => Err("Invalid value for DynamicDistributionTag"),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Gaussian {
    pub std: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TUniform {
    pub bound_log2: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union DynamicDistributionPayload {
    pub gaussian: Gaussian,
    pub t_uniform: TUniform,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DynamicDistribution {
    pub tag: u64,
    pub distribution: DynamicDistributionPayload,
}

impl DynamicDistribution {
    pub fn new_gaussian_from_std_dev(std: f64) -> Self {
        Self {
            tag: DynamicDistributionTag::Gaussian as u64,
            distribution: DynamicDistributionPayload {
                gaussian: Gaussian { std },
            },
        }
    }

    pub fn new_t_uniform(bound_log2: u32) -> Self {
        Self {
            tag: DynamicDistributionTag::TUniform as u64,
            distribution: DynamicDistributionPayload {
                t_uniform: TUniform { bound_log2 },
            },
        }
    }
}

impl<T: UnsignedInteger> TryFrom<DynamicDistribution> for RustDynamicDistribution<T> {
    type Error = &'static str;

    fn try_from(value: DynamicDistribution) -> Result<Self, Self::Error> {
        let tag: DynamicDistributionTag = value.tag.try_into()?;

        match tag {
            DynamicDistributionTag::Gaussian => {
                Ok(Self::new_gaussian_from_std_dev(StandardDev(unsafe {
                    value.distribution.gaussian.std
                })))
            }
            DynamicDistributionTag::TUniform => Ok(Self::try_new_t_uniform(unsafe {
                value.distribution.t_uniform.bound_log2
            })?),
        }
    }
}

impl<T: UnsignedInteger> RustDynamicDistribution<T> {
    pub const fn convert_to_c(&self) -> DynamicDistribution {
        match self {
            Self::Gaussian(gaussian) => DynamicDistribution {
                tag: DynamicDistributionTag::Gaussian as u64,
                distribution: DynamicDistributionPayload {
                    gaussian: Gaussian { std: gaussian.std },
                },
            },
            Self::TUniform(t_uniform) => DynamicDistribution {
                tag: DynamicDistributionTag::TUniform as u64,
                distribution: DynamicDistributionPayload {
                    t_uniform: TUniform {
                        bound_log2: t_uniform.bound_log2(),
                    },
                },
            },
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn new_gaussian_from_std_dev(std_dev: f64) -> DynamicDistribution {
    DynamicDistribution::new_gaussian_from_std_dev(std_dev)
}

#[no_mangle]
pub unsafe extern "C" fn new_t_uniform(bound_log2: u32) -> DynamicDistribution {
    DynamicDistribution::new_t_uniform(bound_log2)
}

#[no_mangle]
pub unsafe extern "C" fn core_crypto_lwe_secret_key(
    output_lwe_sk_ptr: *mut u64,
    lwe_sk_dim: usize,
    seed_low_bytes: u64,
    seed_high_bytes: u64,
) -> c_int {
    catch_panic(|| {
        use crate::core_crypto::commons::math::random::Seed;
        use crate::core_crypto::prelude::*;

        let seed_low_bytes: u128 = seed_low_bytes.into();
        let seed_high_bytes: u128 = seed_high_bytes.into();
        let seed = (seed_high_bytes << 64) | seed_low_bytes;

        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(Seed(seed));

        // Create the LweSecretKey
        let output_lwe_sk_slice = std::slice::from_raw_parts_mut(output_lwe_sk_ptr, lwe_sk_dim);

        let mut lwe_sk = LweSecretKey::from_container(output_lwe_sk_slice);

        generate_binary_lwe_secret_key(&mut lwe_sk, &mut secret_generator);
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_crypto_lwe_encrypt(
    output_ct_ptr: *mut u64,
    pt: u64,
    lwe_sk_ptr: *const u64,
    lwe_sk_dim: usize,
    lwe_noise_distribution: DynamicDistribution,
    seed_low_bytes: u64,
    seed_high_bytes: u64,
) -> c_int {
    catch_panic(|| {
        use crate::core_crypto::commons::generators::DeterministicSeeder;
        use crate::core_crypto::commons::math::random::Seed;
        use crate::core_crypto::prelude::*;

        let lwe_sk_slice = std::slice::from_raw_parts(lwe_sk_ptr, lwe_sk_dim);
        let lwe_sk = LweSecretKey::from_container(lwe_sk_slice);

        let seed_low_bytes: u128 = seed_low_bytes.into();
        let seed_high_bytes: u128 = seed_high_bytes.into();
        let seed = (seed_high_bytes << 64) | seed_low_bytes;

        let seed = Seed(seed);
        let mut determinisitic_seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(seed);
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
            determinisitic_seeder.seed(),
            &mut determinisitic_seeder,
        );

        let plaintext = Plaintext(pt);
        let output_ct = std::slice::from_raw_parts_mut(output_ct_ptr, lwe_sk_dim + 1);
        let mut ct = LweCiphertext::from_container(output_ct, CiphertextModulus::new_native());

        let lwe_noise_distribution: DynamicDistribution<u64> =
            lwe_noise_distribution.try_into().unwrap();

        encrypt_lwe_ciphertext(
            &lwe_sk,
            &mut ct,
            plaintext,
            lwe_noise_distribution,
            &mut encryption_generator,
        );
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_crypto_ggsw_encrypt(
    output_ct_ptr: *mut u64,
    pt: u64,
    glwe_sk_ptr: *const u64,
    glwe_sk_dim: usize,
    poly_size: usize,
    level_count: usize,
    base_log: usize,
    glwe_noise_distribution: DynamicDistribution,
    seed_low_bytes: u64,
    seed_high_bytes: u64,
) -> c_int {
    catch_panic(|| {
        use crate::core_crypto::commons::generators::DeterministicSeeder;
        use crate::core_crypto::commons::math::random::Seed;
        use crate::core_crypto::prelude::*;

        let glwe_sk_slice = std::slice::from_raw_parts(glwe_sk_ptr, glwe_sk_dim * poly_size);
        let glwe_sk = GlweSecretKey::from_container(glwe_sk_slice, PolynomialSize(poly_size));

        let seed_low_bytes: u128 = seed_low_bytes.into();
        let seed_high_bytes: u128 = seed_high_bytes.into();
        let seed = (seed_high_bytes << 64) | seed_low_bytes;

        let seed = Seed(seed);
        let mut determinisitic_seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(seed);
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
            determinisitic_seeder.seed(),
            &mut determinisitic_seeder,
        );

        let plaintext = Plaintext(pt);
        let output_ct = std::slice::from_raw_parts_mut(
            output_ct_ptr,
            ggsw_ciphertext_size(
                GlweDimension(glwe_sk_dim).to_glwe_size(),
                PolynomialSize(poly_size),
                DecompositionLevelCount(level_count),
            ),
        );
        let mut ct = GgswCiphertext::from_container(
            output_ct,
            GlweDimension(glwe_sk_dim).to_glwe_size(),
            PolynomialSize(poly_size),
            DecompositionBaseLog(base_log),
            CiphertextModulus::new_native(),
        );

        let glwe_noise_distribution: DynamicDistribution<u64> =
            glwe_noise_distribution.try_into().unwrap();

        encrypt_constant_ggsw_ciphertext(
            &glwe_sk,
            &mut ct,
            plaintext,
            glwe_noise_distribution,
            &mut encryption_generator,
        );
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_crypto_lwe_decrypt(
    output_pt: *mut u64,
    input_ct_ptr: *const u64,
    lwe_sk_ptr: *const u64,
    lwe_sk_dim: usize,
) -> c_int {
    catch_panic(|| {
        use crate::core_crypto::prelude::*;

        let lwe_sk_slice = std::slice::from_raw_parts(lwe_sk_ptr, lwe_sk_dim);
        let lwe_sk = LweSecretKey::from_container(lwe_sk_slice);

        let input_ct = std::slice::from_raw_parts(input_ct_ptr, lwe_sk_dim + 1);
        let ct = LweCiphertext::from_container(input_ct, CiphertextModulus::new_native());

        let plaintext = decrypt_lwe_ciphertext(&lwe_sk, &ct);

        *output_pt = plaintext.0;
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_crypto_glwe_decrypt(
    output_pt: *mut u64,
    input_ct_ptr: *const u64,
    glwe_sk_ptr: *const u64,
    glwe_sk_dim: usize,
    glwe_poly_size: usize,
) -> c_int {
    catch_panic(|| {
        use crate::core_crypto::prelude::*;

        let glwe_sk_slice = std::slice::from_raw_parts(glwe_sk_ptr, glwe_sk_dim * glwe_poly_size);
        let glwe_sk = GlweSecretKey::from_container(glwe_sk_slice, PolynomialSize(glwe_poly_size));

        let input_ct = std::slice::from_raw_parts(
            input_ct_ptr,
            glwe_ciphertext_size(
                GlweDimension(glwe_sk_dim).to_glwe_size(),
                PolynomialSize(glwe_poly_size),
            ),
        );
        let ct = GlweCiphertext::from_container(
            input_ct,
            PolynomialSize(glwe_poly_size),
            CiphertextModulus::new_native(),
        );
        let output = std::slice::from_raw_parts_mut(output_pt, glwe_poly_size);
        let mut plaintext_list = PlaintextList::from_container(output);

        decrypt_glwe_ciphertext(&glwe_sk, &ct, &mut plaintext_list);
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_crypto_lwe_multi_bit_bootstrapping_key_element_size(
    input_lwe_sk_dim: usize,
    output_glwe_sk_dim: usize,
    output_glwe_sk_poly_size: usize,
    lwe_multi_bit_level_count: usize,
    lwe_multi_bit_grouping_factor: usize,
    result: *mut usize,
) -> c_int {
    catch_panic(|| {
        use crate::core_crypto::prelude::*;

        let result = get_mut_checked(result).unwrap();

        let input_lwe_sk_dim = LweDimension(input_lwe_sk_dim);

        let output_glwe_sk_dim = GlweDimension(output_glwe_sk_dim);
        let output_glwe_sk_poly_size = PolynomialSize(output_glwe_sk_poly_size);

        let lwe_multi_bit_level_count = DecompositionLevelCount(lwe_multi_bit_level_count);
        let lwe_multi_bit_grouping_factor = LweBskGroupingFactor(lwe_multi_bit_grouping_factor);

        *result = lwe_multi_bit_bootstrap_key_size(
            input_lwe_sk_dim,
            output_glwe_sk_dim.to_glwe_size(),
            output_glwe_sk_poly_size,
            lwe_multi_bit_level_count,
            lwe_multi_bit_grouping_factor,
        )
        .unwrap();
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_crypto_par_generate_lwe_bootstrapping_key(
    output_bsk_ptr: *mut u64,
    bsk_base_log: usize,
    bsk_level_count: usize,
    input_lwe_sk_ptr: *const u64,
    input_lwe_sk_dim: usize,
    output_glwe_sk_ptr: *const u64,
    output_glwe_sk_dim: usize,
    output_glwe_sk_poly_size: usize,
    glwe_noise_distribution: DynamicDistribution,
    seed_low_bytes: u64,
    seed_high_bytes: u64,
) -> c_int {
    catch_panic(|| {
        use crate::core_crypto::commons::generators::DeterministicSeeder;
        use crate::core_crypto::commons::math::random::Seed;
        use crate::core_crypto::prelude::*;

        let input_lwe_sk_slice = std::slice::from_raw_parts(input_lwe_sk_ptr, input_lwe_sk_dim);
        let input_lwe_sk = LweSecretKey::from_container(input_lwe_sk_slice);

        let output_glwe_sk_dim = GlweDimension(output_glwe_sk_dim);
        let output_glwe_sk_poly_size = PolynomialSize(output_glwe_sk_poly_size);
        let output_glwe_sk_size =
            glwe_ciphertext_mask_size(output_glwe_sk_dim, output_glwe_sk_poly_size);
        let output_glwe_sk_slice =
            std::slice::from_raw_parts(output_glwe_sk_ptr, output_glwe_sk_size);
        let output_glwe_sk =
            GlweSecretKey::from_container(output_glwe_sk_slice, output_glwe_sk_poly_size);

        let seed_low_bytes: u128 = seed_low_bytes.into();
        let seed_high_bytes: u128 = seed_high_bytes.into();
        let seed = (seed_high_bytes << 64) | seed_low_bytes;

        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(seed));
        let mut encryption_random_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            );

        let lwe_base_log = DecompositionBaseLog(bsk_base_log);
        let lwe_level_count = DecompositionLevelCount(bsk_level_count);

        let lwe_slice_len = {
            let bsk = LweBootstrapKeyOwned::new(
                0u64,
                output_glwe_sk.glwe_dimension().to_glwe_size(),
                output_glwe_sk.polynomial_size(),
                lwe_base_log,
                lwe_level_count,
                input_lwe_sk.lwe_dimension(),
                CiphertextModulus::new_native(),
            );
            bsk.into_container().len()
        };

        let bsk_slice = std::slice::from_raw_parts_mut(output_bsk_ptr, lwe_slice_len);

        let mut bsk = LweBootstrapKey::from_container(
            bsk_slice,
            output_glwe_sk.glwe_dimension().to_glwe_size(),
            output_glwe_sk.polynomial_size(),
            lwe_base_log,
            lwe_level_count,
            CiphertextModulus::new_native(),
        );

        let glwe_noise_distribution: DynamicDistribution<u64> =
            glwe_noise_distribution.try_into().unwrap();

        par_generate_lwe_bootstrap_key(
            &input_lwe_sk,
            &output_glwe_sk,
            &mut bsk,
            glwe_noise_distribution,
            &mut encryption_random_generator,
        )
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_crypto_par_generate_lwe_multi_bit_bootstrapping_key(
    input_lwe_sk_ptr: *const u64,
    input_lwe_sk_dim: usize,
    output_glwe_sk_ptr: *const u64,
    output_glwe_sk_dim: usize,
    output_glwe_sk_poly_size: usize,
    lwe_multi_bit_ptr: *mut u64,
    lwe_multi_bit_base_log: usize,
    lwe_multi_bit_level_count: usize,
    lwe_multi_bit_grouping_factor: usize,
    glwe_noise_distribution: DynamicDistribution,
    seed_low_bytes: u64,
    seed_high_bytes: u64,
) -> c_int {
    catch_panic(|| {
        use crate::core_crypto::commons::generators::DeterministicSeeder;
        use crate::core_crypto::commons::math::random::Seed;
        use crate::core_crypto::prelude::*;

        let input_lwe_sk_slice = std::slice::from_raw_parts(input_lwe_sk_ptr, input_lwe_sk_dim);
        let input_lwe_sk = LweSecretKey::from_container(input_lwe_sk_slice);

        let output_glwe_sk_dim = GlweDimension(output_glwe_sk_dim);
        let output_glwe_sk_poly_size = PolynomialSize(output_glwe_sk_poly_size);
        let output_glwe_sk_size =
            glwe_ciphertext_mask_size(output_glwe_sk_dim, output_glwe_sk_poly_size);
        let output_glwe_sk_slice =
            std::slice::from_raw_parts(output_glwe_sk_ptr, output_glwe_sk_size);
        let output_glwe_sk =
            GlweSecretKey::from_container(output_glwe_sk_slice, output_glwe_sk_poly_size);

        let seed_low_bytes: u128 = seed_low_bytes.into();
        let seed_high_bytes: u128 = seed_high_bytes.into();
        let seed = (seed_high_bytes << 64) | seed_low_bytes;

        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(seed));
        let mut encryption_random_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            );

        let lwe_multi_bit_base_log = DecompositionBaseLog(lwe_multi_bit_base_log);
        let lwe_multi_bit_level_count = DecompositionLevelCount(lwe_multi_bit_level_count);
        let lwe_multi_bit_grouping_factor = LweBskGroupingFactor(lwe_multi_bit_grouping_factor);

        let lwe_multi_bit_slice_len = {
            let bsk = LweMultiBitBootstrapKeyOwned::new(
                0u64,
                output_glwe_sk.glwe_dimension().to_glwe_size(),
                output_glwe_sk.polynomial_size(),
                lwe_multi_bit_base_log,
                lwe_multi_bit_level_count,
                input_lwe_sk.lwe_dimension(),
                lwe_multi_bit_grouping_factor,
                CiphertextModulus::new_native(),
            );
            bsk.into_container().len()
        };

        let lwe_multi_bit_slice =
            std::slice::from_raw_parts_mut(lwe_multi_bit_ptr, lwe_multi_bit_slice_len);

        let mut bsk = LweMultiBitBootstrapKey::from_container(
            lwe_multi_bit_slice,
            output_glwe_sk.glwe_dimension().to_glwe_size(),
            output_glwe_sk.polynomial_size(),
            lwe_multi_bit_base_log,
            lwe_multi_bit_level_count,
            lwe_multi_bit_grouping_factor,
            CiphertextModulus::new_native(),
        );

        let glwe_noise_distribution: DynamicDistribution<u64> =
            glwe_noise_distribution.try_into().unwrap();

        par_generate_lwe_multi_bit_bootstrap_key(
            &input_lwe_sk,
            &output_glwe_sk,
            &mut bsk,
            glwe_noise_distribution,
            &mut encryption_random_generator,
        );
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_crypto_par_generate_lwe_keyswitch_key(
    output_ksk_ptr: *mut u64,
    ksk_base_log: usize,
    ksk_level_count: usize,
    input_lwe_sk_ptr: *const u64,
    input_lwe_sk_dim: usize,
    output_lwe_sk_ptr: *const u64,
    output_lwe_sk_dim: usize,
    lwe_noise_distribution: DynamicDistribution,
    seed_low_bytes: u64,
    seed_high_bytes: u64,
) -> c_int {
    catch_panic(|| {
        use crate::core_crypto::commons::generators::DeterministicSeeder;
        use crate::core_crypto::commons::math::random::Seed;
        use crate::core_crypto::prelude::*;

        let input_lwe_sk_slice = std::slice::from_raw_parts(input_lwe_sk_ptr, input_lwe_sk_dim);
        let input_lwe_sk = LweSecretKey::from_container(input_lwe_sk_slice);
        let output_lwe_sk_slice = std::slice::from_raw_parts(output_lwe_sk_ptr, output_lwe_sk_dim);
        let output_lwe_sk = LweSecretKey::from_container(output_lwe_sk_slice);

        let seed_low_bytes: u128 = seed_low_bytes.into();
        let seed_high_bytes: u128 = seed_high_bytes.into();
        let seed = (seed_high_bytes << 64) | seed_low_bytes;

        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(seed));
        let mut encryption_random_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            );

        let lwe_base_log = DecompositionBaseLog(ksk_base_log);
        let lwe_level_count = DecompositionLevelCount(ksk_level_count);

        let lwe_slice_len = {
            let bsk = LweKeyswitchKeyOwned::new(
                0u64,
                lwe_base_log,
                lwe_level_count,
                LweDimension(input_lwe_sk_dim),
                LweDimension(output_lwe_sk_dim),
                CiphertextModulus::new_native(),
            );
            bsk.into_container().len()
        };

        let ksk_slice = std::slice::from_raw_parts_mut(output_ksk_ptr, lwe_slice_len);

        let mut ksk = LweKeyswitchKey::from_container(
            ksk_slice,
            lwe_base_log,
            lwe_level_count,
            LweDimension(output_lwe_sk_dim).to_lwe_size(),
            CiphertextModulus::new_native(),
        );

        let lwe_noise_distribution: DynamicDistribution<u64> =
            lwe_noise_distribution.try_into().unwrap();

        generate_lwe_keyswitch_key(
            &input_lwe_sk,
            &output_lwe_sk,
            &mut ksk,
            lwe_noise_distribution,
            &mut encryption_random_generator,
        )
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_crypto_par_generate_lwe_private_functional_keyswitch_key(
    output_pksk_ptr: *mut u64,
    pksk_base_log: usize,
    pksk_level_count: usize,
    input_lwe_sk_ptr: *const u64,
    input_lwe_sk_dim: usize,
    output_glwe_sk_ptr: *const u64,
    poly_size: usize,
    glwe_dim: usize,
    lwe_noise_distribution: DynamicDistribution,
    seed_low_bytes: u64,
    seed_high_bytes: u64,
) -> c_int {
    catch_panic(|| {
        use crate::core_crypto::commons::generators::DeterministicSeeder;
        use crate::core_crypto::commons::math::random::Seed;
        use crate::core_crypto::prelude::*;

        let input_lwe_sk_slice = std::slice::from_raw_parts(input_lwe_sk_ptr, input_lwe_sk_dim);
        let input_lwe_sk = LweSecretKey::from_container(input_lwe_sk_slice);
        let output_glwe_sk_slice =
            std::slice::from_raw_parts(output_glwe_sk_ptr, glwe_dim * poly_size);
        let output_glwe_sk =
            GlweSecretKey::from_container(output_glwe_sk_slice, PolynomialSize(poly_size));

        let seed_low_bytes: u128 = seed_low_bytes.into();
        let seed_high_bytes: u128 = seed_high_bytes.into();
        let seed = (seed_high_bytes << 64) | seed_low_bytes;

        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(seed));
        let mut encryption_random_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            );

        let pksk_len = {
            let ksk = LwePrivateFunctionalPackingKeyswitchKeyList::new(
                0u64,
                DecompositionBaseLog(pksk_base_log),
                DecompositionLevelCount(pksk_level_count),
                LweDimension(input_lwe_sk_dim),
                GlweDimension(glwe_dim).to_glwe_size(),
                PolynomialSize(poly_size),
                FunctionalPackingKeyswitchKeyCount(glwe_dim + 1),
                CiphertextModulus::new_native(),
            );
            ksk.into_container().len()
        };

        let ksk_slice = std::slice::from_raw_parts_mut(output_pksk_ptr, pksk_len);

        let mut fp_ksk = LwePrivateFunctionalPackingKeyswitchKeyList::from_container(
            ksk_slice,
            DecompositionBaseLog(pksk_base_log),
            DecompositionLevelCount(pksk_level_count),
            LweDimension(input_lwe_sk_dim).to_lwe_size(),
            GlweDimension(glwe_dim).to_glwe_size(),
            PolynomialSize(poly_size),
            CiphertextModulus::new_native(),
        );

        let lwe_noise_distribution: DynamicDistribution<u64> =
            lwe_noise_distribution.try_into().unwrap();

        generate_circuit_bootstrap_lwe_pfpksk_list(
            &mut fp_ksk,
            &input_lwe_sk,
            &output_glwe_sk,
            lwe_noise_distribution,
            &mut encryption_random_generator,
        )
    })
}
