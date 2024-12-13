use self::packed_integers::PackedIntegers;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::backward_compatibility::entities::compressed_modulus_switched_multi_bit_lwe_ciphertext::CompressedModulusSwitchedMultiBitLweCiphertextVersions;
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::prelude::*;
use itertools::Itertools;
use tfhe_versionable::Versionize;

/// An object to store a ciphertext using less memory
/// The ciphertext is applied a modulus switch as done in the multi bit PBS.
/// It is then stored in a compact way.
/// The uncompacted result must go through a multi bit PBS to
/// be recovered.
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// let small_lwe_dimension = LweDimension(742);
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(2048);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let pbs_base_log = DecompositionBaseLog(23);
/// let pbs_level = DecompositionLevelCount(1);
/// let grouping_factor = LweBskGroupingFactor(2); // Group bits in pairs
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// let log_modulus = polynomial_size.to_blind_rotation_input_modulus_log();
///
/// // Request the best seeder possible, starting with hardware entropy sources and falling back to
/// // /dev/random on Unix systems if enabled via cargo features
/// let mut boxed_seeder = new_seeder();
/// // Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
/// let seeder = boxed_seeder.as_mut();
///
/// // Create a generator which uses a CSPRNG to generate secret keys
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create a generator which uses two CSPRNGs to generate public masks and secret encryption
/// // noise
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
///
/// // Generate an LweSecretKey with binary coefficients
/// let small_lwe_sk =
///     LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);
///
/// // Generate a GlweSecretKey with binary coefficients
/// let glwe_sk =
///     GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
///
/// // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
/// let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();
///
/// let mut bsk = LweMultiBitBootstrapKey::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     pbs_base_log,
///     pbs_level,
///     small_lwe_dimension,
///     grouping_factor,
///     ciphertext_modulus,
/// );
///
/// par_generate_lwe_multi_bit_bootstrap_key(
///     &small_lwe_sk,
///     &glwe_sk,
///     &mut bsk,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let mut multi_bit_bsk = FourierLweMultiBitBootstrapKey::new(
///     bsk.input_lwe_dimension(),
///     bsk.glwe_size(),
///     bsk.polynomial_size(),
///     bsk.decomposition_base_log(),
///     bsk.decomposition_level_count(),
///     bsk.grouping_factor(),
/// );
///
/// par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(&bsk, &mut multi_bit_bsk);
///
/// // We don't need the standard bootstrapping key anymore
/// drop(bsk);
///
/// // Now we will use a PBS to compute a multiplication by 2, it is NOT the recommended way of
/// // doing this operation in terms of performance as it's much more costly than a multiplication
/// // with a cleartext, however it resets the noise in a ciphertext to a nominal level and allows
/// // to evaluate arbitrary functions so depending on your use case it can be a better fit.
///
/// // Our 4 bits message space
/// let message_modulus = 1u64 << 4;
///
/// // Delta used to encode 4 bits of message + a bit of padding on u64
/// let delta = (1_u64 << 63) / message_modulus;
///
/// // Generate the accumulator for our multiplication by 2 using a simple closure
/// let mut accumulator: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
///     polynomial_size,
///     glwe_dimension.to_glwe_size(),
///     message_modulus as usize,
///     ciphertext_modulus,
///     delta,
///     |x: u64| x,
/// );
///
/// // Our input message
/// let input_message = 3u64;
///
/// // Apply our encoding
/// let plaintext = Plaintext(input_message * delta);
///
/// // Allocate a new LweCiphertext and encrypt our plaintext
/// let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
///     &small_lwe_sk,
///     plaintext,
///     lwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Can be stored using much less space than the standard lwe ciphertexts
/// let compressed = CompressedModulusSwitchedMultiBitLweCiphertext::compress(
///     &lwe_ciphertext_in,
///     log_modulus,
///     grouping_factor,
/// );
///
/// let waiting_for_br = compressed.extract();
///
/// // Use 4 threads for the multi-bit blind rotation for example
/// multi_bit_deterministic_blind_rotate_assign(
///     &waiting_for_br,
///     &mut accumulator,
///     &multi_bit_bsk,
///     ThreadCount(4),
/// );
///
/// // Allocate the LweCiphertext to store the result of the PBS
/// let mut decompressed_ct = LweCiphertext::new(
///     0u64,
///     big_lwe_sk.lwe_dimension().to_lwe_size(),
///     ciphertext_modulus,
/// );
///
/// extract_lwe_sample_from_glwe_ciphertext(&accumulator, &mut decompressed_ct, MonomialDegree(0));
///
/// // Decrypt the PBS multiplication result
/// let decompressed_plaintext: Plaintext<u64> =
///     decrypt_lwe_ciphertext(&big_lwe_sk, &decompressed_ct);
///
/// // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
/// // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
/// // round the 5 MSB, 1 bit of padding plus our 4 bits of message
/// let signed_decomposer =
///     SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
///
/// // Round and remove our encoding
/// let decompression_result: u64 =
///     signed_decomposer.closest_representable(decompressed_plaintext.0) / delta;
///
/// assert_eq!(decompression_result, input_message);
/// ```
#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedModulusSwitchedMultiBitLweCiphertextVersions)]
pub struct CompressedModulusSwitchedMultiBitLweCiphertext<
    Scalar: UnsignedInteger + CastInto<usize> + CastFrom<usize>,
> {
    body: usize,
    packed_mask: PackedIntegers<usize>,
    packed_diffs: Option<PackedIntegers<usize>>,
    lwe_dimension: LweDimension,
    uncompressed_ciphertext_modulus: CiphertextModulus<Scalar>,
    grouping_factor: LweBskGroupingFactor,
}

impl<Scalar: UnsignedInteger + CastInto<usize> + CastFrom<usize>>
    CompressedModulusSwitchedMultiBitLweCiphertext<Scalar>
{
    /// Compresses a ciphertext by reducing its modulus
    /// This operation adds a lot of noise
    pub fn compress<Cont: Container<Element = Scalar>>(
        ct: &LweCiphertext<Cont>,
        log_modulus: CiphertextModulusLog,
        grouping_factor: LweBskGroupingFactor,
    ) -> Self {
        let uncompressed_ciphertext_modulus = ct.ciphertext_modulus();

        assert!(
            ct.ciphertext_modulus().is_power_of_two(),
            "Modulus switch compression doe not support non power of 2 input moduli",
        );

        let uncompressed_ciphertext_modulus_log =
            if uncompressed_ciphertext_modulus.is_native_modulus() {
                Scalar::BITS
            } else {
                uncompressed_ciphertext_modulus.get_custom_modulus().ilog2() as usize
            };

        assert!(
            log_modulus.0 <= uncompressed_ciphertext_modulus_log,
            "The log_modulus (={}) for modulus switch compression must be smaller than the uncompressed ciphertext_modulus_log (={})",
            log_modulus.0,
            uncompressed_ciphertext_modulus_log,
        );

        let (input_lwe_mask, input_lwe_body) = ct.get_mask_and_body();

        let body = modulus_switch(*input_lwe_body.data, log_modulus).cast_into();

        let modulus_switched: Vec<usize> = ct
            .as_ref()
            .iter()
            .map(|a| modulus_switch(*a, log_modulus).cast_into())
            .collect();

        let mut diffs = vec![];

        for lwe_mask_elements in input_lwe_mask.as_ref().chunks_exact(grouping_factor.0) {
            for ggsw_idx in 1..grouping_factor.ggsw_per_multi_bit_element().0 {
                // We need to store the diff sums of more than one element as we store the
                // individual modulus_switched elements
                if ggsw_idx.is_power_of_two() {
                    continue;
                }

                let mut sum_then_mod_switched = 0;

                let mut monomial_degree = Scalar::ZERO;

                for (&mask_element, selection_bit) in lwe_mask_elements
                    .iter()
                    .zip_eq(selection_bit(grouping_factor, ggsw_idx))
                {
                    let selection_bit: Scalar = Scalar::cast_from(selection_bit);

                    monomial_degree =
                        monomial_degree.wrapping_add(selection_bit.wrapping_mul(mask_element));

                    let modulus_switched =
                        modulus_switch(selection_bit.wrapping_mul(mask_element), log_modulus)
                            .cast_into();

                    sum_then_mod_switched = sum_then_mod_switched.wrapping_add(modulus_switched);
                }

                let mod_switched_then_sum: usize =
                    modulus_switch(monomial_degree, log_modulus).cast_into();

                sum_then_mod_switched %= 1 << log_modulus.0;

                let diff = mod_switched_then_sum.wrapping_sub(sum_then_mod_switched);

                diffs.push(diff);
            }
        }

        let packed_mask = PackedIntegers::pack(&modulus_switched, log_modulus);

        let packed_diffs = if diffs.iter().all(|a| *a == 0) {
            None
        } else {
            // We need some space to store integer in 2 complement representation
            // We must have -half_space <= value < half_space
            // <=> half_space >= -value and half_space >= value + 1
            // <=> half_space >= max(-value, value + 1)
            let half_needed_space = diffs
                .iter()
                .map(|a| *a as isize)
                .map(|a| (a + 1).max(-a))
                .max()
                .unwrap() as usize;

            let half_needed_space_ceil_log = half_needed_space.ceil_ilog2();

            let used_space_log = half_needed_space_ceil_log + 1;

            let diffs_two_complement: Vec<usize> = diffs
                .iter()
                .map(|a| *a as isize)
                .map(|a| {
                    // put into two complement representation on used_space_log bits
                    if a >= 0 {
                        a as usize
                    } else {
                        ((1_isize << used_space_log) + a) as usize
                    }
                })
                .collect();

            Some(PackedIntegers::pack(
                &diffs_two_complement,
                CiphertextModulusLog(used_space_log as usize),
            ))
        };

        Self {
            body,
            packed_mask,
            packed_diffs,
            lwe_dimension: ct.lwe_size().to_lwe_dimension(),
            uncompressed_ciphertext_modulus,
            grouping_factor,
        }
    }

    /// Converts back a compressed ciphertext to its initial modulus
    /// The noise added during the compression stays in the output
    /// The output must got through a PBS to reduce the noise
    pub fn extract(&self) -> FromCompressionMultiBitModulusSwitchedCt {
        let masks: Vec<usize> = self.packed_mask.unpack().collect();

        let mut diffs_two_complement: Vec<usize> = vec![];

        if let Some(packed_diffs) = &self.packed_diffs {
            diffs_two_complement = packed_diffs.unpack().collect()
        };

        let diffs = |a: usize| {
            self.packed_diffs.as_ref().map_or(0, |packed_diffs| {
                let diffs_two_complement: usize = diffs_two_complement[a];
                let used_space_log = packed_diffs.log_modulus.0;
                // rebuild from two complement representation on used_space_log bits
                let used_space = 1 << used_space_log;
                if diffs_two_complement >= used_space / 2 {
                    diffs_two_complement.wrapping_sub(used_space)
                } else {
                    diffs_two_complement
                }
            })
        };

        let mut diff_index = 0;

        let mut switched_modulus_input_mask_per_group: Vec<usize> = vec![];

        for lwe_mask_elements in masks.chunks_exact(self.grouping_factor.0) {
            for ggsw_idx in 1..self.grouping_factor.ggsw_per_multi_bit_element().0 {
                let mut monomial_degree = 0;
                for (&mask_element, selection_bit) in lwe_mask_elements
                    .iter()
                    .zip_eq(selection_bit(self.grouping_factor, ggsw_idx))
                {
                    monomial_degree =
                        monomial_degree.wrapping_add(selection_bit.wrapping_mul(mask_element));
                }

                if ggsw_idx.count_ones() != 1 {
                    let diff = diffs(diff_index);

                    diff_index += 1;

                    monomial_degree = monomial_degree.wrapping_add(diff);
                }

                switched_modulus_input_mask_per_group
                    .push(monomial_degree % (1 << self.packed_mask.log_modulus.0));
            }
        }

        FromCompressionMultiBitModulusSwitchedCt {
            switched_modulus_input_lwe_body: self.body,
            switched_modulus_input_mask_per_group,
            grouping_factor: self.grouping_factor,
            lwe_dimension: self.lwe_dimension,
        }
    }
}

pub struct FromCompressionMultiBitModulusSwitchedCt {
    switched_modulus_input_lwe_body: usize,
    switched_modulus_input_mask_per_group: Vec<usize>,
    grouping_factor: LweBskGroupingFactor,
    lwe_dimension: LweDimension,
}

impl MultiBitModulusSwitchedCt for FromCompressionMultiBitModulusSwitchedCt {
    fn lwe_dimension(&self) -> LweDimension {
        self.lwe_dimension
    }
    fn switched_modulus_input_lwe_body(&self) -> usize {
        self.switched_modulus_input_lwe_body
    }
    fn switched_modulus_input_mask_per_group(
        &self,
        index: usize,
    ) -> impl Iterator<Item = usize> + '_ {
        let ggsw_per_multi_bit_element = self.grouping_factor.ggsw_per_multi_bit_element();

        let chunk_size = ggsw_per_multi_bit_element.0 - 1;

        self.switched_modulus_input_mask_per_group[index * chunk_size..(index + 1) * chunk_size]
            .iter()
            .copied()
    }
}

impl<Scalar: UnsignedInteger + CastInto<usize> + CastFrom<usize>> ParameterSetConformant
    for CompressedModulusSwitchedMultiBitLweCiphertext<Scalar>
{
    type ParameterSet = LweCiphertextParameters<Scalar>;

    fn is_conformant(&self, lwe_ct_parameters: &LweCiphertextParameters<Scalar>) -> bool {
        let Self {
            body,
            packed_mask,
            packed_diffs,
            lwe_dimension,
            uncompressed_ciphertext_modulus,
            grouping_factor,
        } = self;

        let lwe_dim = lwe_dimension.0;

        body >> packed_mask.log_modulus.0 == 0
            && packed_mask.is_conformant(&lwe_dim)
            && packed_diffs
                .as_ref()
                .is_none_or(|packed_diffs| packed_diffs.is_conformant(&lwe_dim))
            && *lwe_dimension == lwe_ct_parameters.lwe_dim
            && lwe_ct_parameters.ct_modulus.is_power_of_two()
            && match lwe_ct_parameters.ms_decompression_method {
                MsDecompressionType::ClassicPbs => false,
                MsDecompressionType::MultiBitPbs(expected_gouping_factor) => {
                    expected_gouping_factor.0 == grouping_factor.0
                }
            }
            && *uncompressed_ciphertext_modulus == lwe_ct_parameters.ct_modulus
    }
}
