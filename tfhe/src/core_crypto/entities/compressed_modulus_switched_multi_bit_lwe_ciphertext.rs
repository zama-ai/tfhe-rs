use self::packed_integers::PackedIntegers;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::backward_compatibility::entities;
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::prelude::*;
use entities::compressed_modulus_switched_multi_bit_lwe_ciphertext::*;
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
/// let compressed = CompressedModulusSwitchedMultiBitLweCiphertext::<u64>::compress(
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
    PackingScalar: UnsignedInteger + CastFrom<usize> + CastInto<usize>,
> {
    body: PackingScalar,
    packed_mask: PackedIntegers<PackingScalar>,
    packed_diffs: Option<PackedIntegers<PackingScalar>>,
    lwe_dimension: LweDimension,
    uncompressed_ciphertext_modulus: CiphertextModulus<PackingScalar>,
    grouping_factor: LweBskGroupingFactor,
}

impl<PackingScalar: UnsignedInteger + CastFrom<usize> + CastInto<usize>>
    CompressedModulusSwitchedMultiBitLweCiphertext<PackingScalar>
{
    pub(crate) fn from_raw_parts(
        body: PackingScalar,
        packed_mask: PackedIntegers<PackingScalar>,
        packed_diffs: Option<PackedIntegers<PackingScalar>>,
        lwe_dimension: LweDimension,
        uncompressed_ciphertext_modulus: CiphertextModulus<PackingScalar>,
        grouping_factor: LweBskGroupingFactor,
    ) -> Self {
        assert_ne!(
            grouping_factor.0, 0,
            "Multibit grouping factor should not be 0"
        );
        assert_eq!(
            packed_mask.initial_len() % grouping_factor.0,
            0,
            "Packed mask len (={}) should be a multiple of grouping factor (={})",
            packed_mask.initial_len(),
            grouping_factor.0
        );
        assert_eq!(packed_mask.initial_len(), lwe_dimension.0,
            "Packed mask list is not of the correct size for the uncompressed LWE: expected {}, got {}",
            lwe_dimension.0,
            packed_mask.initial_len());

        if let Some(diffs) = packed_diffs.as_ref() {
            // Get the expected number of diffs from the compression code
            let multi_bit_elements = packed_mask.initial_len() / grouping_factor.0;
            let ggsw_per_multi_bit_element = grouping_factor.ggsw_per_multi_bit_element().0;

            // In the diff list creation, we skip every power of two, so we have to remove them from
            // the total count
            let num_powers_of_2 = ggsw_per_multi_bit_element.ceil_ilog2() as usize;
            let expected_diffs_len =
                (ggsw_per_multi_bit_element - 1 - num_powers_of_2) * multi_bit_elements;
            assert_eq!(
                diffs.initial_len(),
                expected_diffs_len,
                "Packed diff list is not of the correct size for the uncompressed LWE: expected {}, got {}",
                diffs.initial_len(),
                expected_diffs_len
            );
        }

        Self {
            body,
            packed_mask,
            packed_diffs,
            lwe_dimension,
            uncompressed_ciphertext_modulus,
            grouping_factor,
        }
    }

    #[cfg(test)]
    #[allow(clippy::type_complexity)]
    pub(crate) fn into_raw_parts(
        self,
    ) -> (
        PackingScalar,
        PackedIntegers<PackingScalar>,
        Option<PackedIntegers<PackingScalar>>,
        LweDimension,
        CiphertextModulus<PackingScalar>,
        LweBskGroupingFactor,
    ) {
        let Self {
            body,
            packed_mask,
            packed_diffs,
            lwe_dimension,
            uncompressed_ciphertext_modulus,
            grouping_factor,
        } = self;

        (
            body,
            packed_mask,
            packed_diffs,
            lwe_dimension,
            uncompressed_ciphertext_modulus,
            grouping_factor,
        )
    }

    /// Compresses a ciphertext by reducing its modulus
    /// This operation adds a lot of noise
    pub fn compress<Scalar, Cont>(
        ct: &LweCiphertext<Cont>,
        log_modulus: CiphertextModulusLog,
        grouping_factor: LweBskGroupingFactor,
    ) -> Self
    where
        Scalar: UnsignedInteger + CastInto<PackingScalar> + CastFrom<usize>,
        Cont: Container<Element = Scalar>,
        PackingScalar::Signed: Ord + CastInto<PackingScalar>,
    {
        let uncompressed_ciphertext_modulus =
            ct.ciphertext_modulus().try_to().unwrap_or_else(|_| {
                panic!(
                "The ciphertext modulus (={}) for modulus switch compression does not fit in the \
                 PackingScalar (={})",
                ct.ciphertext_modulus(), PackingScalar::BITS)
            });

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
            "The log_modulus (={}) for modulus switch compression must be smaller than the \
             uncompressed ciphertext_modulus_log (={})",
            log_modulus.0,
            uncompressed_ciphertext_modulus_log,
        );

        let (input_lwe_mask, input_lwe_body) = ct.get_mask_and_body();

        let body = modulus_switch(*input_lwe_body.data, log_modulus).cast_into();

        let modulus_switched: Vec<_> = input_lwe_mask
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

                let mut sum_then_mod_switched = PackingScalar::ZERO;

                let mut monomial_degree = Scalar::ZERO;

                for (&mask_element, selection_bit) in lwe_mask_elements
                    .iter()
                    .zip_eq(selection_bit(grouping_factor, ggsw_idx))
                {
                    let selection_bit = Scalar::cast_from(selection_bit);

                    monomial_degree =
                        monomial_degree.wrapping_add(selection_bit.wrapping_mul(mask_element));

                    let modulus_switched: PackingScalar =
                        modulus_switch(selection_bit.wrapping_mul(mask_element), log_modulus)
                            .cast_into();

                    sum_then_mod_switched = sum_then_mod_switched.wrapping_add(modulus_switched);
                }

                let mod_switched_then_sum: PackingScalar =
                    modulus_switch(monomial_degree, log_modulus).cast_into();

                sum_then_mod_switched %= PackingScalar::ONE << log_modulus.0;

                let diff = mod_switched_then_sum.wrapping_sub(sum_then_mod_switched);

                diffs.push(diff);
            }
        }

        let packed_mask = PackedIntegers::pack::<PackingScalar>(&modulus_switched, log_modulus);

        let packed_diffs = if diffs.iter().all(|a| *a == PackingScalar::ZERO) {
            None
        } else {
            // We need some space to store integer in 2 complement representation
            // We must have -half_space <= value < half_space
            // <=> half_space >= -value and half_space >= value + 1
            // <=> half_space >= max(-value, value + 1)
            let half_needed_space: PackingScalar = diffs
                .iter()
                .map(|a| PackingScalar::Signed::cast_from(*a))
                .map(|a| (a + PackingScalar::Signed::ONE).max(-a))
                .max()
                .unwrap()
                .cast_into();

            let half_needed_space_ceil_log = half_needed_space.ceil_ilog2();

            let used_space_log = half_needed_space_ceil_log + 1;

            let diffs_two_complement: Vec<_> = diffs
                .iter()
                .map(|a| PackingScalar::Signed::cast_from(*a))
                .map(|a| {
                    // put into two complement representation on used_space_log bits
                    if a >= PackingScalar::Signed::ZERO {
                        a.cast_into()
                    } else {
                        ((PackingScalar::Signed::ONE << used_space_log as usize) + a).cast_into()
                    }
                })
                .collect();

            Some(PackedIntegers::pack(
                &diffs_two_complement,
                CiphertextModulusLog(used_space_log as usize),
            ))
        };

        Self::from_raw_parts(
            body,
            packed_mask,
            packed_diffs,
            ct.lwe_size().to_lwe_dimension(),
            uncompressed_ciphertext_modulus,
            grouping_factor,
        )
    }

    /// Converts back a compressed ciphertext to its initial modulus
    /// The noise added during the compression stays in the output
    /// The output must got through a PBS to reduce the noise
    pub fn extract(&self) -> FromCompressionMultiBitModulusSwitchedCt {
        let masks: Vec<usize> = self.packed_mask.unpack::<usize>().collect();

        assert_eq!(
            masks.len() % self.grouping_factor.0,
            0,
            "Mask len (={}) should be a multiple of grouping factor (={})",
            masks.len(),
            self.grouping_factor.0
        );

        let mut diffs_two_complement: Vec<usize> = vec![];

        if let Some(packed_diffs) = &self.packed_diffs {
            diffs_two_complement = packed_diffs.unpack::<usize>().collect()
        }

        let diffs = |a: usize| {
            self.packed_diffs.as_ref().map_or(0, |packed_diffs| {
                let diffs_two_complement: usize = diffs_two_complement[a];
                let used_space_log = packed_diffs.log_modulus().0;
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
                    .push(monomial_degree % (1 << self.packed_mask.log_modulus().0));
            }
        }

        FromCompressionMultiBitModulusSwitchedCt {
            switched_modulus_input_lwe_body: self.body.cast_into(),
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

impl MultiBitModulusSwitchedLweCiphertext for FromCompressionMultiBitModulusSwitchedCt {
    fn lwe_dimension(&self) -> LweDimension {
        self.lwe_dimension
    }
    fn grouping_factor(&self) -> LweBskGroupingFactor {
        self.grouping_factor
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
    type ParameterSet = CompressedModulusSwitchedLweCiphertextConformanceParams<Scalar>;

    fn is_conformant(
        &self,
        compressed_ct_parameters: &CompressedModulusSwitchedLweCiphertextConformanceParams<Scalar>,
    ) -> bool {
        let Self {
            body,
            packed_mask,
            packed_diffs,
            lwe_dimension,
            uncompressed_ciphertext_modulus,
            grouping_factor,
        } = self;

        let CompressedModulusSwitchedLweCiphertextConformanceParams {
            ct_params,
            ms_decompression_type,
        } = compressed_ct_parameters;

        let LweCiphertextConformanceParams {
            lwe_dim: params_lwe_dim,
            ct_modulus,
        } = ct_params;

        *body >> packed_mask.log_modulus().0 == Scalar::ZERO
            && packed_mask.is_conformant(&lwe_dimension.0)
            && packed_diffs
                .as_ref()
                .is_none_or(|packed_diffs| packed_diffs.is_conformant(&lwe_dimension.0))
            && lwe_dimension == params_lwe_dim
            && ct_modulus.is_power_of_two()
            && match ms_decompression_type {
                MsDecompressionType::ClassicPbs => false,
                MsDecompressionType::MultiBitPbs(expected_grouping_factor) => {
                    expected_grouping_factor.0 == grouping_factor.0
                }
            }
            && uncompressed_ciphertext_modulus == ct_modulus
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use super::*;
    #[test]
    fn test_from_raw_parts() {
        type Scalar = u64;

        let len = 694;
        let log_modulus = 12;
        let grouping_factor = LweBskGroupingFactor(3);

        let ciphertext_modulus = CiphertextModulus::new_native();

        let mut lwe = LweCiphertext::new(Scalar::ZERO, LweSize(len), ciphertext_modulus);

        // We don't care about the exact content here
        rand::rng().fill(lwe.as_mut());

        let compressed = CompressedModulusSwitchedMultiBitLweCiphertext::<u64>::compress(
            &lwe,
            CiphertextModulusLog(log_modulus),
            grouping_factor,
        );

        let (
            body,
            packed_mask,
            packed_diffs,
            lwe_dimension,
            uncompressed_ciphertext_modulus,
            grouping_factor,
        ) = compressed.into_raw_parts();

        let rebuilt = CompressedModulusSwitchedMultiBitLweCiphertext::from_raw_parts(
            body,
            packed_mask,
            packed_diffs,
            lwe_dimension,
            uncompressed_ciphertext_modulus,
            grouping_factor,
        );

        let _ = rebuilt.extract();
    }
}
