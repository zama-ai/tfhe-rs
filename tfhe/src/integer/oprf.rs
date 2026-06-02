use super::{RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::{Container, IntoContainerOwned};
use crate::integer::ciphertext::{
    IntegerRadixCiphertext, ReRandomizationHashAlgo, ReRandomizationKey,
};
use crate::integer::ClientKey;
use crate::named::Named;
use crate::shortint::oprf::{
    CompressedOprfServerKey as ShortintCompressedOprfServerKey,
    ExpandedOprfServerKey as ShortintExpandedOprfServerKey,
    GenericOprfServerKey as ShortintGenericOprfServerKey, OprfPrivateKey as ShortintOprfPrivateKey,
    OprfServerKey as ShortintOprfServerKey,
};
use crate::shortint::{AtomicPatternParameters, OprfSeed};
use aligned_vec::ABox;
use std::num::NonZeroU64;
use tfhe_fft::c64;
use tfhe_versionable::Versionize;

pub use tfhe_csprng::seeders::{Seed, Seeder};

use super::backward_compatibility::oprf::*;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(OprfPrivateKeyVersions)]
pub struct OprfPrivateKey(pub(crate) ShortintOprfPrivateKey);

impl OprfPrivateKey {
    pub fn new(ck: &ClientKey) -> Self {
        Self(ShortintOprfPrivateKey::new(&ck.key))
    }

    pub fn from_raw_parts(sk: ShortintOprfPrivateKey) -> Self {
        Self(sk)
    }

    pub fn into_raw_parts(self) -> ShortintOprfPrivateKey {
        self.0
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedOprfServerKeyVersions)]
pub struct CompressedOprfServerKey(pub(crate) ShortintCompressedOprfServerKey);

impl CompressedOprfServerKey {
    pub fn new(sk: &OprfPrivateKey, target_ck: &ClientKey) -> crate::Result<Self> {
        ShortintCompressedOprfServerKey::new(&sk.0, &target_ck.key).map(Self)
    }

    pub fn from_raw_parts(inner: ShortintCompressedOprfServerKey) -> Self {
        Self(inner)
    }

    pub fn into_raw_parts(self) -> ShortintCompressedOprfServerKey {
        self.0
    }

    pub fn expand(&self) -> ExpandedOprfServerKey {
        ExpandedOprfServerKey(self.0.expand())
    }

    pub(crate) fn is_conformant(&self, sk_param: &AtomicPatternParameters) -> bool {
        self.0.is_conformant(sk_param)
    }
}

#[derive(PartialEq, Eq)]
pub struct ExpandedOprfServerKey(pub(crate) ShortintExpandedOprfServerKey);

impl ExpandedOprfServerKey {
    pub fn from_raw_parts(inner: ShortintExpandedOprfServerKey) -> Self {
        Self(inner)
    }

    pub fn into_raw_parts(self) -> ShortintExpandedOprfServerKey {
        self.0
    }

    pub fn to_fourier(&self) -> OprfServerKey {
        OprfServerKey::from_raw_parts(self.0.to_fourier())
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
#[versionize(GenericOprfServerKeyVersions)]
pub struct GenericOprfServerKey<C: Container<Element = c64>> {
    pub(crate) key: ShortintGenericOprfServerKey<C>,
}

pub type OprfServerKey = GenericOprfServerKey<ABox<[c64]>>;
pub type OprfServerKeyView<'a> = GenericOprfServerKey<&'a [c64]>;

impl<C> GenericOprfServerKey<C>
where
    C: Container<Element = c64> + Sync,
{
    pub fn from_raw_parts(inner: ShortintGenericOprfServerKey<C>) -> Self {
        Self { key: inner }
    }

    pub fn into_raw_parts(self) -> ShortintGenericOprfServerKey<C> {
        self.key
    }
    /// Generates an encrypted `num_block` blocks unsigned integer
    /// taken uniformly in its full range using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::oprf::{OprfPrivateKey, OprfServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    /// use tfhe::Seed;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let oprf_pk = OprfPrivateKey::new(cks.as_ref());
    /// let oprf_sk = OprfServerKey::new(&oprf_pk, cks.as_ref()).unwrap();
    ///
    /// // DANGER: Using a fixed seed is insecure and only done here to show API usage.
    /// // The proper way of generating a seed depends on your application.
    /// // `seed` can be either a `Seed` or any byte-like input (`&[u8]`, `&[u8; N]`, ...).
    /// let ct_res =
    ///     oprf_sk.par_generate_oblivious_pseudo_random_unsigned_integer(Seed(0), size as u64, &sks);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    ///
    /// assert!(dec_result < 1 << (2 * size));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_unsigned_integer(
        &self,
        seed: impl OprfSeed,
        num_blocks: u64,
        target_sks: &ServerKey,
    ) -> RadixCiphertext {
        self.par_generate_oblivious_pseudo_random_integer_full_impl(seed, num_blocks, target_sks)
    }

    pub fn par_generate_oblivious_pseudo_random_unsigned_integer_and_re_randomize(
        &self,
        seed: impl OprfSeed,
        num_blocks: u64,
        target_sks: &ServerKey,
        re_randomization_key: &ReRandomizationKey,
        re_randomization_hash_algo: ReRandomizationHashAlgo,
    ) -> crate::Result<RadixCiphertext> {
        self.par_generate_oblivious_pseudo_random_integer_full_and_re_randomize_impl(
            seed,
            num_blocks,
            target_sks,
            re_randomization_key,
            re_randomization_hash_algo,
        )
    }

    /// Generates an encrypted `num_block` blocks unsigned integer
    /// taken uniformly in `[0, 2^random_bits_count[` using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::oprf::{OprfPrivateKey, OprfServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    /// use tfhe::Seed;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let oprf_pk = OprfPrivateKey::new(cks.as_ref());
    /// let oprf_sk = OprfServerKey::new(&oprf_pk, cks.as_ref()).unwrap();
    ///
    /// let random_bits_count = 3;
    ///
    /// // DANGER: Using a fixed seed is insecure and only done here to show API usage.
    /// // The proper way of generating a seed depends on your application.
    /// let ct_res = oprf_sk.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
    ///     Seed(0),
    ///     random_bits_count,
    ///     size as u64,
    ///     &sks,
    /// );
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert!(dec_result < (1 << random_bits_count));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        num_blocks: u64,
        target_sks: &ServerKey,
    ) -> RadixCiphertext {
        self.par_generate_oblivious_pseudo_random_integer_bounded_impl(
            seed,
            random_bits_count,
            num_blocks,
            target_sks,
        )
    }

    pub fn par_generate_oblivious_pseudo_random_unsigned_integer_bounded_and_re_randomize(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        num_blocks: u64,
        target_sks: &ServerKey,
        re_randomization_key: &ReRandomizationKey,
        re_randomization_hash_algo: ReRandomizationHashAlgo,
    ) -> crate::Result<RadixCiphertext> {
        self.par_generate_oblivious_pseudo_random_integer_bounded_and_re_randomize_impl(
            seed,
            random_bits_count,
            num_blocks,
            target_sks,
            re_randomization_key,
            re_randomization_hash_algo,
        )
    }

    /// Generates an encrypted `num_blocks_output` blocks unsigned integer
    /// taken almost uniformly in [0, excluded_upper_bound[ using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    /// The higher num_input_random_bits, the closer to a uniform the distribution will be (at the
    /// cost of computation time).
    /// It is recommended to use a multiple of `log2_message_modulus`
    /// as `num_input_random_bits`
    ///
    /// ```rust
    /// use std::num::NonZeroU64;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::oprf::{OprfPrivateKey, OprfServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    /// use tfhe::Seed;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let oprf_pk = OprfPrivateKey::new(cks.as_ref());
    /// let oprf_sk = OprfServerKey::new(&oprf_pk, cks.as_ref()).unwrap();
    ///
    /// let num_input_random_bits = 5;
    /// let excluded_upper_bound = NonZeroU64::new(3).unwrap();
    /// let num_blocks_output = 8;
    ///
    /// // DANGER: Using a fixed seed is insecure and only done here to show API usage.
    /// // The proper way of generating a seed depends on your application.
    /// let ct_res = oprf_sk.par_generate_oblivious_pseudo_random_unsigned_custom_range(
    ///     Seed(0),
    ///     num_input_random_bits,
    ///     excluded_upper_bound,
    ///     num_blocks_output,
    ///     &sks,
    /// );
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    ///
    /// assert!(dec_result < excluded_upper_bound.get());
    /// ```
    pub fn par_generate_oblivious_pseudo_random_unsigned_custom_range<InputSeed>(
        &self,
        seed: InputSeed,
        num_input_random_bits: u64,
        excluded_upper_bound: NonZeroU64,
        num_blocks_output: u64,
        target_sks: &ServerKey,
    ) -> RadixCiphertext
    where
        InputSeed: OprfSeed,
    {
        self.par_generate_oblivious_pseudo_random_unsigned_custom_range_impl(
            seed,
            num_input_random_bits,
            excluded_upper_bound,
            num_blocks_output,
            target_sks,
            |sself: &Self,
             seed: InputSeed,
             num_input_random_bits: u64,
             num_blocks: u64,
             target_sks: &ServerKey| {
                Ok(
                    sself.par_generate_oblivious_pseudo_random_integer_bounded_impl(
                        seed,
                        num_input_random_bits,
                        num_blocks,
                        target_sks,
                    ),
                )
            },
        )
        .unwrap()
        // Safe to unwrap our closure returns an Ok result
    }

    #[allow(clippy::too_many_arguments)]
    pub fn par_generate_oblivious_pseudo_random_unsigned_custom_range_and_re_randomize<InputSeed>(
        &self,
        seed: InputSeed,
        num_input_random_bits: u64,
        excluded_upper_bound: NonZeroU64,
        num_blocks_output: u64,
        target_sks: &ServerKey,
        re_randomization_key: &ReRandomizationKey,
        re_randomization_hash_algo: ReRandomizationHashAlgo,
    ) -> crate::Result<RadixCiphertext>
    where
        InputSeed: OprfSeed,
    {
        self.par_generate_oblivious_pseudo_random_unsigned_custom_range_impl(
            seed,
            num_input_random_bits,
            excluded_upper_bound,
            num_blocks_output,
            target_sks,
            |sself: &Self,
             seed: InputSeed,
             num_input_random_bits: u64,
             num_blocks: u64,
             target_sks: &ServerKey| {
                sself.par_generate_oblivious_pseudo_random_integer_bounded_and_re_randomize_impl(
                    seed,
                    num_input_random_bits,
                    num_blocks,
                    target_sks,
                    re_randomization_key,
                    re_randomization_hash_algo,
                )
            },
        )
    }

    /// Generates an encrypted `num_block` blocks signed integer
    /// taken uniformly in its full range using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::oprf::{OprfPrivateKey, OprfServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    /// use tfhe::Seed;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let oprf_pk = OprfPrivateKey::new(cks.as_ref());
    /// let oprf_sk = OprfServerKey::new(&oprf_pk, cks.as_ref()).unwrap();
    ///
    /// // DANGER: Using a fixed seed is insecure and only done here to show API usage.
    /// // The proper way of generating a seed depends on your application.
    /// let ct_res =
    ///     oprf_sk.par_generate_oblivious_pseudo_random_signed_integer(Seed(0), size as u64, &sks);
    ///
    /// // Decrypt:
    /// let dec_result: i64 = cks.decrypt_signed(&ct_res);
    /// assert!(dec_result < 1 << (2 * size - 1));
    /// assert!(dec_result >= -(1 << (2 * size - 1)));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_signed_integer(
        &self,
        seed: impl OprfSeed,
        num_blocks: u64,
        target_sks: &ServerKey,
    ) -> SignedRadixCiphertext {
        self.par_generate_oblivious_pseudo_random_integer_full_impl(seed, num_blocks, target_sks)
    }

    pub fn par_generate_oblivious_pseudo_random_signed_integer_and_re_randomize(
        &self,
        seed: impl OprfSeed,
        num_blocks: u64,
        target_sks: &ServerKey,
        re_randomization_key: &ReRandomizationKey,
        re_randomization_hash_algo: ReRandomizationHashAlgo,
    ) -> crate::Result<SignedRadixCiphertext> {
        self.par_generate_oblivious_pseudo_random_integer_full_and_re_randomize_impl(
            seed,
            num_blocks,
            target_sks,
            re_randomization_key,
            re_randomization_hash_algo,
        )
    }

    /// Generates an encrypted `num_block` blocks signed integer
    /// taken uniformly in `[0, 2^random_bits_count[` using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::oprf::{OprfPrivateKey, OprfServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    /// use tfhe::Seed;
    ///
    /// let size = 4;
    ///
    /// let random_bits_count = 3;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let oprf_pk = OprfPrivateKey::new(cks.as_ref());
    /// let oprf_sk = OprfServerKey::new(&oprf_pk, cks.as_ref()).unwrap();
    ///
    /// // DANGER: Using a fixed seed is insecure and only done here to show API usage.
    /// // The proper way of generating a seed depends on your application.
    /// let ct_res = oprf_sk.par_generate_oblivious_pseudo_random_signed_integer_bounded(
    ///     Seed(0),
    ///     random_bits_count,
    ///     size as u64,
    ///     &sks,
    /// );
    ///
    /// // Decrypt:
    /// let dec_result: i64 = cks.decrypt_signed(&ct_res);
    /// assert!(dec_result >= 0);
    /// assert!(dec_result < (1 << random_bits_count));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_signed_integer_bounded(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        num_blocks: u64,
        target_sks: &ServerKey,
    ) -> SignedRadixCiphertext {
        self.par_generate_oblivious_pseudo_random_integer_bounded_impl(
            seed,
            random_bits_count,
            num_blocks,
            target_sks,
        )
    }

    pub fn par_generate_oblivious_pseudo_random_signed_integer_bounded_and_re_randomize(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        num_blocks: u64,
        target_sks: &ServerKey,
        re_randomization_key: &ReRandomizationKey,
        re_randomization_hash_algo: ReRandomizationHashAlgo,
    ) -> crate::Result<SignedRadixCiphertext> {
        self.par_generate_oblivious_pseudo_random_integer_bounded_and_re_randomize_impl(
            seed,
            random_bits_count,
            num_blocks,
            target_sks,
            re_randomization_key,
            re_randomization_hash_algo,
        )
    }

    fn par_generate_oblivious_pseudo_random_integer_full_impl<T: IntegerRadixCiphertext>(
        &self,
        seed: impl OprfSeed,
        num_blocks: u64,
        target_sks: &ServerKey,
    ) -> T {
        assert!(target_sks.message_modulus().0.is_power_of_two());
        let message_bits_count = target_sks.message_modulus().0.ilog2() as u64;

        let blocks = self
            .key
            .generate_oblivious_pseudo_random_bits_chunks(
                seed,
                &[num_blocks * message_bits_count],
                &target_sks.key,
            )
            .into_iter()
            .next()
            .expect("Expected a single chunk for the radix being generated, got 0");

        T::from(blocks)
    }

    fn par_generate_oblivious_pseudo_random_integer_full_and_re_randomize_impl<
        T: IntegerRadixCiphertext,
    >(
        &self,
        seed: impl OprfSeed,
        num_blocks: u64,
        target_sks: &ServerKey,
        re_randomization_key: &ReRandomizationKey,
        re_randomization_hash_algo: ReRandomizationHashAlgo,
    ) -> crate::Result<T> {
        assert!(target_sks.message_modulus().0.is_power_of_two());
        let message_bits_count = target_sks.message_modulus().0.ilog2() as u64;

        let (compact_public_key, key_switching_key_material) =
            re_randomization_key.get_cpk_and_optional_ksk();

        let blocks = self
            .key
            .generate_oblivious_pseudo_random_bits_chunks_and_re_randomize(
                seed,
                &[num_blocks * message_bits_count],
                &target_sks.key,
                &compact_public_key.key,
                key_switching_key_material.as_ref().map(|k| &k.material),
                re_randomization_hash_algo,
            )?
            .into_iter()
            .next()
            .expect("Expected a single chunk for the radix being generated, got 0");

        Ok(T::from(blocks))
    }

    fn par_generate_oblivious_pseudo_random_integer_bounded_impl<T: IntegerRadixCiphertext>(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        num_blocks: u64,
        target_sks: &ServerKey,
    ) -> T {
        assert!(target_sks.message_modulus().0.is_power_of_two());
        let message_bits_count = target_sks.message_modulus().0.ilog2() as u64;
        let range_bits_count = message_bits_count * num_blocks;
        assert!(range_bits_count > 0);

        if T::IS_SIGNED {
            let signed_range_bits_count = range_bits_count.saturating_sub(1);
            assert!(
                random_bits_count <= signed_range_bits_count,
                "The range asked for a random value in (=[0, 2^{random_bits_count}[) \
                which does not fit in the available range \
                [-2^{signed_range_bits_count}, 2^{signed_range_bits_count}[",
            );
        } else {
            assert!(
                random_bits_count <= range_bits_count,
                "The range asked for a random value in (=[0, 2^{random_bits_count}[) \
                which does not fit in the available range [0, 2^{range_bits_count}[",
            );
        }

        let mut blocks = self
            .key
            .generate_oblivious_pseudo_random_bits_chunks(
                seed,
                &[random_bits_count],
                &target_sks.key,
            )
            .into_iter()
            .next()
            .expect("Expected a single chunk for the radix being generated, got 0");
        if blocks.len() < num_blocks as usize {
            blocks.resize(num_blocks as usize, target_sks.key.create_trivial(0));
        }

        T::from(blocks)
    }

    fn par_generate_oblivious_pseudo_random_integer_bounded_and_re_randomize_impl<
        T: IntegerRadixCiphertext,
    >(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        num_blocks: u64,
        target_sks: &ServerKey,
        re_randomization_key: &ReRandomizationKey,
        re_randomization_hash_algo: ReRandomizationHashAlgo,
    ) -> crate::Result<T> {
        assert!(target_sks.message_modulus().0.is_power_of_two());
        let message_bits_count = target_sks.message_modulus().0.ilog2() as u64;
        let range_bits_count = message_bits_count * num_blocks;
        assert!(range_bits_count > 0);

        if T::IS_SIGNED {
            let signed_range_bits_count = range_bits_count.saturating_sub(1);
            assert!(
                random_bits_count <= signed_range_bits_count,
                "The range asked for a random value in (=[0, 2^{random_bits_count}[) \
                which does not fit in the available range \
                [-2^{signed_range_bits_count}, 2^{signed_range_bits_count}[",
            );
        } else {
            assert!(
                random_bits_count <= range_bits_count,
                "The range asked for a random value in (=[0, 2^{random_bits_count}[) \
                which does not fit in the available range [0, 2^{range_bits_count}[",
            );
        }

        let (compact_public_key, key_switching_key_material) =
            re_randomization_key.get_cpk_and_optional_ksk();

        let mut blocks = self
            .key
            .generate_oblivious_pseudo_random_bits_chunks_and_re_randomize(
                seed,
                &[random_bits_count],
                &target_sks.key,
                &compact_public_key.key,
                key_switching_key_material.as_ref().map(|k| &k.material),
                re_randomization_hash_algo,
            )?
            .into_iter()
            .next()
            .expect("Expected a single chunk for the radix being generated, got 0");

        if blocks.len() < num_blocks as usize {
            blocks.resize(num_blocks as usize, target_sks.key.create_trivial(0));
        }

        Ok(T::from(blocks))
    }

    fn par_generate_oblivious_pseudo_random_unsigned_custom_range_impl<InputSeed>(
        &self,
        seed: InputSeed,
        num_input_random_bits: u64,
        excluded_upper_bound: NonZeroU64,
        num_blocks_output: u64,
        target_sks: &ServerKey,
        prf_callback: impl Fn(
            &Self,      // sself
            InputSeed,  // seed
            u64,        // num_input_random_bits
            u64,        // num_blocks
            &ServerKey, // target_sks
        ) -> crate::Result<RadixCiphertext>,
    ) -> crate::Result<RadixCiphertext>
    where
        InputSeed: OprfSeed,
    {
        let excluded_upper_bound = excluded_upper_bound.get();

        assert!(target_sks.message_modulus().0.is_power_of_two());
        let message_bits_count: u64 = target_sks.message_modulus().0.ilog2().into();

        assert!(
            !excluded_upper_bound.is_power_of_two(),
            "Use the cheaper par_generate_oblivious_pseudo_random_unsigned_integer_bounded \
            function instead"
        );

        // Since excluded_upper_bound is not a power of two, we know the ceil log2 of the value is
        // the ilog2 + 1, this is how many bits are needed to represent the value
        let excluded_upper_bound_log2: u64 = excluded_upper_bound.ilog2().into();
        let excluded_upper_bound_ceil_log2 = excluded_upper_bound_log2 + 1;
        let num_bits_output = num_blocks_output * message_bits_count;

        assert!(
            excluded_upper_bound_ceil_log2 <= num_bits_output,
            "num_blocks_output(={num_blocks_output}) is too small to hold an integer \
            up to excluded_upper_bound(={excluded_upper_bound}). Output has {num_bits_output} bits,\
            {excluded_upper_bound} needs {excluded_upper_bound_ceil_log2} bits to be represented."
        );

        let post_mul_num_bits = num_input_random_bits + excluded_upper_bound_ceil_log2;

        let num_blocks = post_mul_num_bits.div_ceil(message_bits_count);

        let random_input = prf_callback(self, seed, num_input_random_bits, num_blocks, target_sks)?;

        let random_multiplied =
            target_sks.scalar_mul_parallelized(&random_input, excluded_upper_bound);

        let mut result =
            target_sks.scalar_right_shift_parallelized(&random_multiplied, num_input_random_bits);

        // Adjust the number of leading (MSB) trivial zeros blocks
        result
            .blocks
            .resize(num_blocks_output as usize, target_sks.key.create_trivial(0));

        Ok(result)
    }
}

// Owned-only methods.
impl OprfServerKey {
    pub fn new(sk: &OprfPrivateKey, target_ck: &ClientKey) -> crate::Result<Self> {
        ShortintOprfServerKey::new(&sk.0, &target_ck.key).map(|key| Self { key })
    }

    pub fn as_view(&self) -> OprfServerKeyView<'_> {
        OprfServerKeyView {
            key: self.key.as_view(),
        }
    }
}

impl ServerKey {
    pub fn as_oprf_key_view(&self) -> OprfServerKeyView<'_> {
        OprfServerKeyView {
            key: self.key.as_oprf_key_view(),
        }
    }
}

impl ParameterSetConformant for OprfServerKey {
    type ParameterSet = AtomicPatternParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        self.key.is_conformant(parameter_set)
    }
}

impl Named for OprfPrivateKey {
    const NAME: &'static str = "integer::OprfPrivateKey";
}

impl Named for OprfServerKey {
    const NAME: &'static str = "integer::OprfServerKey";
}

impl Named for CompressedOprfServerKey {
    const NAME: &'static str = "integer::CompressedOprfServerKey";
}
