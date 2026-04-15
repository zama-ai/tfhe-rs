use super::{RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::conformance::ParameterSetConformant;
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::ClientKey;
use crate::named::Named;
use crate::shortint::oprf::{
    CompressedOprfServerKey as ShortintCompressedOprfServerKey, ExpandedOprfServerKey,
    OprfPrivateKey as ShortintOprfPrivateKey, OprfServerKey as ShortintOprfServerKey,
};
use crate::shortint::server_key::ShortintBootstrappingKey;
use crate::shortint::{AtomicPatternParameters, OprfSeed};
use std::borrow::Borrow;
use std::num::NonZeroU64;
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
        self.0.expand()
    }

    pub(crate) fn is_conformant(&self, sk_param: &AtomicPatternParameters) -> bool {
        self.0.is_conformant(sk_param)
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(OprfServerKeyVersions)]
pub struct OprfServerKey(pub(crate) ShortintOprfServerKey);

pub type OprfServerKeyView<'a> =
    crate::shortint::oprf::GenericOprfServerKey<&'a ShortintBootstrappingKey<u64>>;

// Helper functions for integer-level OPRF operations, used by both OprfServerKey and
// OprfServerKeyView.
fn par_generate_oblivious_pseudo_random_integer_full_impl<
    T: IntegerRadixCiphertext,
    K: Borrow<ShortintBootstrappingKey<u64>> + Sync,
>(
    shortint_key: &crate::shortint::oprf::GenericOprfServerKey<K>,
    seed: impl OprfSeed,
    num_blocks: u64,
    target_sks: &ServerKey,
) -> T {
    assert!(target_sks.message_modulus().0.is_power_of_two());
    let message_bits_count = target_sks.message_modulus().0.ilog2() as u64;

    let blocks = shortint_key.generate_oblivious_pseudo_random_bits(
        seed,
        num_blocks * message_bits_count,
        &target_sks.key,
    );

    T::from(blocks)
}

fn par_generate_oblivious_pseudo_random_integer_bounded_impl<
    T: IntegerRadixCiphertext,
    K: Borrow<ShortintBootstrappingKey<u64>> + Sync,
>(
    shortint_key: &crate::shortint::oprf::GenericOprfServerKey<K>,
    seed: impl OprfSeed,
    random_bits_count: u64,
    num_blocks: u64,
    target_sks: &ServerKey,
) -> T {
    assert!(target_sks.message_modulus().0.is_power_of_two());
    let message_bits_count = target_sks.message_modulus().0.ilog2() as u64;
    let range_log_size = message_bits_count * num_blocks;

    if T::IS_SIGNED {
        #[allow(clippy::int_plus_one)]
        {
            assert!(
                random_bits_count + 1 <= range_log_size,
                "The range asked for a random value (=[0, 2^{}[) does not fit in the available range [-2^{}, 2^{}[",
                random_bits_count, range_log_size - 1, range_log_size - 1,
            );
        }
    } else {
        assert!(
            random_bits_count <= range_log_size,
            "The range asked for a random value (=[0, 2^{random_bits_count}[) does not fit in the available range [0, 2^{range_log_size}[",
        );
    }

    let mut blocks = shortint_key.generate_oblivious_pseudo_random_bits(
        seed,
        random_bits_count,
        &target_sks.key,
    );
    if blocks.len() < num_blocks as usize {
        blocks.resize(num_blocks as usize, target_sks.key.create_trivial(0));
    }

    T::from(blocks)
}

fn par_generate_oblivious_pseudo_random_unsigned_custom_range_impl<
    K: Borrow<ShortintBootstrappingKey<u64>> + Sync,
>(
    shortint_key: &crate::shortint::oprf::GenericOprfServerKey<K>,
    seed: impl OprfSeed,
    num_input_random_bits: u64,
    excluded_upper_bound: NonZeroU64,
    num_blocks_output: u64,
    target_sks: &ServerKey,
) -> RadixCiphertext {
    let excluded_upper_bound = excluded_upper_bound.get();

    assert!(target_sks.message_modulus().0.is_power_of_two());
    let message_bits_count = target_sks.message_modulus().0.ilog2() as u64;

    assert!(
        !excluded_upper_bound.is_power_of_two(),
        "Use the cheaper par_generate_oblivious_pseudo_random_unsigned_integer_bounded function instead"
    );

    let num_bits_output = num_blocks_output * message_bits_count;
    assert!(
        (excluded_upper_bound as f64) < 2_f64.powi(num_bits_output as i32),
        "num_blocks_output(={num_blocks_output}) is too small to hold an integer up to excluded_upper_bound(=excluded_upper_bound)"
    );

    let post_mul_num_bits =
        num_input_random_bits + (excluded_upper_bound as f64).log2().ceil() as u64;

    let num_blocks = post_mul_num_bits.div_ceil(message_bits_count);

    let random_input: RadixCiphertext = par_generate_oblivious_pseudo_random_integer_bounded_impl(
        shortint_key,
        seed,
        num_input_random_bits,
        num_blocks,
        target_sks,
    );

    let random_multiplied = target_sks.scalar_mul_parallelized(&random_input, excluded_upper_bound);

    let mut result =
        target_sks.scalar_right_shift_parallelized(&random_multiplied, num_input_random_bits);

    // Adjust the number of leading (MSB) trivial zeros blocks
    result
        .blocks
        .resize(num_blocks_output as usize, target_sks.key.create_trivial(0));

    result
}

impl OprfServerKey {
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
        par_generate_oblivious_pseudo_random_integer_full_impl(
            &self.0, seed, num_blocks, target_sks,
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
    /// let ct_res = oprf_sk.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
    ///     &0u128.to_le_bytes(),
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
        par_generate_oblivious_pseudo_random_integer_bounded_impl(
            &self.0,
            seed,
            random_bits_count,
            num_blocks,
            target_sks,
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
    /// let ct_res = oprf_sk.par_generate_oblivious_pseudo_random_unsigned_custom_range(
    ///     &0u128.to_le_bytes(),
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
    pub fn par_generate_oblivious_pseudo_random_unsigned_custom_range(
        &self,
        seed: impl OprfSeed,
        num_input_random_bits: u64,
        excluded_upper_bound: NonZeroU64,
        num_blocks_output: u64,
        target_sks: &ServerKey,
    ) -> RadixCiphertext {
        par_generate_oblivious_pseudo_random_unsigned_custom_range_impl(
            &self.0,
            seed,
            num_input_random_bits,
            excluded_upper_bound,
            num_blocks_output,
            target_sks,
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
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let oprf_pk = OprfPrivateKey::new(cks.as_ref());
    /// let oprf_sk = OprfServerKey::new(&oprf_pk, cks.as_ref()).unwrap();
    ///
    /// let ct_res = oprf_sk.par_generate_oblivious_pseudo_random_signed_integer(
    ///     tfhe::Seed(0),
    ///     size as u64,
    ///     &sks,
    /// );
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
        par_generate_oblivious_pseudo_random_integer_full_impl(
            &self.0, seed, num_blocks, target_sks,
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
    /// let ct_res = oprf_sk.par_generate_oblivious_pseudo_random_signed_integer_bounded(
    ///     &0u128.to_le_bytes(),
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
        par_generate_oblivious_pseudo_random_integer_bounded_impl(
            &self.0,
            seed,
            random_bits_count,
            num_blocks,
            target_sks,
        )
    }
}

impl OprfServerKeyView<'_> {
    pub fn par_generate_oblivious_pseudo_random_unsigned_integer(
        &self,
        seed: impl OprfSeed,
        num_blocks: u64,
        target_sks: &ServerKey,
    ) -> RadixCiphertext {
        par_generate_oblivious_pseudo_random_integer_full_impl(self, seed, num_blocks, target_sks)
    }

    pub fn par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        num_blocks: u64,
        target_sks: &ServerKey,
    ) -> RadixCiphertext {
        par_generate_oblivious_pseudo_random_integer_bounded_impl(
            self,
            seed,
            random_bits_count,
            num_blocks,
            target_sks,
        )
    }

    pub fn par_generate_oblivious_pseudo_random_signed_integer(
        &self,
        seed: impl OprfSeed,
        num_blocks: u64,
        target_sks: &ServerKey,
    ) -> SignedRadixCiphertext {
        par_generate_oblivious_pseudo_random_integer_full_impl(self, seed, num_blocks, target_sks)
    }

    pub fn par_generate_oblivious_pseudo_random_signed_integer_bounded(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        num_blocks: u64,
        target_sks: &ServerKey,
    ) -> SignedRadixCiphertext {
        par_generate_oblivious_pseudo_random_integer_bounded_impl(
            self,
            seed,
            random_bits_count,
            num_blocks,
            target_sks,
        )
    }

    pub fn par_generate_oblivious_pseudo_random_unsigned_custom_range(
        &self,
        seed: impl OprfSeed,
        num_input_random_bits: u64,
        excluded_upper_bound: NonZeroU64,
        num_blocks_output: u64,
        target_sks: &ServerKey,
    ) -> RadixCiphertext {
        par_generate_oblivious_pseudo_random_unsigned_custom_range_impl(
            self,
            seed,
            num_input_random_bits,
            excluded_upper_bound,
            num_blocks_output,
            target_sks,
        )
    }
}

// Owned-only methods.
impl OprfServerKey {
    pub fn new(sk: &OprfPrivateKey, target_ck: &ClientKey) -> crate::Result<Self> {
        ShortintOprfServerKey::new(&sk.0, &target_ck.key).map(Self)
    }

    pub fn from_raw_parts(inner: ShortintOprfServerKey) -> Self {
        Self(inner)
    }

    pub fn into_raw_parts(self) -> ShortintOprfServerKey {
        self.0
    }

    pub(crate) fn is_conformant(&self, sk_param: &AtomicPatternParameters) -> bool {
        self.0.is_conformant(sk_param)
    }

    pub fn as_view(&self) -> OprfServerKeyView<'_> {
        self.0.as_view()
    }
}

impl ParameterSetConformant for OprfServerKey {
    type ParameterSet = AtomicPatternParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        self.0.is_conformant(parameter_set)
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
