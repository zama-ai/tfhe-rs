use tfhe_versionable::Versionize;

use self::packed_integers::PackedIntegers;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::backward_compatibility::entities::compressed_modulus_switched_lwe_ciphertext::CompressedModulusSwitchedLweCiphertextVersions;
use crate::core_crypto::prelude::*;

/// An object to store a ciphertext using less memory
/// The modulus of the ciphertext is decreased by rounding and the result is stored in a compact way
/// The uncompacted result can be used as the input of a blind rotation to recover a low noise lwe
/// ciphertext
///
/// ```rust
/// use itertools::Itertools;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe_csprng::seeders::Seed;
///
/// let log_modulus = 12;
///
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(Seed(0));
///
/// // Create the LweSecretKey
/// let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key::<u64, _>(
///     LweDimension(2048),
///     &mut secret_generator,
/// );
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
///
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
///
/// // Unsecure parameters, do not use them
/// let lwe = allocate_and_encrypt_new_lwe_ciphertext(
///     &lwe_secret_key,
///     Plaintext(0),
///     Gaussian::from_standard_dev(StandardDev(0.), 0.),
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let lwe_msed_before =
///     lwe_ciphertext_modulus_switch::<_, u64, _>(lwe, CiphertextModulusLog(log_modulus));
///
/// // Can be stored using much less space than the standard lwe ciphertexts
/// let compressed = lwe_msed_before.compress::<u64>();
///
/// let lwe_msed_after = compressed.extract::<u64>();
///
/// for (i, j) in lwe_msed_before.mask().zip_eq(lwe_msed_after.mask()) {
///     assert_eq!(i, j);
/// }
///
/// assert!(lwe_msed_before.body() == lwe_msed_after.body());
/// ```
#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedModulusSwitchedLweCiphertextVersions)]
pub struct CompressedModulusSwitchedLweCiphertext<PackingScalar: UnsignedInteger> {
    packed_integers: PackedIntegers<PackingScalar>,
    lwe_dimension: LweDimension,
}

pub trait ToCompressedModulusSwitchedLweCiphertext<SwitchedScalar> {
    fn compress<PackingScalar>(&self) -> CompressedModulusSwitchedLweCiphertext<PackingScalar>
    where
        SwitchedScalar: CastInto<PackingScalar>,
        PackingScalar: UnsignedInteger;
}

impl<T: ModulusSwitchedLweCiphertext<SwitchedScalar>, SwitchedScalar: UnsignedInteger>
    ToCompressedModulusSwitchedLweCiphertext<SwitchedScalar> for T
{
    fn compress<PackingScalar>(&self) -> CompressedModulusSwitchedLweCiphertext<PackingScalar>
    where
        SwitchedScalar: CastInto<PackingScalar>,
        PackingScalar: UnsignedInteger,
    {
        let log_modulus = self.log_modulus();

        let container: Vec<SwitchedScalar> =
            self.mask().chain(std::iter::once(self.body())).collect();

        let packed_integers = PackedIntegers::pack(&container, log_modulus);

        CompressedModulusSwitchedLweCiphertext::from_raw_parts(
            packed_integers,
            self.lwe_dimension(),
        )
    }
}

impl<PackingScalar: UnsignedInteger> CompressedModulusSwitchedLweCiphertext<PackingScalar> {
    pub(crate) fn from_raw_parts(
        packed_integers: PackedIntegers<PackingScalar>,
        lwe_dimension: LweDimension,
    ) -> Self {
        assert_eq!(packed_integers.initial_len(), lwe_dimension.to_lwe_size().0,
            "Packed integers list is not of the correct size for the uncompressed LWE: expected {}, got {}",
            lwe_dimension.to_lwe_size().0,
            packed_integers.initial_len());

        Self {
            packed_integers,
            lwe_dimension,
        }
    }

    #[cfg(test)]
    pub(crate) fn into_raw_parts(self) -> (PackedIntegers<PackingScalar>, LweDimension) {
        let Self {
            packed_integers,
            lwe_dimension,
        } = self;

        (packed_integers, lwe_dimension)
    }

    pub fn extract<Scalar>(&self) -> StandardModulusSwitchedLweCiphertext<Scalar>
    where
        PackingScalar: CastInto<Scalar>,
        Scalar: UnsignedInteger,
    {
        let lwe_size = self.lwe_dimension.to_lwe_size().0;

        let initial_len = self.packed_integers.initial_len();

        assert_eq!(
            lwe_size, initial_len,
            "Mismatch between actual(={lwe_size}) and expected(={initial_len}) lwe  size",
        );

        StandardModulusSwitchedLweCiphertext::from_packed(&self.packed_integers)
    }
}

#[derive(Copy, Clone)]
pub enum MsDecompressionType {
    ClassicPbs,
    MultiBitPbs(LweBskGroupingFactor),
}

#[derive(Copy, Clone)]
pub struct CompressedModulusSwitchedLweCiphertextConformanceParams<Scalar>
where
    Scalar: UnsignedInteger,
{
    pub ct_params: LweCiphertextConformanceParams<Scalar>,
    pub ms_decompression_type: MsDecompressionType,
}

impl<Scalar: UnsignedInteger> ParameterSetConformant
    for CompressedModulusSwitchedLweCiphertext<Scalar>
{
    type ParameterSet = CompressedModulusSwitchedLweCiphertextConformanceParams<Scalar>;

    fn is_conformant(
        &self,
        compressed_ct_parameters: &CompressedModulusSwitchedLweCiphertextConformanceParams<Scalar>,
    ) -> bool {
        let Self {
            packed_integers,
            lwe_dimension,
        } = self;

        let CompressedModulusSwitchedLweCiphertextConformanceParams {
            ct_params,
            ms_decompression_type,
        } = compressed_ct_parameters;

        let LweCiphertextConformanceParams {
            lwe_dim: params_lwe_dim,
            ct_modulus,
        } = ct_params;

        let lwe_size = lwe_dimension.to_lwe_size().0;

        let number_bits_to_pack = lwe_size * packed_integers.log_modulus().0;

        let len = number_bits_to_pack.div_ceil(Scalar::BITS);

        packed_integers.packed_coeffs().len() == len
            && lwe_dimension == params_lwe_dim
            && ct_modulus.is_power_of_two()
            && matches!(ms_decompression_type, MsDecompressionType::ClassicPbs)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core_crypto::fft_impl::common::modulus_switch;
    use rand::{Fill, Rng};

    #[test]
    fn ms_compression_() {
        ms_compression::<u32, u32, u32>(1, 100);
        ms_compression::<u32, u32, u32>(10, 64);
        ms_compression::<u32, u32, u32>(11, 700);
        ms_compression::<u32, u32, u32>(12, 751);

        ms_compression::<u64, u64, u64>(1, 100);
        ms_compression::<u64, u64, u64>(10, 64);
        ms_compression::<u64, u64, u64>(11, 700);
        ms_compression::<u64, u64, u64>(12, 751);
        ms_compression::<u64, u64, u64>(33, 10);
        ms_compression::<u64, u64, u64>(53, 37);
        ms_compression::<u64, u64, u64>(63, 63);

        ms_compression::<u128, u128, u128>(127, 127);

        ms_compression::<u32, u32, u64>(1, 100);
        ms_compression::<u32, u32, u64>(10, 64);
        ms_compression::<u32, u32, u64>(11, 700);
        ms_compression::<u32, u32, u64>(12, 751);

        ms_compression::<u32, u32, u64>(1, 100);
        ms_compression::<u32, u32, u64>(10, 64);
        ms_compression::<u32, u32, u64>(11, 700);
        ms_compression::<u32, u32, u64>(12, 751);

        ms_compression::<u64, u64, u128>(1, 100);
        ms_compression::<u64, u64, u128>(10, 64);
        ms_compression::<u64, u64, u128>(11, 700);
        ms_compression::<u64, u64, u128>(12, 751);
        ms_compression::<u64, u64, u128>(33, 10);
        ms_compression::<u64, u64, u128>(53, 37);
        ms_compression::<u64, u64, u128>(63, 63);
    }

    fn ms_compression<
        Scalar: UnsignedTorus + CastInto<SwitchedScalar>,
        SwitchedScalar: UnsignedTorus + CastFrom<PackingScalar>,
        PackingScalar: UnsignedTorus + CastFrom<SwitchedScalar>,
    >(
        log_modulus: usize,
        len: usize,
    ) where
        [Scalar]: Fill,
    {
        let ciphertext_modulus = CiphertextModulus::new_native();

        let mut lwe = LweCiphertext::new(Scalar::ZERO, LweSize(len), ciphertext_modulus);

        // We don't care about the exact content here
        rand::rng().fill(lwe.as_mut());

        let lwe_msed_before_packing = lwe_ciphertext_modulus_switch::<_, SwitchedScalar, _>(
            lwe.as_view(),
            CiphertextModulusLog(log_modulus),
        );

        let compressed = lwe_msed_before_packing.compress::<PackingScalar>();

        let lwe_msed_after_packing = compressed.extract::<SwitchedScalar>();

        let lwe = lwe.into_container();

        for (i, output) in lwe_msed_after_packing.container().iter().enumerate() {
            assert!(*output < SwitchedScalar::ONE << log_modulus);

            let msed: Scalar = modulus_switch(lwe[i], CiphertextModulusLog(log_modulus));

            assert_eq!(*output, msed.cast_into());
        }
    }

    #[test]
    fn test_from_raw_parts() {
        type Scalar = u64;

        let len = 751;
        let log_modulus = 12;

        let ciphertext_modulus = CiphertextModulus::new_native();

        let mut lwe = LweCiphertext::new(Scalar::ZERO, LweSize(len), ciphertext_modulus);

        // We don't care about the exact content here
        rand::rng().fill(lwe.as_mut());

        let msed = lwe_ciphertext_modulus_switch::<_, Scalar, _>(
            lwe.as_view(),
            CiphertextModulusLog(log_modulus),
        );

        let (packed_integers, lwe_dimension) = msed.compress::<u64>().into_raw_parts();

        let rebuilt =
            CompressedModulusSwitchedLweCiphertext::from_raw_parts(packed_integers, lwe_dimension);

        let lwe_ms_ed = rebuilt.extract::<Scalar>();

        let lwe_ms_ed = lwe_ms_ed.container();

        let lwe = lwe.into_container();

        for (i, output) in lwe_ms_ed.iter().enumerate() {
            assert!(*output < 1 << log_modulus);

            let msed = modulus_switch(lwe[i], CiphertextModulusLog(log_modulus));

            assert_eq!(*output, msed)
        }
    }
}
