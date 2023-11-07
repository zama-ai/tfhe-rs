use crate::forward_compatibility::ConvertInto;

use crate::core_crypto::entities::lwe_multi_bit_bootstrap_key::LweMultiBitBootstrapKey;
use crate::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList;
use next_tfhe::core_crypto::entities::lwe_multi_bit_bootstrap_key::LweMultiBitBootstrapKey as NextLweMultiBitBootstrapKey;
use next_tfhe::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList as NextFourierPolynomialList;

use crate::core_crypto::commons::numeric::UnsignedInteger;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<LweMultiBitBootstrapKey<C>>
    for NextLweMultiBitBootstrapKey<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: LweMultiBitBootstrapKey<C>) -> Self {
        let glwe_size = value.glwe_size();
        let polynomial_size = value.polynomial_size();
        let decomp_base_log = value.decomposition_base_log();
        let decomp_level_count = value.decomposition_level_count();
        let grouping_factor = value.grouping_factor();
        let ciphertext_modulus = value.ciphertext_modulus();
        let container = value.into_container();

        Self::from_container(
            container,
            glwe_size.convert_into(),
            polynomial_size.convert_into(),
            decomp_base_log.convert_into(),
            decomp_level_count.convert_into(),
            grouping_factor.convert_into(),
            ciphertext_modulus.convert_into(),
        )
    }
}

use crate::core_crypto::entities::lwe_multi_bit_bootstrap_key::FourierLweMultiBitBootstrapKey;
use next_tfhe::core_crypto::entities::lwe_multi_bit_bootstrap_key::FourierLweMultiBitBootstrapKey as NextFourierLweMultiBitBootstrapKey;

use next_tfhe::core_crypto::commons::traits::Container as NextContainer;
use next_tfhe::core_crypto::fft_impl::fft64::{c64 as NextC64, ABox as NextABox};

use crate::core_crypto::commons::traits::Container;
use crate::core_crypto::fft_impl::fft64::c64;

impl<C> crate::forward_compatibility::ConvertFrom<FourierLweMultiBitBootstrapKey<C>>
    for NextFourierLweMultiBitBootstrapKey<NextABox<[NextC64]>>
where
    C: Container<Element = c64> + NextContainer<Element = NextC64>,
{
    #[inline]
    fn convert_from(value: FourierLweMultiBitBootstrapKey<C>) -> Self {
        let input_lwe_dimension = value.input_lwe_dimension();
        let glwe_size = value.glwe_size();
        let polynomial_size = value.polynomial_size();
        let decomposition_base_log = value.decomposition_base_log();
        let decomposition_level_count = value.decomposition_level_count();
        let grouping_factor = value.grouping_factor();
        let data = value.data();

        let poly_list = FourierPolynomialList {
            data,
            polynomial_size,
        };

        let next_poly_list: NextFourierPolynomialList<_> = poly_list.convert_into();
        let data = next_poly_list.data;

        Self::from_container(
            data,
            input_lwe_dimension.convert_into(),
            glwe_size.convert_into(),
            polynomial_size.convert_into(),
            decomposition_base_log.convert_into(),
            decomposition_level_count.convert_into(),
            grouping_factor.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_lwe_multi_bit_bootstrap_key() {
        use crate::core_crypto::entities::lwe_multi_bit_bootstrap_key::LweMultiBitBootstrapKey;
        use next_tfhe::core_crypto::entities::lwe_multi_bit_bootstrap_key::LweMultiBitBootstrapKey as NextLweMultiBitBootstrapKey;

        use crate::core_crypto::commons::parameters::*;

        let input_lwe_dimension = LweDimension(100);
        let polynomial_size = PolynomialSize(2048);
        let glwe_size = GlweSize(2);
        let decomp_base_log = DecompositionBaseLog(23);
        let decomp_level_count = DecompositionLevelCount(1);
        let grouping_factor = LweBskGroupingFactor(2);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let tfhe_struct = LweMultiBitBootstrapKey::new(
            0u64,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            grouping_factor,
            ciphertext_modulus,
        );
        let _next_tfhe_struct: NextLweMultiBitBootstrapKey<_> = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_fourier_lwe_multi_bit_bootstrap_key() {
        use crate::core_crypto::entities::lwe_multi_bit_bootstrap_key::{
            FourierLweMultiBitBootstrapKey, LweMultiBitBootstrapKey,
        };
        use next_tfhe::core_crypto::entities::lwe_multi_bit_bootstrap_key::FourierLweMultiBitBootstrapKey as NextFourierLweMultiBitBootstrapKey;

        use crate::core_crypto::algorithms::par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier;
        use crate::core_crypto::commons::parameters::*;

        let input_lwe_dimension = LweDimension(100);
        let polynomial_size = PolynomialSize(2048);
        let glwe_size = GlweSize(2);
        let decomp_base_log = DecompositionBaseLog(23);
        let decomp_level_count = DecompositionLevelCount(1);
        let grouping_factor = LweBskGroupingFactor(2);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let bsk = LweMultiBitBootstrapKey::new(
            0u64,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            grouping_factor,
            ciphertext_modulus,
        );
        let mut tfhe_struct = FourierLweMultiBitBootstrapKey::new(
            bsk.input_lwe_dimension(),
            bsk.glwe_size(),
            bsk.polynomial_size(),
            bsk.decomposition_base_log(),
            bsk.decomposition_level_count(),
            bsk.grouping_factor(),
        );

        par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(&bsk, &mut tfhe_struct);

        let _next_tfhe_struct: NextFourierLweMultiBitBootstrapKey<_> = tfhe_struct.convert_into();
    }
}
