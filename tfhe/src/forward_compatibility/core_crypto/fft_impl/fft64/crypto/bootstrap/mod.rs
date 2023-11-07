use crate::core_crypto::commons::traits::Container;
use crate::core_crypto::fft_impl::fft64::c64;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;
use next_tfhe::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKey as NextFourierLweBootstrapKey;
use next_tfhe::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList as NextFourierPolynomialList;
use next_tfhe::core_crypto::fft_impl::fft64::{c64 as NextC64, ABox as NextABox};

impl<C> crate::forward_compatibility::ConvertFrom<FourierLweBootstrapKey<C>>
    for NextFourierLweBootstrapKey<NextABox<[NextC64]>>
where
    C: Container<Element = c64> + NextContainer<Element = NextC64>,
{
    #[inline]
    fn convert_from(value: FourierLweBootstrapKey<C>) -> Self {
        let input_lwe_dimension = value.input_lwe_dimension();
        let glwe_size = value.glwe_size();
        let polynomial_size = value.polynomial_size();
        let decomposition_base_log = value.decomposition_base_log();
        let decomposition_level_count = value.decomposition_level_count();
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
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_fourier_lwe_bootstrap_key() {
        use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKey;
        use next_tfhe::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKey as NextFourierLweBootstrapKey;

        use crate::core_crypto::commons::parameters::*;
        use crate::core_crypto::fft_impl::fft64::c64;
        use aligned_vec::avec;

        let input_lwe_dimension = LweDimension(100);
        let polynomial_size = PolynomialSize(2048);
        let glwe_size = GlweSize(2);
        let decomposition_level_count = DecompositionLevelCount(1);
        let decomposition_base_log = DecompositionBaseLog(23);
        let container = avec![
            c64::new(0.0, 0.0);
            input_lwe_dimension.0
                * polynomial_size.to_fourier_polynomial_size().0
                * glwe_size.0
                * glwe_size.0
                * decomposition_level_count.0
        ]
        .into_boxed_slice();

        let tfhe_struct = FourierLweBootstrapKey::from_container(
            container,
            input_lwe_dimension,
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
        );

        let _next_tfhe_struct: NextFourierLweBootstrapKey<_> = tfhe_struct.convert_into();
    }
}
