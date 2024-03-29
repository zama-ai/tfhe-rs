use crate::core_crypto::commons::traits::Container;
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKey;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;
use next_tfhe::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKey as NextFourier128LweBootstrapKey;

impl<C> crate::forward_compatibility::ConvertFrom<Fourier128LweBootstrapKey<C>>
    for NextFourier128LweBootstrapKey<C>
where
    C: Container<Element = f64> + NextContainer<Element = f64>,
{
    #[inline]
    fn convert_from(value: Fourier128LweBootstrapKey<C>) -> Self {
        let polynomial_size = value.polynomial_size();
        let input_lwe_dimension = value.input_lwe_dimension();
        let glwe_size = value.glwe_size();
        let decomposition_base_log = value.decomposition_base_log();
        let decomposition_level_count = value.decomposition_level_count();

        let (data_re0, data_re1, data_im0, data_im1) = value.data();

        Self::from_container(
            data_re0,
            data_re1,
            data_im0,
            data_im1,
            polynomial_size.convert_into(),
            input_lwe_dimension.convert_into(),
            glwe_size.convert_into(),
            decomposition_base_log.convert_into(),
            decomposition_level_count.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_fourier128_lwe_bootstrap_key() {
        use crate::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKey;
        use next_tfhe::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKey as NextFourier128LweBootstrapKey;

        use crate::core_crypto::commons::parameters::*;

        let input_lwe_dimension = LweDimension(100);
        let polynomial_size = PolynomialSize(2048);
        let glwe_size = GlweSize(2);
        let decomposition_level_count = DecompositionLevelCount(1);
        let decomposition_base_log = DecompositionBaseLog(23);

        let container_len = input_lwe_dimension.0
            * polynomial_size.to_fourier_polynomial_size().0
            * glwe_size.0
            * glwe_size.0
            * decomposition_level_count.0;

        let data_re0 = vec![0.0f64; container_len];
        let data_re1 = vec![1.0f64; container_len];
        let data_im0 = vec![2.0f64; container_len];
        let data_im1 = vec![3.0f64; container_len];

        let tfhe_struct = Fourier128LweBootstrapKey::from_container(
            data_re0,
            data_re1,
            data_im0,
            data_im1,
            polynomial_size,
            input_lwe_dimension,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
        );

        let _next_tfhe_struct: NextFourier128LweBootstrapKey<_> = tfhe_struct.convert_into();
    }
}
