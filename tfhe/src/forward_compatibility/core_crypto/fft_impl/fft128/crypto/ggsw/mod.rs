use crate::core_crypto::commons::traits::Container;
use crate::core_crypto::fft_impl::fft128::crypto::ggsw::Fourier128GgswCiphertext;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;
use next_tfhe::core_crypto::fft_impl::fft128::crypto::ggsw::Fourier128GgswCiphertext as NextFourier128GgswCiphertext;

impl<C> crate::forward_compatibility::ConvertFrom<Fourier128GgswCiphertext<C>>
    for NextFourier128GgswCiphertext<C>
where
    C: Container<Element = f64> + NextContainer<Element = f64>,
{
    #[inline]
    fn convert_from(value: Fourier128GgswCiphertext<C>) -> Self {
        let polynomial_size = value.polynomial_size();
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
    fn test_conversion_fourier128_ggsw_ciphertext() {
        use crate::core_crypto::fft_impl::fft128::crypto::ggsw::Fourier128GgswCiphertext;
        use next_tfhe::core_crypto::fft_impl::fft128::crypto::ggsw::Fourier128GgswCiphertext as NextFourier128GgswCiphertext;

        use crate::core_crypto::commons::parameters::*;

        let polynomial_size = PolynomialSize(2048);
        let glwe_size = GlweSize(2);
        let decomposition_level_count = DecompositionLevelCount(1);
        let decomposition_base_log = DecompositionBaseLog(23);

        let container_len = polynomial_size.to_fourier_polynomial_size().0
            * glwe_size.0
            * glwe_size.0
            * decomposition_level_count.0;

        let data_re0 = vec![0.0f64; container_len];
        let data_re1 = vec![1.0f64; container_len];
        let data_im0 = vec![2.0f64; container_len];
        let data_im1 = vec![3.0f64; container_len];

        let tfhe_struct = Fourier128GgswCiphertext::from_container(
            data_re0,
            data_re1,
            data_im0,
            data_im1,
            polynomial_size,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
        );

        let _next_tfhe_struct: NextFourier128GgswCiphertext<_> = tfhe_struct.convert_into();
    }
}
