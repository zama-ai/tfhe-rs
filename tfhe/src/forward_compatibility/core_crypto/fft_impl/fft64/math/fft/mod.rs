use crate::core_crypto::commons::traits::Container;
use crate::core_crypto::fft_impl::fft64::c64;
use crate::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList;
use next_tfhe::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList as NextFourierPolynomialList;
use next_tfhe::core_crypto::fft_impl::fft64::{c64 as NextC64, ABox as NextABox};

impl<C> crate::forward_compatibility::ConvertFrom<FourierPolynomialList<C>>
    for NextFourierPolynomialList<NextABox<[NextC64]>>
where
    C: Container<Element = c64>,
{
    #[inline]
    fn convert_from(value: FourierPolynomialList<C>) -> Self {
        // As fft plans are unique per TFHE-rs instance, we need to convert to a common format then
        // convert back, for now we go through serialization, otherwise coefficients will be
        // completely in the wrong order
        let serialized = bincode::serialize(&value).unwrap();
        drop(value);

        bincode::deserialize(&serialized).unwrap()
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_fourier_polynomial_list() {
        use crate::core_crypto::commons::parameters::PolynomialSize;
        use crate::core_crypto::fft_impl::fft64::c64;
        use crate::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList;
        use next_tfhe::core_crypto::fft_impl::fft64::math::fft::FourierPolynomialList as NextFourierPolynomialList;
        use next_tfhe::core_crypto::fft_impl::fft64::{c64 as NextC64, ABox as NextABox};

        let polynomial_size = PolynomialSize(2048);

        let tfhe_struct = FourierPolynomialList {
            data: vec![c64::new(0.0, 0.0); polynomial_size.0],
            polynomial_size,
        };

        let next_tfhe_struct: NextFourierPolynomialList<NextABox<[NextC64]>> =
            tfhe_struct.convert_into();

        assert_eq!(next_tfhe_struct.polynomial_size.0, polynomial_size.0);
    }
}
