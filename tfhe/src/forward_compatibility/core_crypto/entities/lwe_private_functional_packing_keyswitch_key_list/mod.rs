use crate::core_crypto::entities::lwe_private_functional_packing_keyswitch_key_list::LwePrivateFunctionalPackingKeyswitchKeyList;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::core_crypto::entities::lwe_private_functional_packing_keyswitch_key_list::LwePrivateFunctionalPackingKeyswitchKeyList as NextLwePrivateFunctionalPackingKeyswitchKeyList;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C>
    crate::forward_compatibility::ConvertFrom<LwePrivateFunctionalPackingKeyswitchKeyList<C>>
    for NextLwePrivateFunctionalPackingKeyswitchKeyList<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: LwePrivateFunctionalPackingKeyswitchKeyList<C>) -> Self {
        let decomp_base_log = value.decomposition_base_log();
        let decomp_level_count = value.decomposition_level_count();
        let input_lwe_size = value.input_lwe_size();
        let output_glwe_size = value.output_glwe_size();
        let output_polynomial_size = value.output_polynomial_size();
        let ciphertext_modulus = value.ciphertext_modulus();
        let container = value.into_container();

        Self::from_container(
            container,
            decomp_base_log.convert_into(),
            decomp_level_count.convert_into(),
            input_lwe_size.convert_into(),
            output_glwe_size.convert_into(),
            output_polynomial_size.convert_into(),
            ciphertext_modulus.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_lwe_private_functional_packing_keyswitch_key_list() {
        use crate::core_crypto::entities::lwe_private_functional_packing_keyswitch_key_list::LwePrivateFunctionalPackingKeyswitchKeyList;
        use next_tfhe::core_crypto::entities::lwe_private_functional_packing_keyswitch_key_list::LwePrivateFunctionalPackingKeyswitchKeyList as NextLwePrivateFunctionalPackingKeyswitchKeyList;

        use crate::core_crypto::commons::parameters::*;

        let tfhe_struct = LwePrivateFunctionalPackingKeyswitchKeyList::new(
            0u64,
            DecompositionBaseLog(12),
            DecompositionLevelCount(2),
            LweDimension(100),
            GlweSize(2),
            PolynomialSize(1024),
            FunctionalPackingKeyswitchKeyCount(2),
            CiphertextModulus::new_native(),
        );

        let _next_tfhe_struct: NextLwePrivateFunctionalPackingKeyswitchKeyList<_> =
            tfhe_struct.convert_into();
    }
}
