use crate::forward_compatibility::ConvertInto;

use crate::integer::public_key::standard::PublicKey;
use next_tfhe::integer::public_key::standard::PublicKey as NextPublicKey;

impl crate::forward_compatibility::ConvertFrom<PublicKey> for NextPublicKey {
    #[inline]
    fn convert_from(value: PublicKey) -> Self {
        let key = value.into_raw_parts();

        Self::from_raw_parts(key.convert_into())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_public_key() {
        use crate::integer::public_key::standard::PublicKey;
        use next_tfhe::integer::public_key::standard::PublicKey as NextPublicKey;

        use crate::integer::{gen_keys, IntegerKeyKind};
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, _sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS, IntegerKeyKind::Radix);
        let tfhe_struct = PublicKey::new(&cks);
        let _next_tfhe_struct: NextPublicKey = tfhe_struct.convert_into();
    }
}
