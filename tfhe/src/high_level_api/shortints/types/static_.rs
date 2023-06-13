use serde::{Deserialize, Serialize};
use std::fmt::Formatter;

use crate::shortint::parameters::{
    CarryModulus, ClassicPBSParameters, CoreCiphertextModulus, DecompositionBaseLog,
    DecompositionLevelCount, EncryptionKeyChoice, GlweDimension, LweDimension, MessageModulus,
    PolynomialSize, StandardDev,
};

use crate::high_level_api::shortints::{CompressedGenericShortint, GenericShortInt};

use super::{
    GenericShortIntClientKey, GenericShortIntCompressedPublicKey,
    GenericShortIntCompressedServerKey, GenericShortIntPublicKey, GenericShortIntServerKey,
};

use crate::high_level_api::shortints::parameters::{
    ShortIntegerParameter, StaticShortIntegerParameter,
};

use paste::paste;

/// Generic Parameter struct for short integers.
///
/// It allows to customize the same parameters as the ones
/// from the underlying `crate::shortint` with the exception of
/// the number of bits of message as its embeded in the type.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct ShortIntegerParameterSet<const MESSAGE_BITS: u8> {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_modular_std_dev: StandardDev,
    pub glwe_modular_std_dev: StandardDev,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CoreCiphertextModulus<u64>,
    pub encryption_key_choice: EncryptionKeyChoice,
}

impl<const MESSAGE_BITS: u8> ShortIntegerParameterSet<MESSAGE_BITS> {
    const fn from_static(params: &'static ClassicPBSParameters) -> Self {
        if params.message_modulus.0 != 1 << MESSAGE_BITS as usize {
            panic!("Invalid bit number");
        }
        Self {
            lwe_dimension: params.lwe_dimension,
            glwe_dimension: params.glwe_dimension,
            polynomial_size: params.polynomial_size,
            lwe_modular_std_dev: params.lwe_modular_std_dev,
            glwe_modular_std_dev: params.glwe_modular_std_dev,
            pbs_base_log: params.pbs_base_log,
            pbs_level: params.pbs_level,
            ks_base_log: params.ks_base_log,
            ks_level: params.ks_level,
            carry_modulus: params.carry_modulus,
            ciphertext_modulus: params.ciphertext_modulus,
            encryption_key_choice: params.encryption_key_choice,
        }
    }
}

impl<const MESSAGE_BITS: u8> From<ShortIntegerParameterSet<MESSAGE_BITS>> for ClassicPBSParameters {
    fn from(params: ShortIntegerParameterSet<MESSAGE_BITS>) -> Self {
        Self {
            lwe_dimension: params.lwe_dimension,
            glwe_dimension: params.glwe_dimension,
            polynomial_size: params.polynomial_size,
            lwe_modular_std_dev: params.lwe_modular_std_dev,
            glwe_modular_std_dev: params.glwe_modular_std_dev,
            pbs_base_log: params.pbs_base_log,
            pbs_level: params.pbs_level,
            ks_base_log: params.ks_base_log,
            ks_level: params.ks_level,
            message_modulus: MessageModulus(1 << MESSAGE_BITS as usize),
            carry_modulus: params.carry_modulus,
            ciphertext_modulus: params.ciphertext_modulus,
            encryption_key_choice: params.encryption_key_choice,
        }
    }
}

/// The Id that is used to identify and retrieve the corresponding keys
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct ShorIntId<const MESSAGE_BITS: u8>;

impl<const MESSAGE_BITS: u8> Serialize for ShorIntId<MESSAGE_BITS> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_unit_struct("ShorIntId")
    }
}

impl<'de, const MESSAGE_BITS: u8> Deserialize<'de> for ShorIntId<MESSAGE_BITS> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor<const MESSAGE_BITS: u8>;

        impl<'de, const MESSAGE_BITS: u8> serde::de::Visitor<'de> for Visitor<MESSAGE_BITS> {
            type Value = ShorIntId<MESSAGE_BITS>;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("struct ShorIntId")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ShorIntId::<MESSAGE_BITS>)
            }
        }

        deserializer.deserialize_unit_struct("ShorIntId", Visitor::<MESSAGE_BITS>)
    }
}

impl<const MESSAGE_BITS: u8> ShortIntegerParameter for ShortIntegerParameterSet<MESSAGE_BITS> {
    type Id = ShorIntId<MESSAGE_BITS>;
}

impl<const MESSAGE_BITS: u8> StaticShortIntegerParameter
    for ShortIntegerParameterSet<MESSAGE_BITS>
{
    const MESSAGE_BITS: u8 = MESSAGE_BITS;
}

/// Defines a new static shortint type.
///
/// It needs as input the:
///     - name of the type
///     - the number of bits of message the type has
///     - the keychain member where ClientKey / Server Key is stored
///
/// It generates code:
///     - type alias for the client key, server key, parameter and shortint types
///     - the trait impl on the id type to access the keys
macro_rules! static_shortint_type {
    (
        $(#[$outer:meta])*
        $name:ident {
            num_bits: $num_bits:literal,
            keychain_member: $($member:ident).*,
        }
    ) => {
        paste! {

            #[doc = concat!("Parameters for the [", stringify!($name), "] data type.")]
            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "shortint"))]
            pub type [<$name Parameters>] = ShortIntegerParameterSet<$num_bits>;

            pub(in crate::high_level_api) type [<$name ClientKey>] = GenericShortIntClientKey<[<$name Parameters>]>;
            pub(in crate::high_level_api) type [<$name PublicKey>] = GenericShortIntPublicKey<[<$name Parameters>]>;
            pub(in crate::high_level_api) type [<$name CompressedPublicKey>] = GenericShortIntCompressedPublicKey<[<$name Parameters>]>;
            pub(in crate::high_level_api) type [<$name ServerKey>] = GenericShortIntServerKey<[<$name Parameters>]>;
            pub(in crate::high_level_api) type [<$name CompressedServerKey>] = GenericShortIntCompressedServerKey<[<$name Parameters>]>;

            $(#[$outer])*
            #[doc=concat!("An unsigned integer type with ", stringify!($num_bits), " bits.")]
            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "shortint"))]
            pub type $name = GenericShortInt<[<$name Parameters>]>;

            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "shortint"))]
            pub type [<Compressed $name>] = CompressedGenericShortint<[<$name Parameters>]>;

            impl_ref_key_from_keychain!(
                for <[<$name Parameters>] as ShortIntegerParameter>::Id {
                    key_type: [<$name ClientKey>],
                    keychain_member: $($member).*,
                    type_variant: crate::high_level_api::errors::Type::$name,
                }
            );

            impl_ref_key_from_public_keychain!(
                for <[<$name Parameters>] as ShortIntegerParameter>::Id {
                    key_type: [<$name PublicKey>],
                    keychain_member: $($member).*,
                    type_variant: crate::high_level_api::errors::Type::$name,
                }
            );

            impl_ref_key_from_compressed_public_keychain!(
                for <[<$name Parameters>] as ShortIntegerParameter>::Id {
                    key_type: [<$name CompressedPublicKey>],
                    keychain_member: $($member).*,
                    type_variant: crate::high_level_api::errors::Type::$name,
                }
            );

            impl_with_global_key!(
                for <[<$name Parameters>] as ShortIntegerParameter>::Id {
                    key_type: [<$name ServerKey>],
                    keychain_member: $($member).*,
                    type_variant: crate::high_level_api::errors::Type::$name,
                }
            );
        }
    };
}

static_shortint_type! {
    FheUint2 {
        num_bits: 2,
        keychain_member: shortint_key.uint2_key,
    }
}

static_shortint_type! {
    FheUint3 {
        num_bits: 3,
        keychain_member: shortint_key.uint3_key,
    }
}

static_shortint_type! {
    FheUint4 {
        num_bits: 4,
        keychain_member: shortint_key.uint4_key,
    }
}

impl FheUint2Parameters {
    pub fn with_carry_1() -> Self {
        Self::from_static(&crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_1_KS_PBS)
    }

    pub fn with_carry_2() -> Self {
        Self::from_static(&crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS)
    }

    pub fn with_carry_3() -> Self {
        Self::from_static(&crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_3_KS_PBS)
    }

    pub fn with_carry_4() -> Self {
        Self::from_static(&crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_4_KS_PBS)
    }

    pub fn with_carry_5() -> Self {
        Self::from_static(&crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_5_KS_PBS)
    }

    pub fn with_carry_6() -> Self {
        Self::from_static(&crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_6_KS_PBS)
    }
}

impl Default for FheUint2Parameters {
    fn default() -> Self {
        Self::with_carry_2()
    }
}

impl FheUint3Parameters {
    pub fn with_carry_1() -> Self {
        Self::from_static(&crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_1_KS_PBS)
    }

    pub fn with_carry_2() -> Self {
        Self::from_static(&crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_2_KS_PBS)
    }

    pub fn with_carry_3() -> Self {
        Self::from_static(&crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS)
    }

    pub fn with_carry_4() -> Self {
        Self::from_static(&crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_4_KS_PBS)
    }

    pub fn with_carry_5() -> Self {
        Self::from_static(&crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_5_KS_PBS)
    }
}

impl Default for FheUint3Parameters {
    fn default() -> Self {
        Self::with_carry_3()
    }
}

impl FheUint4Parameters {
    pub fn with_carry_1() -> Self {
        Self::from_static(&crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_1_KS_PBS)
    }

    pub fn with_carry_2() -> Self {
        Self::from_static(&crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_2_KS_PBS)
    }

    pub fn with_carry_3() -> Self {
        Self::from_static(&crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_3_KS_PBS)
    }

    pub fn with_carry_4() -> Self {
        Self::from_static(&crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_KS_PBS)
    }
}

impl Default for FheUint4Parameters {
    fn default() -> Self {
        Self::with_carry_4()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn can_serialize_deserialize_shortint_id() {
        let id = ShorIntId::<2>;
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        bincode::serialize_into(&mut cursor, &id).unwrap();
        cursor.set_position(0);
        let id2: ShorIntId<2> = bincode::deserialize_from(cursor).unwrap();

        assert_eq!(id, id2);
    }
}
