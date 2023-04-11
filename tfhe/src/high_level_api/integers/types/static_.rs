use serde::{Deserialize, Serialize};

use crate::high_level_api::integers::client_key::GenericIntegerClientKey;
use crate::high_level_api::integers::parameters::{
    EvaluationIntegerKey, IntegerParameter, RadixParameters, RadixRepresentation,
    StaticIntegerParameter, StaticRadixParameter,
};
use crate::high_level_api::integers::public_key::compressed::GenericIntegerCompressedPublicKey;
use crate::high_level_api::integers::public_key::GenericIntegerPublicKey;
use crate::high_level_api::integers::server_key::GenericIntegerServerKey;
use crate::high_level_api::integers::types::compressed::CompressedGenericInteger;
use crate::high_level_api::keys::RefKeyFromKeyChain;
use crate::high_level_api::traits::{FheDecrypt, FheEncrypt};
use crate::high_level_api::ClientKey;

use super::base::GenericInteger;
use crate::high_level_api::internal_traits::{DecryptionKey, EncryptionKey, ParameterType};
#[cfg(feature = "internal-keycache")]
use crate::integer::keycache::{KEY_CACHE, KEY_CACHE_WOPBS};
use crate::integer::wopbs::WopbsKey;
use paste::paste;

macro_rules! define_static_integer_parameters {
    (
        Radix {
            num_bits: $num_bits:literal,
            big_block_parameters: $big_block_parameters:expr,
            small_block_parameters: $small_block_parameters:expr,
            num_block: $num_block:literal,
            wopbs_block_parameters: $wopbs_block_parameters:expr,
        }
    ) => {
        paste! {
            #[doc = concat!("Id for the [FheUint", stringify!($num_bits), "] data type.")]
            #[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
            pub struct [<FheUint $num_bits Id>];

            #[doc = concat!("Parameters for the [FheUint", stringify!($num_bits), "] data type.")]
            #[derive(Copy, Clone, Debug, Serialize, Deserialize)]
            pub struct [<FheUint $num_bits Parameters>](pub(in crate::high_level_api) RadixParameters);

            impl Default for [<FheUint $num_bits Parameters>] {
                fn default() -> Self {
                    Self::big()
                }
            }

            impl [<FheUint $num_bits Parameters>] {
                pub fn big() -> Self {
                    Self(
                        RadixParameters {
                            block_parameters: $big_block_parameters,
                            num_block: $num_block,
                            wopbs_block_parameters: $wopbs_block_parameters,
                            pbs_order: crate::shortint::PBSOrder::KeyswitchBootstrap,
                        },
                    )
                }

                pub fn small() -> Self {
                    Self(
                        RadixParameters {
                            block_parameters: $small_block_parameters,
                            num_block: $num_block,
                            wopbs_block_parameters: $wopbs_block_parameters,
                            pbs_order: crate::shortint::PBSOrder::BootstrapKeyswitch,
                        }
                    )
                }
            }

            impl ParameterType for [<FheUint $num_bits Parameters>] {
                type Id = [<FheUint $num_bits Id>];
                type InnerCiphertext = crate::high_level_api::integers::server_key::RadixCiphertextDyn;
                type InnerClientKey = crate::high_level_api::integers::client_key::RadixClientKey;
                type InnerPublicKey = crate::high_level_api::integers::public_key::RadixPublicKey;
                type InnerServerKey = crate::integer::ServerKey;
            }

            impl IntegerParameter for [<FheUint $num_bits Parameters>] {
                fn wopbs_block_parameters(&self) -> crate::shortint::Parameters {
                    self.0.wopbs_block_parameters
                }

                fn block_parameters(&self) -> crate::shortint::Parameters {
                    self.0.block_parameters
                }
            }

            impl From<[<FheUint $num_bits Parameters>]> for RadixParameters {
                fn from(p: [<FheUint $num_bits Parameters>]) -> Self {
                    p.0
                }
            }

            impl StaticIntegerParameter for [<FheUint $num_bits Parameters>] {
                type Representation = RadixRepresentation;
                const MESSAGE_BITS: usize = $num_bits;
            }

            impl StaticRadixParameter for [<FheUint $num_bits Parameters>] {}
        }
    };
    (
        Crt {
            num_bits: $num_bits:literal,
            block_parameters: $block_parameters:expr,
            moduli: $moduli:expr,
            wopbs_block_parameters: $wopbs_block_parameters:expr,
        }
    ) => {
        paste! {
            #[doc = concat!("Id for the [FheUint", stringify!($num_bits), "] data type.")]
            #[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
            pub struct [<FheUint $num_bits Id>];

            #[doc = concat!("Parameters for the [FheUint", stringify!($num_bits), "] data type.")]
            #[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
            pub struct [<FheUint $num_bits Parameters>](CrtParameters);

            impl Default for [<FheUint $num_bits Parameters>] {
                fn default() -> Self {
                    Self(
                        CrtParameters {
                            block_parameters: $block_parameters,
                            moduli: $moduli,
                            wopbs_block_parameters: $wopbs_block_parameters,
                        },
                    )
                }
            }

            impl ParameterType for [<FheUint $num_bits Parameters>] {
                type Id = [<FheUint $num_bits Id>];
                type InnerCiphertext = crate::integer::CrtCiphertext;
                type InnerClientKey = crate::integer::CrtClientKey;
                type InnerPublicKey = crate::high_level_api::integers::public_key::CrtPublicKey;
                type InnerServerKey = crate::integer::ServerKey;
            }

            impl IntegerParameter for [<FheUint $num_bits Parameters>] {
                fn wopbs_block_parameters(&self) -> crate::shortint::Parameters {
                    self.0.wopbs_block_parameters
                }

                fn block_parameters(&self) -> crate::shortint::Parameters {
                    self.0.block_parameters
                }
            }

            impl From<[<FheUint $num_bits Parameters>]> for CrtCiphertext {
                fn from(p: [<FheUint $num_bits Parameters>]) -> Self {
                    p.0
                }
            }

            impl StaticIntegerParameter for [<FheUint $num_bits Parameters>] {
                type Representation = CrtRepresentation;
                const MESSAGE_BITS: usize = $num_bits;
            }

            impl StaticCrtParameter for [<FheUint $num_bits Parameters>] {}
        }
    };
}

macro_rules! static_int_type {
    // This rule generates the types specialization
    // as well as call the macros
    // that implement necessary traits for the ClientKey and ServerKey
    //
    // This is not meant to be used directly, instead see the other rules below
    (
        @impl_types_and_key_traits,
        $(#[$outer:meta])*
        $name:ident {
            num_bits: $num_bits:literal,
            keychain_member: $($member:ident).*,
        }
    ) => {
         paste! {
            #[doc = concat!("ClientKey for the [", stringify!($name), "] data type.")]
            pub(in crate::high_level_api::integers) type [<$name ClientKey>] = GenericIntegerClientKey<[<$name Parameters>]>;

            #[doc = concat!("PublicKey for the [", stringify!($name), "] data type.")]
            pub(in crate::high_level_api::integers) type [<$name PublicKey>] = GenericIntegerPublicKey<[<$name Parameters>]>;

            #[doc = concat!("CompressedPublicKey for the [", stringify!($name), "] data type.")]
            pub(in crate::high_level_api::integers) type [<$name CompressedPublicKey>] = GenericIntegerCompressedPublicKey<[<$name Parameters>]>;

            #[doc = concat!("ServerKey for the [", stringify!($name), "] data type.")]
            pub(in crate::high_level_api::integers) type [<$name ServerKey>] = GenericIntegerServerKey<[<$name Parameters>]>;

            #[doc = concat!("An unsigned integer type with", stringify!($num_bits), "bits")]
            $(#[$outer])*
            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type $name = GenericInteger<[<$name Parameters>]>;

            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<Compressed $name>] = CompressedGenericInteger<[<$name Parameters>]>;

            impl_ref_key_from_keychain!(
                for <[<$name Parameters>] as ParameterType>::Id {
                    key_type: [<$name ClientKey>],
                    keychain_member: $($member).*,
                    type_variant: crate::high_level_api::errors::Type::$name,
                }
            );

            impl_ref_key_from_public_keychain!(
                for <[<$name Parameters>] as ParameterType>::Id {
                    key_type: [<$name PublicKey>],
                    keychain_member: $($member).*,
                    type_variant: crate::high_level_api::errors::Type::$name,
                }
            );

            impl_ref_key_from_compressed_public_keychain!(
                for <[<$name Parameters>] as ParameterType>::Id {
                    key_type: [<$name CompressedPublicKey>],
                    keychain_member: $($member).*,
                    type_variant: crate::high_level_api::errors::Type::$name,
                }
            );

            impl_with_global_key!(
                for <[<$name Parameters>] as ParameterType>::Id {
                    key_type: [<$name ServerKey>],
                    keychain_member: $($member).*,
                    type_variant: crate::high_level_api::errors::Type::$name,
                }
            );
        }
    };

    // Defines a static integer type that uses
    // the `Radix` representation
    (
        $(#[$outer:meta])*
        {
            num_bits: $num_bits:literal,
            keychain_member: $($member:ident).*,
            parameters: Radix {
                big_block_parameters: $big_block_parameters:expr,
                small_block_parameters: $small_block_parameters:expr,
                num_block: $num_block:literal,
                wopbs_block_parameters: $wopbs_block_parameters:expr,
            },
        }
    ) => {
        define_static_integer_parameters!(
            Radix {
                num_bits: $num_bits,
                big_block_parameters: $big_block_parameters,
                small_block_parameters: $small_block_parameters,
                num_block: $num_block,
                wopbs_block_parameters: $wopbs_block_parameters,
            }
        );

        ::paste::paste!{
            static_int_type!(
                @impl_types_and_key_traits,
                $(#[$outer])*
                [<FheUint $num_bits>] {
                    num_bits: $num_bits,
                    keychain_member: $($member).*,
                }
            );
        }
    };

    // Defines a static integer type that uses
    // the `CRT` representation
    (
        $(#[$outer:meta])*
        {
            num_bits: $num_bits:literal,
            keychain_member: $($member:ident).*,
            parameters: Crt {
                block_parameters: $block_parameters:expr,
                moduli: $moduli:expr,
                wopbs_block_parameters: $wopbs_block_parameters:expr,
            },
        }
    ) => {
        define_static_integer_parameters!(
            Crt {
                num_bits: $num_bits,
                block_parameters: $block_parameters,
                moduli: $moduli,
                wopbs_block_parameters: $wopbs_block_parameters,
            }
        );

        ::paste::paste!{
            static_int_type!(
                @impl_types_and_key_traits,
                $(#[$outer])*
                [<FheUint $num_bits>] {
                    num_bits: $num_bits,
                    keychain_member: $($member).*,
                }
            );
        }
    };
}

impl<C> EvaluationIntegerKey<C> for crate::integer::ServerKey
where
    C: AsRef<crate::integer::ClientKey>,
{
    fn new(client_key: &C) -> Self {
        #[cfg(feature = "internal-keycache")]
        {
            KEY_CACHE
                .get_from_params(client_key.as_ref().parameters())
                .1
        }
        #[cfg(not(feature = "internal-keycache"))]
        {
            crate::integer::ServerKey::new(client_key)
        }
    }

    fn new_wopbs_key(
        client_key: &C,
        server_key: &Self,
        wopbs_block_parameters: crate::shortint::Parameters,
    ) -> WopbsKey {
        #[cfg(not(feature = "internal-keycache"))]
        {
            WopbsKey::new_wopbs_key(client_key.as_ref(), server_key, &wopbs_block_parameters)
        }
        #[cfg(feature = "internal-keycache")]
        {
            let _ = &server_key; // silence warning
            KEY_CACHE_WOPBS
                .get_from_params((client_key.as_ref().parameters(), wopbs_block_parameters))
        }
    }
}

static_int_type! {
    {
        num_bits: 8,
        keychain_member: integer_key.uint8_key,
        parameters: Radix {
            big_block_parameters: crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2,
            small_block_parameters: crate::shortint::parameters::PARAM_SMALL_MESSAGE_2_CARRY_2,
            num_block: 4,
            wopbs_block_parameters: crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2,
        },
    }
}

static_int_type! {
    {
        num_bits: 10,
        keychain_member: integer_key.uint10_key,
        parameters: Radix {
            big_block_parameters: crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2,
            small_block_parameters: crate::shortint::parameters::PARAM_SMALL_MESSAGE_2_CARRY_2,
            num_block: 5,
            wopbs_block_parameters: crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2,
        },
    }
}

static_int_type! {
    {
        num_bits: 12,
        keychain_member: integer_key.uint12_key,
        parameters: Radix {
            big_block_parameters: crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2,
            small_block_parameters: crate::shortint::parameters::PARAM_SMALL_MESSAGE_2_CARRY_2,
            num_block: 6,
            wopbs_block_parameters: crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2,
        },
    }
}

static_int_type! {
    {
        num_bits: 14,
        keychain_member: integer_key.uint14_key,
        parameters: Radix {
            big_block_parameters: crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2,
            small_block_parameters: crate::shortint::parameters::PARAM_SMALL_MESSAGE_2_CARRY_2,
            num_block: 7,
            wopbs_block_parameters: crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2,
        },
    }
}

static_int_type! {
    {
        num_bits: 16,
        keychain_member: integer_key.uint16_key,
        parameters: Radix {
            big_block_parameters: crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2,
            small_block_parameters: crate::shortint::parameters::PARAM_SMALL_MESSAGE_2_CARRY_2,
            num_block: 8,
            wopbs_block_parameters: crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2,
        },
    }
}

static_int_type! {
    {
        num_bits: 32,
        keychain_member: integer_key.uint32_key,
        parameters: Radix {
            big_block_parameters: crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2,
            small_block_parameters: crate::shortint::parameters::PARAM_SMALL_MESSAGE_2_CARRY_2,
            num_block: 32,
            wopbs_block_parameters: crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2,
        },
    }
}

static_int_type! {
    {
        num_bits: 64,
        keychain_member: integer_key.uint64_key,
        parameters: Radix {
            big_block_parameters: crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2,
            small_block_parameters: crate::shortint::parameters::PARAM_SMALL_MESSAGE_2_CARRY_2,
            num_block: 32,
            wopbs_block_parameters: crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2,
        },
    }
}

static_int_type! {
    {
        num_bits: 128,
        keychain_member: integer_key.uint128_key,
        parameters: Radix {
            big_block_parameters: crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2,
            small_block_parameters: crate::shortint::parameters::PARAM_SMALL_MESSAGE_2_CARRY_2,
            num_block: 64,
            wopbs_block_parameters: crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2,
        },
    }
}

static_int_type! {
    {
        num_bits: 256,
        keychain_member: integer_key.uint256_key,
        parameters: Radix {
            big_block_parameters: crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2,
            small_block_parameters: crate::shortint::parameters::PARAM_SMALL_MESSAGE_2_CARRY_2,
            num_block: 128,
            wopbs_block_parameters: crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2,
        },
    }
}

impl FheEncrypt<u8, ClientKey> for GenericInteger<FheUint8Parameters> {
    #[track_caller]
    fn encrypt(value: u8, key: &ClientKey) -> Self {
        let id = <FheUint8Parameters as ParameterType>::Id::default();
        let key = id.unwrapped_ref_key(key);
        let ciphertext = key.inner.encrypt(u64::from(value));
        Self::new(ciphertext, id)
    }
}

impl FheDecrypt<u8> for FheUint8 {
    #[track_caller]
    fn decrypt(&self, key: &ClientKey) -> u8 {
        let id = <FheUint8Parameters as ParameterType>::Id::default();
        let key = id.unwrapped_ref_key(key);
        let clear: u64 = key.inner.decrypt(&*self.ciphertext.borrow());
        clear as u8
    }
}

impl FheEncrypt<u16, ClientKey> for FheUint16 {
    #[track_caller]
    fn encrypt(value: u16, key: &ClientKey) -> Self {
        let id = <FheUint16Parameters as ParameterType>::Id::default();
        let key = id.unwrapped_ref_key(key);
        let ciphertext = key.inner.encrypt(u64::from(value));
        Self::new(ciphertext, id)
    }
}
