use crate::conformance::ParameterSetConformant;
use crate::high_level_api::integers::parameters::IntegerParameter;
use crate::high_level_api::integers::types::base::GenericInteger;
use crate::high_level_api::internal_traits::{EncryptionKey, TypeIdentifier};
use crate::high_level_api::traits::FheTryEncrypt;
use crate::high_level_api::ClientKey;
use crate::integer::parameters::RadixCiphertextConformanceParams;
use crate::named::Named;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CompressedGenericInteger<P>
where
    P: IntegerParameter,
{
    pub(in crate::high_level_api::integers) ciphertext: P::InnerCompressedCiphertext,
    pub(in crate::high_level_api::integers) id: P::Id,
}

impl<P: IntegerParameter> ParameterSetConformant for CompressedGenericInteger<P>
where
    P::InnerCompressedCiphertext:
        ParameterSetConformant<ParameterSet = RadixCiphertextConformanceParams>,
{
    type ParameterSet = RadixCiphertextConformanceParams;
    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        self.ciphertext.is_conformant(params)
    }
}

impl<P: IntegerParameter> Named for CompressedGenericInteger<P> {
    const NAME: &'static str = "high_level_api::CompressedGenericInteger";
}

impl<P> CompressedGenericInteger<P>
where
    P: IntegerParameter,
{
    pub(in crate::high_level_api::integers) fn new(
        inner: P::InnerCompressedCiphertext,
        id: P::Id,
    ) -> Self {
        Self {
            ciphertext: inner,
            id,
        }
    }
}

impl<P> CompressedGenericInteger<P>
where
    P: IntegerParameter,
    P::InnerCompressedCiphertext: Into<P::InnerCiphertext>,
{
    pub fn decompress(self) -> GenericInteger<P> {
        let inner = self.ciphertext.into();
        GenericInteger::new(inner, self.id)
    }
}

impl<P> From<CompressedGenericInteger<P>> for GenericInteger<P>
where
    P: IntegerParameter,
    P::InnerCompressedCiphertext: Into<P::InnerCiphertext>,
{
    fn from(value: CompressedGenericInteger<P>) -> Self {
        let inner = value.ciphertext.into();
        Self::new(inner, value.id)
    }
}

impl<P, T> FheTryEncrypt<T, ClientKey> for CompressedGenericInteger<P>
where
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
    crate::integer::ClientKey: EncryptionKey<(T, usize), P::InnerCompressedCiphertext>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let integer_client_key = &key.key.key;
        let inner = <crate::integer::ClientKey as EncryptionKey<_, _>>::encrypt(
            integer_client_key,
            (value, P::num_blocks()),
        );
        Ok(Self::new(inner, id))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::conformance::ParameterSetConformant;
    use crate::core_crypto::prelude::UnsignedInteger;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    use crate::shortint::CiphertextModulus;
    use crate::{generate_keys, set_server_key, CompressedFheUint8, ConfigBuilder};
    use rand::{thread_rng, Rng};

    type IndexedParameterAccessor<Ct, T> = dyn Fn(usize, &mut Ct) -> &mut T;

    type IndexedParameterModifier<'a, Ct> = dyn Fn(usize, &mut Ct) + 'a;

    fn change_parameters<Ct, T: UnsignedInteger>(
        func: &IndexedParameterAccessor<Ct, T>,
    ) -> [Box<IndexedParameterModifier<'_, Ct>>; 3] {
        [
            Box::new(|i, ct| *func(i, ct) = T::ZERO),
            Box::new(|i, ct| *func(i, ct) = func(i, ct).wrapping_add(T::ONE)),
            Box::new(|i, ct| *func(i, ct) = func(i, ct).wrapping_sub(T::ONE)),
        ]
    }

    #[test]
    fn test_invalid_generic_compressed_integer() {
        type Ct = CompressedFheUint8;

        let config = ConfigBuilder::default().build();

        let (client_key, _server_key) = generate_keys(config);

        let ct = CompressedFheUint8::try_encrypt(0_u64, &client_key).unwrap();

        assert!(
            ct.is_conformant(&RadixCiphertextConformanceParams::from_pbs_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                4
            ))
        );

        let breaker_lists = [
            change_parameters(&|i: usize, ct: &mut Ct| {
                &mut ct.ciphertext.blocks[i].ct.get_mut_lwe_size().0
            }),
            change_parameters(&|i: usize, ct: &mut Ct| {
                &mut ct.ciphertext.blocks[i].message_modulus.0
            }),
            change_parameters(&|i: usize, ct: &mut Ct| {
                &mut ct.ciphertext.blocks[i].carry_modulus.0
            }),
            change_parameters(&|i: usize, ct: &mut Ct| &mut ct.ciphertext.blocks[i].degree.0),
        ];

        for breaker_list in breaker_lists {
            for breaker in breaker_list {
                for i in 0..ct.ciphertext.blocks.len() {
                    let mut ct_clone = ct.clone();

                    breaker(i, &mut ct_clone);

                    assert!(!ct_clone.is_conformant(
                        &RadixCiphertextConformanceParams::from_pbs_parameters(
                            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                            4
                        )
                    ));
                }
            }
        }

        let breakers2: Vec<&IndexedParameterModifier<'_, Ct>> = vec![
            &|i, ct: &mut Ct| {
                *ct.ciphertext.blocks[i].ct.get_mut_ciphertext_modulus() =
                    CiphertextModulus::try_new_power_of_2(1).unwrap();
            },
            &|i, ct: &mut Ct| {
                *ct.ciphertext.blocks[i].ct.get_mut_ciphertext_modulus() =
                    CiphertextModulus::try_new(3).unwrap();
            },
            &|_i, ct: &mut Ct| {
                ct.ciphertext.blocks.pop();
            },
            &|i, ct: &mut Ct| {
                let value = ct.ciphertext.blocks[i].clone();
                ct.ciphertext.blocks.push(value);
            },
        ];

        for breaker in breakers2 {
            for i in 0..ct.ciphertext.blocks.len() {
                let mut ct_clone = ct.clone();

                breaker(i, &mut ct_clone);

                assert!(!ct_clone.is_conformant(
                    &RadixCiphertextConformanceParams::from_pbs_parameters(
                        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                        4
                    )
                ));
            }
        }
    }

    #[test]
    fn test_valid_generic_compressed_integer() {
        let config = ConfigBuilder::default().build();

        let (client_key, server_key) = generate_keys(config);

        set_server_key(server_key);

        let ct = CompressedFheUint8::try_encrypt(0_u64, &client_key).unwrap();

        assert!(
            ct.is_conformant(&RadixCiphertextConformanceParams::from_pbs_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                4
            ))
        );

        let mut rng = thread_rng();

        let num_blocks = ct.ciphertext.blocks.len();

        for _ in 0..10 {
            let mut ct_clone = ct.clone();

            for i in 0..num_blocks {
                *ct_clone.ciphertext.blocks[i].ct.get_mut_data() = rng.gen::<u64>();

                ct_clone.ciphertext.blocks[i]
                    .ct
                    .get_mut_compressed_seed()
                    .seed
                    .0 = rng.gen::<u128>();
            }
            assert!(ct_clone.is_conformant(
                &RadixCiphertextConformanceParams::from_pbs_parameters(
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                    4
                )
            ));

            let mut ct_clone_decompressed = ct_clone.decompress();

            ct_clone_decompressed += &ct_clone_decompressed.clone();
        }
    }
}
