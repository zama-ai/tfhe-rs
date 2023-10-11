use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
use crate::errors::{UninitializedPublicKey, UnwrapResultExt};
use crate::high_level_api::integers::parameters::IntegerParameter;
use crate::high_level_api::integers::types::base::GenericInteger;
use crate::high_level_api::internal_traits::TypeIdentifier;
use crate::high_level_api::traits::FheTryEncrypt;
use crate::integer::ciphertext::CompactCiphertextList;
use crate::integer::parameters::{
    RadixCiphertextConformanceParams, RadixCompactCiphertextListConformanceParams,
};
use crate::named::Named;
use crate::CompactPublicKey;

#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GenericCompactInteger<P: IntegerParameter> {
    pub(in crate::high_level_api::integers) list: CompactCiphertextList,
    pub(in crate::high_level_api::integers) id: P::Id,
}

#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GenericCompactIntegerList<P: IntegerParameter> {
    pub(in crate::high_level_api::integers) list: CompactCiphertextList,
    pub(in crate::high_level_api::integers) id: P::Id,
}

impl<P> GenericCompactInteger<P>
where
    P: IntegerParameter,
{
    pub fn expand(&self) -> GenericInteger<P> {
        let ct = self.list.expand_one();
        GenericInteger::new(ct, self.id)
    }
}

impl<P> GenericCompactIntegerList<P>
where
    P: IntegerParameter,
{
    pub fn len(&self) -> usize {
        self.list.ciphertext_count()
    }

    pub fn expand(&self) -> Vec<GenericInteger<P>> {
        self.list
            .expand()
            .into_iter()
            .map(|ct| GenericInteger::new(ct, self.id))
            .collect::<Vec<_>>()
    }
}

impl<P, T> FheTryEncrypt<T, CompactPublicKey> for GenericCompactInteger<P>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let ciphertext = key
            .integer_key
            .try_encrypt_compact(&[value], P::num_blocks())
            .ok_or(UninitializedPublicKey(id.type_variant()))
            .unwrap_display();
        Ok(Self {
            list: ciphertext,
            id,
        })
    }
}

impl<'a, P, T> FheTryEncrypt<&'a [T], CompactPublicKey> for GenericCompactIntegerList<P>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(values: &'a [T], key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let ciphertext = key
            .integer_key
            .try_encrypt_compact(values, P::num_blocks())
            .ok_or(UninitializedPublicKey(id.type_variant()))
            .unwrap_display();
        Ok(Self {
            list: ciphertext,
            id,
        })
    }
}

impl<P: IntegerParameter> ParameterSetConformant for GenericCompactInteger<P> {
    type ParameterSet = RadixCiphertextConformanceParams;
    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        let lsc = ListSizeConstraint::exact_size(1);

        let params = params.to_ct_list_conformance_parameters(lsc);
        self.list.is_conformant(&params)
    }
}

impl<P: IntegerParameter> Named for GenericCompactInteger<P> {
    const NAME: &'static str = "high_level_api::GenericCompactInteger";
}

impl<P: IntegerParameter> Named for GenericCompactIntegerList<P> {
    const NAME: &'static str = "high_level_api::GenericCompactIntegerList";
}

impl<P: IntegerParameter> ParameterSetConformant for GenericCompactIntegerList<P> {
    type ParameterSet = RadixCompactCiphertextListConformanceParams;
    fn is_conformant(&self, params: &RadixCompactCiphertextListConformanceParams) -> bool {
        self.list.is_conformant(params)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::conformance::ParameterSetConformant;
    use crate::core_crypto::prelude::UnsignedInteger;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    use crate::shortint::{CiphertextModulus, PBSOrder};
    use crate::{
        generate_keys, set_server_key, CompactFheUint8, CompactFheUint8List, ConfigBuilder,
    };
    use rand::{thread_rng, Rng};

    type ParameterAccessor<Ct, T> = dyn Fn(&mut Ct) -> &mut T;

    type ParameterModifier<'a, Ct> = dyn Fn(&mut Ct) + 'a;

    fn change_parameters<Ct, T: UnsignedInteger>(
        func: &ParameterAccessor<Ct, T>,
    ) -> Vec<Box<ParameterModifier<'_, Ct>>> {
        vec![
            Box::new(|ct| *func(ct) = T::ZERO),
            Box::new(|ct| *func(ct) = func(ct).wrapping_add(T::ONE)),
            Box::new(|ct| *func(ct) = func(ct).wrapping_sub(T::ONE)),
        ]
    }

    #[test]
    fn test_invalid_generic_compact_integer() {
        type Ct = CompactFheUint8;

        let config = ConfigBuilder::all_disabled()
            .enable_default_integers()
            .build();

        let (client_key, _server_key) = generate_keys(config);

        let public_key = CompactPublicKey::new(&client_key);

        let ct = CompactFheUint8::try_encrypt(0, &public_key).unwrap();

        assert!(
            ct.is_conformant(&RadixCiphertextConformanceParams::from_pbs_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                4
            ))
        );

        let breaker_lists = vec![
            change_parameters(&|ct: &mut Ct| &mut ct.list.num_blocks_per_integer),
            change_parameters(&|ct: &mut Ct| &mut ct.list.ct_list.message_modulus.0),
            change_parameters(&|ct: &mut Ct| &mut ct.list.ct_list.carry_modulus.0),
            change_parameters(&|ct: &mut Ct| &mut ct.list.ct_list.degree.0),
            change_parameters(&|ct: &mut Ct| {
                &mut ct.list.ct_list.ct_list.get_mut_lwe_ciphertext_count().0
            }),
            change_parameters(&|ct: &mut Ct| &mut ct.list.ct_list.ct_list.get_mut_lwe_size().0),
        ];

        for breaker_list in breaker_lists {
            for breaker in breaker_list {
                let mut ct_clone = ct.clone();

                breaker(&mut ct_clone);

                assert!(!ct_clone.is_conformant(
                    &RadixCiphertextConformanceParams::from_pbs_parameters(
                        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                        4
                    )
                ));
            }
        }

        let breakers2: Vec<&ParameterModifier<'_, Ct>> = vec![
            &|ct: &mut Ct| ct.list.ct_list.pbs_order = PBSOrder::BootstrapKeyswitch,
            &|ct: &mut Ct| {
                *ct.list.ct_list.ct_list.get_mut_ciphertext_modulus() =
                    CiphertextModulus::try_new_power_of_2(1).unwrap();
            },
            &|ct: &mut Ct| {
                *ct.list.ct_list.ct_list.get_mut_ciphertext_modulus() =
                    CiphertextModulus::try_new(3).unwrap();
            },
            &|ct: &mut Ct| {
                ct.list.ct_list.ct_list.get_mut_container().pop();
            },
            &|ct: &mut Ct| ct.list.ct_list.ct_list.get_mut_container().push(0),
        ];

        for breaker in breakers2 {
            let mut ct_clone = ct.clone();

            breaker(&mut ct_clone);

            assert!(!ct_clone.is_conformant(
                &RadixCiphertextConformanceParams::from_pbs_parameters(
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                    4
                )
            ));
        }
    }

    #[test]
    fn test_invalid_generic_compact_integer_list() {
        type Ct = CompactFheUint8List;

        let config = ConfigBuilder::all_disabled()
            .enable_default_integers()
            .build();

        let (client_key, _server_key) = generate_keys(config);

        let public_key = CompactPublicKey::new(&client_key);

        let ct = Ct::try_encrypt(&[0, 1], &public_key).unwrap();

        let params = RadixCiphertextConformanceParams::from_pbs_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            4,
        )
        .to_ct_list_conformance_parameters(ListSizeConstraint::exact_size(2));

        assert!(ct.is_conformant(&params));

        let breaker_lists = vec![
            change_parameters(&|ct: &mut Ct| &mut ct.list.num_blocks_per_integer),
            change_parameters(&|ct: &mut Ct| &mut ct.list.ct_list.message_modulus.0),
            change_parameters(&|ct: &mut Ct| &mut ct.list.ct_list.carry_modulus.0),
            change_parameters(&|ct: &mut Ct| &mut ct.list.ct_list.degree.0),
            change_parameters(&|ct: &mut Ct| {
                &mut ct.list.ct_list.ct_list.get_mut_lwe_ciphertext_count().0
            }),
            change_parameters(&|ct: &mut Ct| &mut ct.list.ct_list.ct_list.get_mut_lwe_size().0),
        ];

        for breaker_list in breaker_lists {
            for breaker in breaker_list {
                let mut ct_clone = ct.clone();

                breaker(&mut ct_clone);

                assert!(!ct_clone.is_conformant(&params));
            }
        }

        let breakers2: Vec<&ParameterModifier<'_, Ct>> = vec![
            &|ct: &mut Ct| ct.list.ct_list.pbs_order = PBSOrder::BootstrapKeyswitch,
            &|ct: &mut Ct| {
                *ct.list.ct_list.ct_list.get_mut_ciphertext_modulus() =
                    CiphertextModulus::try_new_power_of_2(1).unwrap();
            },
            &|ct: &mut Ct| {
                *ct.list.ct_list.ct_list.get_mut_ciphertext_modulus() =
                    CiphertextModulus::try_new(3).unwrap();
            },
            &|ct: &mut Ct| {
                ct.list.ct_list.ct_list.get_mut_container().pop();
            },
            &|ct: &mut Ct| ct.list.ct_list.ct_list.get_mut_container().push(0),
        ];

        for breaker in breakers2 {
            let mut ct_clone = ct.clone();

            breaker(&mut ct_clone);

            assert!(!ct_clone.is_conformant(&params));
        }
    }

    #[test]
    fn test_valid_generic_compact_integer() {
        let config = ConfigBuilder::all_disabled()
            .enable_default_integers()
            .build();

        let (client_key, server_key) = generate_keys(config);

        let public_key = CompactPublicKey::new(&client_key);

        set_server_key(server_key);

        let ct = CompactFheUint8::try_encrypt(0, &public_key).unwrap();

        assert!(
            ct.is_conformant(&RadixCiphertextConformanceParams::from_pbs_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                4
            ))
        );

        let mut rng = thread_rng();

        for _ in 0..10 {
            let mut ct_clone = ct.clone();

            ct_clone
                .list
                .ct_list
                .ct_list
                .get_mut_container()
                .fill_with(|| rng.gen::<u64>());

            assert!(ct_clone.is_conformant(
                &RadixCiphertextConformanceParams::from_pbs_parameters(
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                    4
                )
            ));

            let mut ct_clone_expanded = ct_clone.expand();

            ct_clone_expanded += &ct_clone_expanded.clone();
        }
    }

    #[test]
    fn test_valid_generic_compact_integer_list() {
        let config = ConfigBuilder::all_disabled()
            .enable_default_integers()
            .build();

        let (client_key, server_key) = generate_keys(config);

        let public_key = CompactPublicKey::new(&client_key);

        set_server_key(server_key);

        let ct = CompactFheUint8List::try_encrypt(&[0, 1], &public_key).unwrap();

        let params = RadixCiphertextConformanceParams::from_pbs_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            4,
        )
        .to_ct_list_conformance_parameters(ListSizeConstraint::exact_size(2));

        assert!(ct.is_conformant(&params));

        let mut rng = thread_rng();

        for _ in 0..10 {
            let mut ct_clone = ct.clone();

            ct_clone
                .list
                .ct_list
                .ct_list
                .get_mut_container()
                .fill_with(|| rng.gen::<u64>());

            assert!(ct_clone.is_conformant(&params));

            let mut ct_clone_expanded = ct_clone.expand();

            // We check that this conformant random ciphertext can be used to do operations without
            // panicking
            for i in &mut ct_clone_expanded {
                *i += i.clone();
            }
        }
    }
}
