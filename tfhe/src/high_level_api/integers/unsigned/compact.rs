use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
use crate::high_level_api::integers::unsigned::base::{
    FheUint, FheUintConformanceParams, FheUintId,
};
use crate::high_level_api::traits::FheTryEncrypt;
use crate::integer::ciphertext::CompactCiphertextList;
use crate::integer::parameters::RadixCompactCiphertextListConformanceParams;
use crate::named::Named;
use crate::shortint::PBSParameters;
use crate::{CompactPublicKey, ServerKey};
use std::marker::PhantomData;

/// Compact [FheUint]
///
/// Meant to save in storage space / transfer.
///
/// - A Compact type must be expanded using [expand](Self::expand) before it can be used.
/// - It is not possible to 'compact' an existing [FheUint]. Compacting can only be achieved at
///   encryption time by a [CompactPublicKey]
///
/// # Example
///
/// ```rust
/// use tfhe::prelude::*;
/// use tfhe::{generate_keys, CompactFheUint32, CompactPublicKey, ConfigBuilder, FheUint32};
///
/// let (client_key, _) = generate_keys(ConfigBuilder::default());
/// let compact_public_key = CompactPublicKey::try_new(&client_key).unwrap();
///
/// let compact = CompactFheUint32::encrypt(u32::MAX, &compact_public_key);
///
/// let ciphertext = compact.expand();
/// let decrypted: u32 = ciphertext.decrypt(&client_key);
/// assert_eq!(decrypted, u32::MAX);
/// ```
#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct CompactFheUint<Id: FheUintId> {
    pub(in crate::high_level_api::integers) list: CompactCiphertextList,
    pub(in crate::high_level_api::integers) id: Id,
}

impl<Id> CompactFheUint<Id>
where
    Id: FheUintId,
{
    /// Expand to a [FheUint]
    ///
    /// See [CompactFheUint] example.
    pub fn expand(&self) -> FheUint<Id> {
        let ct: crate::integer::RadixCiphertext = self.list.expand_one();
        let mut ct = FheUint::new(ct);
        ct.move_to_device_of_server_key_if_set();
        ct
    }

    pub fn into_raw_parts(self) -> (CompactCiphertextList, Id) {
        let Self { list, id } = self;
        (list, id)
    }

    pub fn from_raw_parts(list: CompactCiphertextList, id: Id) -> Self {
        Self { list, id }
    }
}

impl<Id, T> FheTryEncrypt<T, CompactPublicKey> for CompactFheUint<Id>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    Id: FheUintId,
{
    type Error = crate::Error;

    fn try_encrypt(value: T, key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let ciphertext = key
            .key
            .try_encrypt_compact(&[value], Id::num_blocks(key.message_modulus()));
        Ok(Self {
            list: ciphertext,
            id: Id::default(),
        })
    }
}

impl<Id: FheUintId> Named for CompactFheUint<Id> {
    const NAME: &'static str = "high_level_api::CompactFheUint";
}

impl<Id: FheUintId> ParameterSetConformant for CompactFheUint<Id> {
    type ParameterSet = FheUintConformanceParams<Id>;

    fn is_conformant(&self, params: &FheUintConformanceParams<Id>) -> bool {
        let params = params
            .params
            .to_ct_list_conformance_parameters(ListSizeConstraint::exact_size(1));
        self.list.is_conformant(&params)
    }
}

/// Compact list of [FheUint]
///
/// Meant to save in storage space / transfer.
///
/// - A Compact type must be expanded using [expand](Self::expand) before it can be used.
/// - It is not possible to 'compact' an existing [FheUint]. Compacting can only be achieved at
///   encryption time by a [CompactPublicKey]
///
/// # Example
///
/// ```rust
/// use tfhe::prelude::*;
/// use tfhe::{generate_keys, CompactFheUint32List, CompactPublicKey, ConfigBuilder, FheUint32};
///
/// let (client_key, _) = generate_keys(ConfigBuilder::default());
/// let compact_public_key = CompactPublicKey::try_new(&client_key).unwrap();
///
/// let clears = vec![u32::MAX, 0, 1];
/// let compact = CompactFheUint32List::encrypt(&clears, &compact_public_key);
/// assert_eq!(compact.len(), clears.len());
///
/// let ciphertexts = compact.expand();
/// let decrypted: Vec<u32> = ciphertexts
///     .into_iter()
///     .map(|ciphertext| ciphertext.decrypt(&client_key))
///     .collect();
/// assert_eq!(decrypted, clears);
/// ```
#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct CompactFheUintList<Id: FheUintId> {
    pub(in crate::high_level_api::integers) list: CompactCiphertextList,
    pub(in crate::high_level_api::integers) id: Id,
}

impl<Id> CompactFheUintList<Id>
where
    Id: FheUintId,
{
    /// Returns the number of element in the compact list
    pub fn len(&self) -> usize {
        self.list.ciphertext_count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn into_raw_parts(self) -> (CompactCiphertextList, Id) {
        let Self { list, id } = self;
        (list, id)
    }

    pub fn from_raw_parts(list: CompactCiphertextList, id: Id) -> Self {
        Self { list, id }
    }

    /// Expand to a Vec<[FheUint]>
    ///
    /// See [CompactFheUintList] example.
    pub fn expand(&self) -> Vec<FheUint<Id>> {
        self.list
            .expand()
            .into_iter()
            .map(|ct: crate::integer::RadixCiphertext| {
                let mut ct = FheUint::new(ct);
                ct.move_to_device_of_server_key_if_set();
                ct
            })
            .collect::<Vec<_>>()
    }
}

impl<'a, Id, T> FheTryEncrypt<&'a [T], CompactPublicKey> for CompactFheUintList<Id>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    Id: FheUintId,
{
    type Error = crate::Error;

    fn try_encrypt(values: &'a [T], key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let ciphertext = key
            .key
            .try_encrypt_compact(values, Id::num_blocks(key.message_modulus()));
        Ok(Self {
            list: ciphertext,
            id: Id::default(),
        })
    }
}

impl<Id: FheUintId> Named for CompactFheUintList<Id> {
    const NAME: &'static str = "high_level_api::CompactFheUintList";
}

pub struct CompactFheUintListConformanceParams<Id: FheUintId> {
    params: RadixCompactCiphertextListConformanceParams,
    _id: PhantomData<Id>,
}

impl<Id: FheUintId, P: Into<PBSParameters>> From<(P, ListSizeConstraint)>
    for CompactFheUintListConformanceParams<Id>
{
    fn from((params, len_constraint): (P, ListSizeConstraint)) -> Self {
        let params = params.into();
        let parameter_set = RadixCompactCiphertextListConformanceParams {
            shortint_params: params.to_shortint_conformance_param(),
            num_blocks_per_integer: Id::num_blocks(params.message_modulus()),
            num_integers_constraint: len_constraint,
        };

        Self {
            params: parameter_set,
            _id: PhantomData,
        }
    }
}

impl<Id: FheUintId> From<(&ServerKey, ListSizeConstraint)>
    for CompactFheUintListConformanceParams<Id>
{
    fn from((sk, len_constraint): (&ServerKey, ListSizeConstraint)) -> Self {
        Self {
            params: RadixCompactCiphertextListConformanceParams {
                shortint_params: sk.key.pbs_key().key.conformance_params(),
                num_blocks_per_integer: Id::num_blocks(sk.key.pbs_key().message_modulus()),
                num_integers_constraint: len_constraint,
            },
            _id: PhantomData,
        }
    }
}

impl<Id: FheUintId> ParameterSetConformant for CompactFheUintList<Id> {
    type ParameterSet = CompactFheUintListConformanceParams<Id>;

    fn is_conformant(&self, params: &CompactFheUintListConformanceParams<Id>) -> bool {
        self.list.is_conformant(&params.params)
    }
}

#[cfg(test)]
mod test {
    use super::*;
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
    ) -> [Box<ParameterModifier<'_, Ct>>; 3] {
        [
            Box::new(|ct| *func(ct) = T::ZERO),
            Box::new(|ct| *func(ct) = func(ct).wrapping_add(T::ONE)),
            Box::new(|ct| *func(ct) = func(ct).wrapping_sub(T::ONE)),
        ]
    }

    #[test]
    fn test_invalid_generic_compact_integer() {
        type Ct = CompactFheUint8;

        let config = ConfigBuilder::default().build();

        let (client_key, _server_key) = generate_keys(config);

        let public_key = CompactPublicKey::new(&client_key);

        let ct = CompactFheUint8::try_encrypt(0, &public_key).unwrap();

        assert!(ct.is_conformant(&FheUintConformanceParams::from(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS
        )));

        let breaker_lists = [
            change_parameters(&|ct: &mut Ct| &mut ct.list.num_blocks_per_integer),
            change_parameters(&|ct: &mut Ct| &mut ct.list.ct_list.message_modulus.0),
            change_parameters(&|ct: &mut Ct| &mut ct.list.ct_list.carry_modulus.0),
            change_parameters(&|ct: &mut Ct| ct.list.ct_list.degree.as_mut()),
            change_parameters(&|ct: &mut Ct| {
                &mut ct.list.ct_list.ct_list.get_mut_lwe_ciphertext_count().0
            }),
            change_parameters(&|ct: &mut Ct| &mut ct.list.ct_list.ct_list.get_mut_lwe_size().0),
        ];

        for breaker_list in breaker_lists {
            for breaker in breaker_list {
                let mut ct_clone = ct.clone();

                breaker(&mut ct_clone);

                assert!(ct.is_conformant(&FheUintConformanceParams::from(
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS
                )));
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

            assert!(ct.is_conformant(&FheUintConformanceParams::from(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS
            )));
        }
    }

    #[test]
    fn test_invalid_generic_compact_integer_list() {
        type Ct = CompactFheUint8List;

        let config = ConfigBuilder::default().build();

        let (client_key, _server_key) = generate_keys(config);

        let public_key = CompactPublicKey::new(&client_key);

        let ct = Ct::try_encrypt(&[0, 1], &public_key).unwrap();

        let params = CompactFheUintListConformanceParams::from((
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            ListSizeConstraint::exact_size(2),
        ));

        assert!(ct.is_conformant(&params));

        let breaker_lists = [
            change_parameters(&|ct: &mut Ct| &mut ct.list.num_blocks_per_integer),
            change_parameters(&|ct: &mut Ct| &mut ct.list.ct_list.message_modulus.0),
            change_parameters(&|ct: &mut Ct| &mut ct.list.ct_list.carry_modulus.0),
            change_parameters(&|ct: &mut Ct| ct.list.ct_list.degree.as_mut()),
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
        let config = ConfigBuilder::default().build();

        let (client_key, server_key) = generate_keys(config);

        let public_key = CompactPublicKey::new(&client_key);

        set_server_key(server_key);

        let ct = CompactFheUint8::try_encrypt(0, &public_key).unwrap();

        assert!(ct.is_conformant(&FheUintConformanceParams::from(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS
        )));

        let mut rng = thread_rng();

        for _ in 0..10 {
            let mut ct_clone = ct.clone();

            ct_clone
                .list
                .ct_list
                .ct_list
                .get_mut_container()
                .fill_with(|| rng.gen::<u64>());

            assert!(ct.is_conformant(&FheUintConformanceParams::from(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS
            )));

            let mut ct_clone_expanded = ct_clone.expand();

            ct_clone_expanded += &ct_clone_expanded.clone();
        }
    }

    #[test]
    fn test_valid_generic_compact_integer_list() {
        let config = ConfigBuilder::default().build();

        let (client_key, server_key) = generate_keys(config);

        let public_key = CompactPublicKey::new(&client_key);

        set_server_key(server_key);

        let ct = CompactFheUint8List::try_encrypt(&[0, 1], &public_key).unwrap();

        let params = CompactFheUintListConformanceParams::from((
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            ListSizeConstraint::exact_size(2),
        ));

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
