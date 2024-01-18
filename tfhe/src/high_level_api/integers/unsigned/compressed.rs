use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::UnsignedNumeric;
use crate::high_level_api::integers::unsigned::base::{FheUint, FheUintId};
use crate::high_level_api::traits::FheTryEncrypt;
use crate::high_level_api::ClientKey;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::CompressedRadixCiphertext;
use crate::integer::parameters::RadixCiphertextConformanceParams;
use crate::named::Named;

/// Compressed [FheUint]
///
/// Meant to save in storage space / transfer.
///
/// - A Compressed type must be decompressed using [decompress](Self::decompress) before it can be
///   used.
/// - It is not possible to compress an existing [FheUint]. compression can only be achieved at
///   encryption time by a [ClientKey]
///
/// # Example
///
/// ```
/// use tfhe::prelude::*;
/// use tfhe::{generate_keys, CompressedFheUint32, ConfigBuilder};
///
/// let (client_key, _) = generate_keys(ConfigBuilder::default());
/// let compressed = CompressedFheUint32::encrypt(u32::MAX, &client_key);
///
/// let decompressed = compressed.decompress();
/// let decrypted: u32 = decompressed.decrypt(&client_key);
/// assert_eq!(decrypted, u32::MAX);
/// ```
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CompressedFheUint<Id>
where
    Id: FheUintId,
{
    pub(in crate::high_level_api::integers) ciphertext: CompressedRadixCiphertext,
    pub(in crate::high_level_api::integers) id: Id,
}

impl<Id> CompressedFheUint<Id>
where
    Id: FheUintId,
{
    pub(in crate::high_level_api::integers) fn new(inner: CompressedRadixCiphertext) -> Self {
        Self {
            ciphertext: inner,
            id: Id::default(),
        }
    }

    pub fn into_raw_parts(self) -> (CompressedRadixCiphertext, Id) {
        let Self { ciphertext, id } = self;
        (ciphertext, id)
    }

    pub fn from_raw_parts(ciphertext: CompressedRadixCiphertext, id: Id) -> Self {
        Self { ciphertext, id }
    }
}

impl<Id> CompressedFheUint<Id>
where
    Id: FheUintId,
{
    /// Decompress to a [FheUint]
    ///
    /// See [CompressedFheUint] example.
    pub fn decompress(self) -> FheUint<Id> {
        let inner: crate::integer::RadixCiphertext = self.ciphertext.into();
        let mut ciphertext = FheUint::new(inner);
        ciphertext.move_to_device_of_server_key_if_set();
        ciphertext
    }
}

impl<Id, T> FheTryEncrypt<T, ClientKey> for CompressedFheUint<Id>
where
    Id: FheUintId,
    T: DecomposableInto<u64> + UnsignedNumeric,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let inner = key
            .key
            .key
            .encrypt_radix_compressed(value, Id::num_blocks(key.message_modulus()));
        Ok(Self::new(inner))
    }
}

impl<Id: FheUintId> ParameterSetConformant for CompressedFheUint<Id> {
    type ParameterSet = RadixCiphertextConformanceParams;
    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        self.ciphertext.is_conformant(params)
    }
}

impl<Id: FheUintId> Named for CompressedFheUint<Id> {
    const NAME: &'static str = "high_level_api::CompressedFheUint";
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
            change_parameters(&|i: usize, ct: &mut Ct| ct.ciphertext.blocks[i].degree.as_mut()),
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
