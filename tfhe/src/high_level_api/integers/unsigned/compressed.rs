use std::marker::PhantomData;

use tfhe_versionable::Versionize;

use crate::backward_compatibility::integers::{
    CompressedFheUintVersions, CompressedRadixCiphertextVersions,
};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::UnsignedNumeric;
use crate::high_level_api::integers::unsigned::base::{FheUint, FheUintId};
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::traits::{FheTryEncrypt, Tagged};
use crate::high_level_api::{global_state, ClientKey};
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::{
    CompressedModulusSwitchedRadixCiphertext,
    CompressedModulusSwitchedRadixCiphertextConformanceParams,
    CompressedRadixCiphertext as IntegerCompressedRadixCiphertext,
};
use crate::named::Named;
use crate::shortint::AtomicPatternParameters;
use crate::{ServerKey, Tag};

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
/// ```rust
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
#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedFheUintVersions)]
pub struct CompressedFheUint<Id>
where
    Id: FheUintId,
{
    pub(in crate::high_level_api::integers) ciphertext: CompressedRadixCiphertext,
    pub(in crate::high_level_api::integers) id: Id,
    pub(crate) tag: Tag,
}

impl<Id> Tagged for CompressedFheUint<Id>
where
    Id: FheUintId,
{
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl<Id> CompressedFheUint<Id>
where
    Id: FheUintId,
{
    pub(in crate::high_level_api) fn new(inner: CompressedRadixCiphertext, tag: Tag) -> Self {
        Self {
            ciphertext: inner,
            id: Id::default(),
            tag,
        }
    }

    pub fn into_raw_parts(self) -> (CompressedRadixCiphertext, Id, Tag) {
        let Self {
            ciphertext,
            id,
            tag,
        } = self;
        (ciphertext, id, tag)
    }

    pub fn from_raw_parts(ciphertext: CompressedRadixCiphertext, id: Id, tag: Tag) -> Self {
        Self {
            ciphertext,
            id,
            tag,
        }
    }
}

impl<Id> CompressedFheUint<Id>
where
    Id: FheUintId,
{
    /// Decompress to a [FheUint]
    ///
    /// See [CompressedFheUint] example.
    pub fn decompress(&self) -> FheUint<Id> {
        let inner = match &self.ciphertext {
            CompressedRadixCiphertext::Seeded(ct) => ct.decompress(),
            CompressedRadixCiphertext::ModulusSwitched(ct) => {
                global_state::with_internal_keys(|keys| match keys {
                    InternalServerKey::Cpu(cpu_key) => {
                        cpu_key.pbs_key().decompress_parallelized(ct)
                    }
                    #[cfg(feature = "gpu")]
                    InternalServerKey::Cuda(_) => {
                        panic!("decompress() on FheUint is not supported on GPU, use a CompressedCiphertextList instead");
                    }
                    #[cfg(feature = "hpu")]
                    InternalServerKey::Hpu(_) => {
                        panic!("decompress() on FheUint is not supported on HPU devices");
                    }
                })
            }
        };

        let mut ciphertext =
            FheUint::new(inner, self.tag.clone(), ReRandomizationMetadata::default());

        ciphertext.move_to_device_of_server_key_if_set();
        ciphertext
    }
}

impl<Id, T> FheTryEncrypt<T, ClientKey> for CompressedFheUint<Id>
where
    Id: FheUintId,
    T: DecomposableInto<u64> + UnsignedNumeric,
{
    type Error = crate::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let inner = key
            .key
            .key
            .encrypt_radix_compressed(value, Id::num_blocks(key.message_modulus()));
        Ok(Self::new(
            CompressedRadixCiphertext::Seeded(inner),
            key.tag.clone(),
        ))
    }
}

#[derive(Copy, Clone)]
pub struct CompressedFheUintConformanceParams<Id: FheUintId> {
    pub(crate) params: CompressedRadixCiphertextConformanceParams,
    pub(crate) id: PhantomData<Id>,
}

impl<Id: FheUintId, P: Into<AtomicPatternParameters>> From<P>
    for CompressedFheUintConformanceParams<Id>
{
    fn from(params: P) -> Self {
        let params = params.into();
        Self {
            params: CompressedRadixCiphertextConformanceParams(
                CompressedModulusSwitchedRadixCiphertextConformanceParams {
                    shortint_params: params.to_compressed_modswitched_conformance_param(),
                    num_blocks_per_integer: Id::num_blocks(params.message_modulus()),
                },
            ),
            id: PhantomData,
        }
    }
}

impl<Id: FheUintId> From<&ServerKey> for CompressedFheUintConformanceParams<Id> {
    fn from(sk: &ServerKey) -> Self {
        Self {
            params: CompressedRadixCiphertextConformanceParams(
                CompressedModulusSwitchedRadixCiphertextConformanceParams {
                    shortint_params: sk
                        .key
                        .pbs_key()
                        .key
                        .compressed_modswitched_conformance_params(),
                    num_blocks_per_integer: Id::num_blocks(sk.key.pbs_key().message_modulus()),
                },
            ),
            id: PhantomData,
        }
    }
}

impl<Id: FheUintId> ParameterSetConformant for CompressedFheUint<Id> {
    type ParameterSet = CompressedFheUintConformanceParams<Id>;

    fn is_conformant(&self, params: &CompressedFheUintConformanceParams<Id>) -> bool {
        let Self {
            ciphertext,
            id: _,
            tag: _,
        } = self;

        ciphertext.is_conformant(&params.params)
    }
}

impl<Id: FheUintId> Named for CompressedFheUint<Id> {
    const NAME: &'static str = "high_level_api::CompressedFheUint";
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedRadixCiphertextVersions)]
pub enum CompressedRadixCiphertext {
    Seeded(IntegerCompressedRadixCiphertext),
    ModulusSwitched(CompressedModulusSwitchedRadixCiphertext),
}

#[derive(Copy, Clone)]
pub struct CompressedRadixCiphertextConformanceParams(
    pub(crate) CompressedModulusSwitchedRadixCiphertextConformanceParams,
);

impl ParameterSetConformant for CompressedRadixCiphertext {
    type ParameterSet = CompressedRadixCiphertextConformanceParams;
    fn is_conformant(&self, params: &CompressedRadixCiphertextConformanceParams) -> bool {
        match self {
            Self::Seeded(ct) => ct.is_conformant(&params.0.into()),
            Self::ModulusSwitched(ct) => ct.is_conformant(&params.0),
        }
    }
}

impl<Id> FheUint<Id>
where
    Id: FheUintId,
{
    pub fn compress(&self) -> CompressedFheUint<Id> {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let ciphertext = CompressedRadixCiphertext::ModulusSwitched(
                    cpu_key
                        .pbs_key()
                        .switch_modulus_and_compress_parallelized(&self.ciphertext.on_cpu()),
                );
                CompressedFheUint::new(ciphertext, self.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("compress() on FheUint is not supported on GPU, use a CompressedCiphertextList instead");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("compress() on FheUint is not supported on HPU devices");
            }
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core_crypto::prelude::UnsignedInteger;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use crate::shortint::{CiphertextModulus, CompressedCiphertext};
    use crate::{generate_keys, set_server_key, CompressedFheUint8, ConfigBuilder};
    use rand::{thread_rng, Rng};

    impl<Id> CompressedFheUint<Id>
    where
        Id: FheUintId,
    {
        fn seeded_blocks(&self) -> &Vec<CompressedCiphertext> {
            match &self.ciphertext {
                CompressedRadixCiphertext::Seeded(ciphertext) => &ciphertext.blocks,
                CompressedRadixCiphertext::ModulusSwitched(_) => {
                    panic!("Accessor does not support ModulusSwitched variant")
                }
            }
        }
        fn seeded_blocks_mut(&mut self) -> &mut Vec<CompressedCiphertext> {
            match &mut self.ciphertext {
                CompressedRadixCiphertext::Seeded(ciphertext) => &mut ciphertext.blocks,
                CompressedRadixCiphertext::ModulusSwitched(_) => {
                    panic!("Accessor does not support ModulusSwitched variant")
                }
            }
        }
    }

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

        assert!(ct.is_conformant(&CompressedFheUintConformanceParams::from(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
        )));

        let breaker_lists = [
            change_parameters(&|i: usize, ct: &mut Ct| {
                &mut ct.seeded_blocks_mut()[i].ct.get_mut_lwe_size().0
            }),
            change_parameters(&|i: usize, ct: &mut Ct| {
                &mut ct.seeded_blocks_mut()[i].message_modulus.0
            }),
            change_parameters(&|i: usize, ct: &mut Ct| {
                &mut ct.seeded_blocks_mut()[i].carry_modulus.0
            }),
            change_parameters(&|i: usize, ct: &mut Ct| ct.seeded_blocks_mut()[i].degree.as_mut()),
        ];

        for breaker_list in breaker_lists {
            for breaker in breaker_list {
                for i in 0..ct.seeded_blocks().len() {
                    let mut ct_clone = ct.clone();

                    breaker(i, &mut ct_clone);

                    assert!(
                        !ct_clone.is_conformant(&CompressedFheUintConformanceParams::from(
                            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                        ))
                    );
                }
            }
        }

        let breakers2: Vec<&IndexedParameterModifier<'_, Ct>> = vec![
            &|i, ct: &mut Ct| {
                *ct.seeded_blocks_mut()[i].ct.get_mut_ciphertext_modulus() =
                    CiphertextModulus::try_new_power_of_2(1).unwrap();
            },
            &|i, ct: &mut Ct| {
                *ct.seeded_blocks_mut()[i].ct.get_mut_ciphertext_modulus() =
                    CiphertextModulus::try_new(3).unwrap();
            },
            &|_i, ct: &mut Ct| {
                ct.seeded_blocks_mut().pop();
            },
            &|i, ct: &mut Ct| {
                let value = ct.seeded_blocks_mut()[i].clone();
                ct.seeded_blocks_mut().push(value);
            },
        ];

        for breaker in breakers2 {
            for i in 0..ct.seeded_blocks().len() {
                let mut ct_clone = ct.clone();

                breaker(i, &mut ct_clone);

                assert!(
                    !ct_clone.is_conformant(&CompressedFheUintConformanceParams::from(
                        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                    ))
                );
            }
        }
    }

    #[test]
    fn test_valid_generic_compressed_integer() {
        let config = ConfigBuilder::default().build();

        let (client_key, server_key) = generate_keys(config);

        set_server_key(server_key);

        let ct = CompressedFheUint8::try_encrypt(0_u64, &client_key).unwrap();

        assert!(ct.is_conformant(&CompressedFheUintConformanceParams::from(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
        )));

        let mut rng = thread_rng();

        let num_blocks = ct.seeded_blocks().len();

        for _ in 0..10 {
            let mut ct_clone = ct.clone();

            for i in 0..num_blocks {
                *ct_clone.seeded_blocks_mut()[i].ct.get_mut_data() = rng.gen::<u64>();

                if let tfhe_csprng::seeders::SeedKind::Ctr(seed) = &mut ct_clone.seeded_blocks_mut()
                    [i]
                    .ct
                    .get_mut_compressed_seed()
                    .inner
                    .seed
                {
                    seed.0 = rng.gen::<u128>();
                }
            }
            assert!(
                ct_clone.is_conformant(&CompressedFheUintConformanceParams::from(
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                ))
            );

            let mut ct_clone_decompressed = ct_clone.decompress();

            ct_clone_decompressed += &ct_clone_decompressed.clone();
        }
    }
}
