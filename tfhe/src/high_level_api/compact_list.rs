use tfhe_versionable::Versionize;

use crate::backward_compatibility::compact_list::CompactCiphertextListVersions;
#[cfg(feature = "zk-pok")]
use crate::backward_compatibility::compact_list::ProvenCompactCiphertextListVersions;
use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
use crate::core_crypto::commons::math::random::{Deserialize, Serialize};
use crate::core_crypto::prelude::Numeric;
use crate::high_level_api::global_state;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::Tagged;
use crate::integer::ciphertext::{DataKind, Expandable};
use crate::integer::encryption::create_clear_radix_block_iterator;
use crate::integer::parameters::{
    CompactCiphertextListConformanceParams, IntegerCompactCiphertextListExpansionMode,
};
use crate::named::Named;
use crate::prelude::CiphertextList;
use crate::shortint::{Ciphertext, MessageModulus};
#[cfg(feature = "zk-pok")]
pub use zk::ProvenCompactCiphertextList;

use crate::integer::block_decomposition::DecomposableInto;
#[cfg(feature = "zk-pok")]
use crate::zk::{CompactPkeCrs, ZkComputeLoad};
use crate::{CompactPublicKey, SerializedKind, Tag};

#[cfg(feature = "strings")]
use super::ClearString;
use super::HlExpandable;

impl crate::FheTypes {
    pub(crate) fn from_data_kind(
        data_kind: DataKind,
        message_modulus: MessageModulus,
    ) -> Option<Self> {
        Some(match data_kind {
            DataKind::Unsigned(n) => {
                let num_bits_per_block = message_modulus.0.ilog2() as usize;
                let num_bits = n * num_bits_per_block;
                match num_bits {
                    2 => Self::Uint2,
                    4 => Self::Uint4,
                    6 => Self::Uint6,
                    8 => Self::Uint8,
                    10 => Self::Uint10,
                    12 => Self::Uint12,
                    14 => Self::Uint14,
                    16 => Self::Uint16,
                    32 => Self::Uint32,
                    64 => Self::Uint64,
                    128 => Self::Uint128,
                    160 => Self::Uint160,
                    256 => Self::Uint256,
                    512 => Self::Uint512,
                    1024 => Self::Uint1024,
                    2048 => Self::Uint2048,
                    _ => return None,
                }
            }
            DataKind::Signed(n) => {
                let num_bits_per_block = message_modulus.0.ilog2() as usize;
                let num_bits = n * num_bits_per_block;
                match num_bits {
                    2 => Self::Int2,
                    4 => Self::Int4,
                    6 => Self::Int6,
                    8 => Self::Int8,
                    10 => Self::Int10,
                    12 => Self::Int12,
                    14 => Self::Int14,
                    16 => Self::Int16,
                    32 => Self::Int32,
                    64 => Self::Int64,
                    128 => Self::Int128,
                    160 => Self::Int160,
                    256 => Self::Int256,
                    _ => return None,
                }
            }
            DataKind::Boolean => Self::Bool,
            DataKind::String { .. } => return None,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(CompactCiphertextListVersions)]
pub struct CompactCiphertextList {
    pub(crate) ct_list: crate::shortint::ciphertext::CompactCiphertextList,
    // Integers stored can have a heterogeneous number of blocks and signedness
    // We store this info to safeguard the expansion
    pub(crate) info: Vec<SerializedKind>,
    pub(crate) tag: Tag,
}

impl Named for CompactCiphertextList {
    const NAME: &'static str = "high_level_api::CompactCiphertextList";
}

impl CompactCiphertextList {
    pub fn builder(pk: &CompactPublicKey) -> CompactCiphertextListBuilder {
        CompactCiphertextListBuilder::new(pk)
    }

    pub fn len(&self) -> usize {
        self.info.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes> {
        self.info
            .get(index)
            .and_then(|&kind| crate::FheTypes::try_from(kind).ok())
    }

    pub fn expand_with_key(
        &self,
        sks: &crate::ServerKey,
    ) -> crate::Result<CompactCiphertextListExpander> {
        println!("LOL {}", self.to_integer_compact().is_packed());
        println!("{:?} vs {:?}", self.info, self.to_integer_compact().info);
        self.to_integer_compact()
            .expand(sks.integer_compact_ciphertext_list_expansion_mode())
            .map(|inner| CompactCiphertextListExpander {
                inner,
                info: self.info.clone(),
                tag: self.tag.clone(),
            })
    }

    pub fn expand(&self) -> crate::Result<CompactCiphertextListExpander> {
        let integer_list = self.to_integer_compact();
        // For WASM
        if !integer_list.is_packed() && !integer_list.needs_casting() {
            // No ServerKey required, short-circuit to avoid the global state call
            return Ok(CompactCiphertextListExpander {
                inner: integer_list
                    .expand(IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking)?,
                info: self.info.clone(),
                tag: self.tag.clone(),
            });
        }

        global_state::try_with_internal_keys(|maybe_keys| match maybe_keys {
            None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
            Some(InternalServerKey::Cpu(cpu_key)) => integer_list
                .expand(cpu_key.integer_compact_ciphertext_list_expansion_mode())
                .map(|inner| CompactCiphertextListExpander {
                    inner,
                    info: self.info.clone(),
                    tag: self.tag.clone(),
                }),
            #[cfg(feature = "gpu")]
            Some(_) => Err(crate::Error::new("Expected a CPU server key".to_string())),
        })
    }

    fn to_integer_compact(&self) -> crate::integer::ciphertext::CompactCiphertextList {
        crate::integer::ciphertext::CompactCiphertextList {
            ct_list: self.ct_list.clone(),
            info: self
                .info
                .iter()
                .copied()
                .map(|info| info.to_data_kind(self.ct_list.message_modulus))
                .collect(),
        }
    }
}

impl Tagged for CompactCiphertextList {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl ParameterSetConformant for CompactCiphertextList {
    type ParameterSet = CompactCiphertextListConformanceParams;

    fn is_conformant(&self, params: &Self::ParameterSet) -> bool {
        let Self {
            ct_list,
            info,
            tag: _,
        } = self;

        if !params.num_elements_constraint.is_valid(info.len()) {
            return false;
        }

        let mut num_blocks: u32 = info
            .iter()
            .copied()
            .map(|kind| kind.num_blocks(ct_list.message_modulus))
            .sum();

        let shortint_params = params.shortint_params;
        // This expects packing, halve the number of blocks with enough capacity
        if shortint_params.degree.get()
            == (shortint_params.message_modulus.0 * shortint_params.carry_modulus.0) - 1
        {
            num_blocks = num_blocks.div_ceil(2);
        }
        let shortint_list_params = shortint_params
            .to_ct_list_conformance_parameters(ListSizeConstraint::exact_size(num_blocks as usize));
        ct_list.is_conformant(&shortint_list_params)
    }
}

#[cfg(feature = "zk-pok")]
mod zk {
    use super::*;
    use crate::conformance::ParameterSetConformant;
    use crate::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
    use crate::zk::CompactPkeCrs;

    #[derive(Clone, Serialize, Deserialize, Versionize)]
    #[versionize(ProvenCompactCiphertextListVersions)]
    pub struct ProvenCompactCiphertextList {
        pub(crate) ct_list: crate::shortint::ciphertext::ProvenCompactCiphertextList,
        // Integers stored can have a heterogeneous number of blocks and signedness
        // We store this info to safeguard the expansion
        pub(crate) info: Vec<SerializedKind>,
        pub(crate) tag: Tag,
    }

    impl Tagged for ProvenCompactCiphertextList {
        fn tag(&self) -> &Tag {
            &self.tag
        }

        fn tag_mut(&mut self) -> &mut Tag {
            &mut self.tag
        }
    }
    impl Named for ProvenCompactCiphertextList {
        const NAME: &'static str = "high_level_api::ProvenCompactCiphertextList";
    }

    impl ProvenCompactCiphertextList {
        pub fn builder(pk: &CompactPublicKey) -> CompactCiphertextListBuilder {
            CompactCiphertextListBuilder::new(pk)
        }

        pub fn len(&self) -> usize {
            self.info.len()
        }

        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        pub fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes> {
            self.info
                .get(index)
                .and_then(|&kind| crate::FheTypes::try_from(kind).ok())
        }

        pub fn verify(
            &self,
            crs: &CompactPkeCrs,
            pk: &CompactPublicKey,
            metadata: &[u8],
        ) -> crate::zk::ZkVerificationOutcome {
            self.ct_list.verify(crs, &pk.key.key.key, metadata)
        }

        pub fn verify_and_expand(
            &self,
            crs: &CompactPkeCrs,
            pk: &CompactPublicKey,
            metadata: &[u8],
        ) -> crate::Result<CompactCiphertextListExpander> {
            // For WASM
            if !self.is_packed() && !self.needs_casting() {
                // No ServerKey required, short circuit to avoid the global state call
                return Ok(CompactCiphertextListExpander {
                    inner: self.to_integer_compact().verify_and_expand(
                        crs,
                        &pk.key.key,
                        metadata,
                        IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking,
                    )?,
                    info: self.info.clone(),
                    tag: self.tag.clone(),
                });
            }

            global_state::try_with_internal_keys(|maybe_keys| match maybe_keys {
                None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
                Some(InternalServerKey::Cpu(cpu_key)) => self
                    .to_integer_compact()
                    .verify_and_expand(
                        crs,
                        &pk.key.key,
                        metadata,
                        cpu_key.integer_compact_ciphertext_list_expansion_mode(),
                    )
                    .map(|expander| CompactCiphertextListExpander {
                        inner: expander,
                        info: self.info.clone(),
                        tag: self.tag.clone(),
                    }),
                #[cfg(feature = "gpu")]
                Some(_) => Err(crate::Error::new("Expected a CPU server key".to_string())),
            })
        }

        #[doc(hidden)]
        /// This function allows to expand a ciphertext without verifying the associated proof.
        ///
        /// If you are here you were probably looking for it: use at your own risks.
        pub fn expand_without_verification(&self) -> crate::Result<CompactCiphertextListExpander> {
            // For WASM
            if !self.is_packed() && !self.needs_casting() {
                // No ServerKey required, short circuit to avoid the global state call
                return Ok(CompactCiphertextListExpander {
                    inner: self.to_integer_compact().expand_without_verification(
                        IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking,
                    )?,
                    info: self.info.clone(),
                    tag: self.tag.clone(),
                });
            }

            global_state::try_with_internal_keys(|maybe_keys| match maybe_keys {
                None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
                Some(InternalServerKey::Cpu(cpu_key)) => self
                    .to_integer_compact()
                    .expand_without_verification(
                        cpu_key.integer_compact_ciphertext_list_expansion_mode(),
                    )
                    .map(|expander| CompactCiphertextListExpander {
                        inner: expander,
                        info: self.info.clone(),
                        tag: self.tag.clone(),
                    }),
                #[cfg(feature = "gpu")]
                Some(_) => Err(crate::Error::new("Expected a CPU server key".to_string())),
            })
        }

        fn is_packed(&self) -> bool {
            self.ct_list.proved_lists[0].0.degree.get()
                > self.ct_list.proved_lists[0]
                    .0
                    .message_modulus
                    .corresponding_max_degree()
                    .get()
        }

        fn needs_casting(&self) -> bool {
            self.ct_list.proved_lists[0].0.needs_casting()
        }

        fn to_integer_compact(&self) -> crate::integer::ciphertext::ProvenCompactCiphertextList {
            crate::integer::ciphertext::ProvenCompactCiphertextList {
                ct_list: self.ct_list.clone(),
                info: self
                    .info
                    .iter()
                    .copied()
                    .map(|info| info.to_data_kind(self.ct_list.message_modulus()))
                    .collect(),
            }
        }
    }

    impl ParameterSetConformant for ProvenCompactCiphertextList {
        type ParameterSet = IntegerProvenCompactCiphertextListConformanceParams;

        fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
            self.to_integer_compact().is_conformant(parameter_set)
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
        use crate::zk::CompactPkeCrs;
        use rand::{thread_rng, Rng};

        #[test]
        fn conformance_zk_compact_ciphertext_list() {
            let mut rng = thread_rng();

            let params = crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let cpk_params = crate::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let casting_params = crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

            let config = crate::ConfigBuilder::with_custom_parameters(params)
                .use_dedicated_compact_public_key_parameters((cpk_params, casting_params));

            let client_key = crate::ClientKey::generate(config.clone());

            let crs = CompactPkeCrs::from_config(config.into(), 64).unwrap();
            let public_key = crate::CompactPublicKey::try_new(&client_key).unwrap();

            let metadata = [b'T', b'F', b'H', b'E', b'-', b'r', b's'];

            let clear_a = rng.gen::<u64>();
            let clear_b = rng.gen::<bool>();

            let proven_compact_list = crate::ProvenCompactCiphertextList::builder(&public_key)
                .push(clear_a)
                .push(clear_b)
                .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
                .unwrap();

            let params =
                IntegerProvenCompactCiphertextListConformanceParams::from_crs_and_parameters(
                    cpk_params, &crs,
                );

            assert!(proven_compact_list.is_conformant(&params));
        }
    }
}

pub struct CompactCiphertextListExpander {
    pub(in crate::high_level_api) inner: crate::integer::ciphertext::CompactCiphertextListExpander,
    info: Vec<SerializedKind>,
    tag: Tag,
}

impl CiphertextList for CompactCiphertextListExpander {
    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes> {
        self.inner.get_kind_of(index).and_then(|data_kind| {
            crate::FheTypes::from_data_kind(data_kind, self.inner.message_modulus())
        })
    }

    fn get<T>(&self, index: usize) -> crate::Result<Option<T>>
    where
        T: HlExpandable + Tagged,
    {
        let Some(kind) = self.info.get(index) else {
            return Ok(None);
        };

        struct RawBlocks(Vec<Ciphertext>);

        impl Expandable for RawBlocks {
            fn from_expanded_blocks(
                blocks: Vec<Ciphertext>,
                _kind: DataKind,
            ) -> crate::Result<Self> {
                Ok(Self(blocks))
            }
        }

        let expanded_blocks = match self.inner.get::<RawBlocks>(index) {
            Ok(Some(raw_blocks)) => raw_blocks.0,
            Ok(None) => return Ok(None),
            Err(e) => {
                return Err(e);
            }
        };

        let mut expanded = T::from_cpu_blocks(expanded_blocks, *kind);

        if let Ok(inner) = &mut expanded {
            inner.tag_mut().set_data(self.tag.data());
        }
        expanded.map(Some)
    }
}

fn num_bits_to_strict_num_blocks(
    num_bits: u32,
    message_modulus: MessageModulus,
) -> crate::Result<u32> {
    let bits_per_block = message_modulus.0.ilog2();
    if num_bits % bits_per_block != 0 {
        let message = format!("Number of bits must be a multiple of the parameter's MessageModulus.ilog2 ({bits_per_block} here)");
        return Err(crate::Error::new(message));
    }
    Ok(num_bits.div_ceil(bits_per_block))
}

pub trait HlCompactable {
    fn compact_into(
        self,
        builder: &mut CompactCiphertextListBuilder,
        message_modulus: MessageModulus,
        // `Some(n)` when we want to save with a specific number of bits
        // e.g: saving a value contained in a u8 as a u2.
        //
        // When `None`, the number of bits of the type shall be used
        desired_num_bits: Option<u32>,
    ) -> crate::Result<()>;
}

impl HlCompactable for bool {
    fn compact_into(
        self,
        builder: &mut CompactCiphertextListBuilder,
        _message_modulus: MessageModulus,
        desired_num_bits: Option<u32>,
    ) -> crate::Result<()> {
        if let Some(num_bits) = desired_num_bits {
            if num_bits != 1 {
                // Given the additional bound on push_with_num_bits
                // this case is actually not reachable
                return Err(crate::Error::new(
                    "`bool` must be saved as having 1 bit".to_string(),
                ));
            }
        }

        builder.messages.push(u64::from(self));
        builder.info.push(SerializedKind::Bool);
        Ok(())
    }
}

impl<T> HlCompactable for T
where
    T: Numeric + DecomposableInto<u64> + std::ops::Shl<usize, Output = T>,
{
    fn compact_into(
        self,
        builder: &mut CompactCiphertextListBuilder,
        message_modulus: MessageModulus,
        desired_num_bits: Option<u32>,
    ) -> crate::Result<()> {
        let num_bits = desired_num_bits.unwrap_or(T::BITS as u32);
        let num_blocks = num_bits_to_strict_num_blocks(num_bits, message_modulus)?;
        let decomposer =
            create_clear_radix_block_iterator(self, message_modulus, num_blocks as usize);
        builder.messages.extend(decomposer);

        // This works because rust always uses two's complement
        let is_signed = (T::ONE << (T::BITS - 1)) < T::ZERO;
        let kind = if is_signed {
            SerializedKind::Int { num_bits }
        } else {
            SerializedKind::Uint { num_bits }
        };
        builder.info.push(kind);
        Ok(())
    }
}

#[cfg(feature = "strings")]
impl HlCompactable for &ClearString {
    fn compact_into(
        self,
        builder: &mut CompactCiphertextListBuilder,
        message_modulus: MessageModulus,
        // always ignored
        desired_num_bits: Option<u32>,
    ) -> crate::Result<()> {
        if desired_num_bits.is_some() {
            return Err(crate::error!(
                "strings cannot be pushed with a specific number of bits"
            ));
        }

        let kind = <Self as crate::integer::ciphertext::Compactable>::compact_into(
            self,
            &mut builder.messages,
            message_modulus,
            None,
        );
        let DataKind::String { n_chars, padded } = kind else {
            unreachable!("Invalid kind returned by string");
        };
        println!("pushed {n_chars}, {padded} {}", self.len());
        builder
            .info
            .push(SerializedKind::String { n_chars, padded });
        Ok(())
    }
}

pub struct CompactCiphertextListBuilder {
    messages: Vec<u64>,
    info: Vec<SerializedKind>,
    pub(crate) pk: CompactPublicKey,
    tag: Tag,
}

impl CompactCiphertextListBuilder {
    pub fn new(pk: &CompactPublicKey) -> Self {
        Self {
            messages: vec![],
            info: vec![],
            pk: pk.clone(),
            tag: pk.tag.clone(),
        }
    }

    pub fn push<T>(&mut self, value: T) -> &mut Self
    where
        T: HlCompactable,
    {
        value
            .compact_into(self, self.pk.parameters().message_modulus, None)
            .unwrap();
        self
    }

    pub fn extend<T>(&mut self, values: impl Iterator<Item = T>) -> &mut Self
    where
        T: HlCompactable,
    {
        for value in values {
            self.push(value);
        }
        self
    }

    pub fn push_with_num_bits<T>(&mut self, number: T, num_bits: usize) -> crate::Result<&mut Self>
    where
        T: HlCompactable + Numeric,
    {
        number.compact_into(
            self,
            self.pk.parameters().message_modulus,
            Some(num_bits as u32),
        )?;

        Ok(self)
    }

    pub fn extend_with_num_bits<T>(
        &mut self,
        values: impl Iterator<Item = T>,
        num_bits: usize,
    ) -> crate::Result<&mut Self>
    where
        T: HlCompactable + Numeric,
    {
        for value in values {
            self.push_with_num_bits(value, num_bits)?;
        }
        Ok(self)
    }

    pub fn build(&self) -> CompactCiphertextList {
        let ct_list = self.pk.key.key.key.encrypt_slice(self.messages.as_slice());
        CompactCiphertextList {
            ct_list,
            info: self.info.clone(),
            tag: self.tag.clone(),
        }
    }

    pub fn build_packed(&self) -> CompactCiphertextList {
        let ct_list = self
            .pk
            .key
            .key
            .key
            .encrypt_slice_packed(self.messages.as_slice())
            .expect("Invalid parameters that should not have been allowed");
        CompactCiphertextList {
            ct_list,
            info: self.info.clone(),
            tag: self.tag.clone(),
        }
    }

    #[cfg(feature = "zk-pok")]
    pub fn build_with_proof_packed(
        &self,
        crs: &CompactPkeCrs,
        metadata: &[u8],
        compute_load: ZkComputeLoad,
    ) -> crate::Result<ProvenCompactCiphertextList> {
        self.pk
            .key
            .key
            .key
            .encrypt_and_prove_slice_packed(self.messages.as_slice(), crs, metadata, compute_load)
            .map(|ct_list| ProvenCompactCiphertextList {
                ct_list,
                info: self.info.clone(),
                tag: self.tag.clone(),
            })
    }
}

#[cfg(feature = "strings")]
impl CompactCiphertextListBuilder {
    pub fn push_string(&mut self, string: &ClearString) -> &mut Self {
        self.push(string)
    }

    pub fn push_string_with_padding(
        &mut self,
        clear_string: &ClearString,
        padding_count: u32,
    ) -> &mut Self {
        let message_modulus = self.pk.key.parameters().message_modulus;
        let blocks_per_char = 7u32.div_ceil(message_modulus.0.ilog2());

        let kind = <&ClearString as crate::integer::ciphertext::Compactable>::compact_into(
            clear_string,
            &mut self.messages,
            message_modulus,
            Some((clear_string.len() + padding_count as usize) * blocks_per_char as usize),
        );
        let DataKind::String { n_chars, padded } = kind else {
            unreachable!("Invalid kind returned by string");
        };
        self.info.push(SerializedKind::String { n_chars, padded });
        self
    }

    pub fn push_string_with_fixed_size(&mut self, string: &ClearString, size: u32) -> &mut Self {
        let message_modulus = self.pk.key.parameters().message_modulus;
        let blocks_per_char = 7u32.div_ceil(message_modulus.0.ilog2());

        let kind = <&ClearString as crate::integer::ciphertext::Compactable>::compact_into(
            string,
            &mut self.messages,
            message_modulus,
            Some((size * blocks_per_char) as usize),
        );
        let DataKind::String { n_chars, padded } = kind else {
            unreachable!("Invalid kind returned by string");
        };
        self.info.push(SerializedKind::String { n_chars, padded });
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;
    use crate::{set_server_key, FheBool, FheInt64, FheUint16, FheUint2, FheUint32};

    #[test]
    fn test_compact_list() {
        let config = crate::ConfigBuilder::default().build();

        let ck = crate::ClientKey::generate(config);
        let sk = crate::ServerKey::new(&ck);
        let pk = crate::CompactPublicKey::new(&ck);

        set_server_key(sk);

        let compact_list = CompactCiphertextList::builder(&pk)
            .push(17u32)
            .push(-1i64)
            .push(false)
            .push(true)
            .push_with_num_bits(3u8, 2)
            .unwrap()
            .build_packed();

        let serialized = bincode::serialize(&compact_list).unwrap();
        let compact_list: CompactCiphertextList = bincode::deserialize(&serialized).unwrap();
        let expander = compact_list.expand().unwrap();

        {
            let a: FheUint32 = expander.get(0).unwrap().unwrap();
            let b: FheInt64 = expander.get(1).unwrap().unwrap();
            let c: FheBool = expander.get(2).unwrap().unwrap();
            let d: FheBool = expander.get(3).unwrap().unwrap();
            let e: FheUint2 = expander.get(4).unwrap().unwrap();

            let a: u32 = a.decrypt(&ck);
            assert_eq!(a, 17);
            let b: i64 = b.decrypt(&ck);
            assert_eq!(b, -1);
            let c = c.decrypt(&ck);
            assert!(!c);
            let d = d.decrypt(&ck);
            assert!(d);
            let e: u8 = e.decrypt(&ck);
            assert_eq!(e, 3);

            assert!(expander.get::<FheBool>(5).unwrap().is_none());
        }

        {
            // Incorrect type
            assert!(expander.get::<FheInt64>(0).is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheUint16>(0).is_err());
        }
    }

    #[test]
    fn test_compact_list_with_casting() {
        use crate::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        use crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

        let config = crate::ConfigBuilder::with_custom_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )
        .use_dedicated_compact_public_key_parameters((
            V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        ))
        .build();

        let ck = crate::ClientKey::generate(config);
        let sk = crate::ServerKey::new(&ck);
        let pk = crate::CompactPublicKey::new(&ck);

        let compact_list = CompactCiphertextList::builder(&pk)
            .push(17u32)
            .push(-1i64)
            .push(false)
            .push(true)
            .push_with_num_bits(3u8, 2)
            .unwrap()
            .build_packed();

        let serialized = bincode::serialize(&compact_list).unwrap();
        let compact_list: CompactCiphertextList = bincode::deserialize(&serialized).unwrap();
        let expander = compact_list.expand_with_key(&sk).unwrap();

        {
            let a: FheUint32 = expander.get(0).unwrap().unwrap();
            let b: FheInt64 = expander.get(1).unwrap().unwrap();
            let c: FheBool = expander.get(2).unwrap().unwrap();
            let d: FheBool = expander.get(3).unwrap().unwrap();
            let e: FheUint2 = expander.get(4).unwrap().unwrap();

            let a: u32 = a.decrypt(&ck);
            assert_eq!(a, 17);
            let b: i64 = b.decrypt(&ck);
            assert_eq!(b, -1);
            let c = c.decrypt(&ck);
            assert!(!c);
            let d = d.decrypt(&ck);
            assert!(d);
            let e: u8 = e.decrypt(&ck);
            assert_eq!(e, 3);

            assert!(expander.get::<FheBool>(5).unwrap().is_none());
        }

        {
            // Incorrect type
            assert!(expander.get::<FheInt64>(0).is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheUint16>(0).is_err());
        }
    }

    #[cfg(feature = "strings")]
    #[test]
    fn test_compact_list_with_string_and_casting() {
        use crate::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        use crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        use crate::FheAsciiString;

        let config = crate::ConfigBuilder::with_custom_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )
        .use_dedicated_compact_public_key_parameters((
            V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        ))
        .build();

        let ck = crate::ClientKey::generate(config);
        let sk = crate::ServerKey::new(&ck);
        let pk = crate::CompactPublicKey::new(&ck);

        let string1 = ClearString::new("The quick brown fox".to_string());
        let string2 = ClearString::new("jumps over the lazy dog".to_string());

        let compact_list = CompactCiphertextList::builder(&pk)
            .push(17u32)
            .push(true)
            .push(&string1)
            .push_string_with_fixed_size(&string2, 55)
            .build_packed();

        let serialized = bincode::serialize(&compact_list).unwrap();
        let compact_list: CompactCiphertextList = bincode::deserialize(&serialized).unwrap();
        let expander = compact_list.expand_with_key(&sk).unwrap();

        {
            let a: FheUint32 = expander.get(0).unwrap().unwrap();
            let b: FheBool = expander.get(1).unwrap().unwrap();
            let c: FheAsciiString = expander.get(2).unwrap().unwrap();
            let d: FheAsciiString = expander.get(3).unwrap().unwrap();

            let a: u32 = a.decrypt(&ck);
            assert_eq!(a, 17);
            let b: bool = b.decrypt(&ck);
            assert!(b);
            let c = c.decrypt(&ck);
            assert_eq!(&c, string1.str());
            let d = d.decrypt(&ck);
            assert_eq!(&d, string2.str());

            assert!(expander.get::<FheBool>(4).unwrap().is_none());
        }

        {
            // Incorrect type
            assert!(expander.get::<FheInt64>(0).is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheAsciiString>(0).is_err());
        }
    }

    #[cfg(feature = "zk-pok")]
    #[test]
    fn test_proven_compact_list() {
        use crate::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        use crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

        let config = crate::ConfigBuilder::with_custom_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )
        .use_dedicated_compact_public_key_parameters((
            V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        ))
        .build();

        let ck = crate::ClientKey::generate(config);
        let pk = crate::CompactPublicKey::new(&ck);
        let sks = crate::ServerKey::new(&ck);

        set_server_key(sks);

        // Intentionally low so that we test when multiple lists and proofs are needed
        let crs = CompactPkeCrs::from_config(config, 32).unwrap();

        let metadata = [b'h', b'l', b'a', b'p', b'i'];

        let compact_list = ProvenCompactCiphertextList::builder(&pk)
            .push(17u32)
            .push(-1i64)
            .push(false)
            .push_with_num_bits(3u32, 2)
            .unwrap()
            .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
            .unwrap();

        let serialized = bincode::serialize(&compact_list).unwrap();
        let compact_list: ProvenCompactCiphertextList = bincode::deserialize(&serialized).unwrap();
        let expander = compact_list
            .verify_and_expand(&crs, &pk, &metadata)
            .unwrap();

        {
            let a: FheUint32 = expander.get(0).unwrap().unwrap();
            let b: FheInt64 = expander.get(1).unwrap().unwrap();
            let c: FheBool = expander.get(2).unwrap().unwrap();
            let d: FheUint2 = expander.get(3).unwrap().unwrap();

            let a: u32 = a.decrypt(&ck);
            assert_eq!(a, 17);
            let b: i64 = b.decrypt(&ck);
            assert_eq!(b, -1);
            let c = c.decrypt(&ck);
            assert!(!c);
            let d: u8 = d.decrypt(&ck);
            assert_eq!(d, 3);

            assert!(expander.get::<FheBool>(4).unwrap().is_none());
        }

        {
            // Incorrect type
            assert!(expander.get::<FheInt64>(0).is_err());

            // Correct type but wrong number of bits
            assert!(expander.get::<FheUint16>(0).is_err());
        }

        let unverified_expander = compact_list.expand_without_verification().unwrap();

        {
            let a: FheUint32 = unverified_expander.get(0).unwrap().unwrap();
            let b: FheInt64 = unverified_expander.get(1).unwrap().unwrap();
            let c: FheBool = unverified_expander.get(2).unwrap().unwrap();
            let d: FheUint2 = unverified_expander.get(3).unwrap().unwrap();

            let a: u32 = a.decrypt(&ck);
            assert_eq!(a, 17);
            let b: i64 = b.decrypt(&ck);
            assert_eq!(b, -1);
            let c = c.decrypt(&ck);
            assert!(!c);
            let d: u8 = d.decrypt(&ck);
            assert_eq!(d, 3);

            assert!(unverified_expander.get::<FheBool>(4).unwrap().is_none());
        }
    }
}
