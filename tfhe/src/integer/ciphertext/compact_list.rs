use super::IntegerRadixCiphertext;
use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
use crate::core_crypto::prelude::Numeric;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::encryption::{create_clear_radix_block_iterator, KnowsMessageModulus};
use crate::integer::parameters::CompactCiphertextListConformanceParams;
pub use crate::integer::parameters::{
    IntegerCompactCiphertextListCastingMode, IntegerCompactCiphertextListUnpackingMode,
};
use crate::integer::{BooleanBlock, CompactPublicKey, ServerKey};
use crate::shortint::parameters::CiphertextConformanceParams;
use crate::shortint::{Ciphertext, MessageModulus};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(feature = "zk-pok-experimental")]
use crate::zk::{CompactPkePublicParams, ZkComputeLoad};

fn extract_message_and_carries(packed_blocks: Vec<Ciphertext>, sks: &ServerKey) -> Vec<Ciphertext> {
    packed_blocks
        .into_par_iter()
        .flat_map(|block| {
            let mut low_block = block;
            let mut high_block = low_block.clone();

            rayon::join(
                || {
                    sks.key.message_extract_assign(&mut low_block);
                },
                || {
                    sks.key.carry_extract_assign(&mut high_block);
                },
            );

            [low_block, high_block]
        })
        .collect::<Vec<_>>()
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataKind {
    Unsigned(usize),
    Signed(usize),
    Boolean,
}

impl DataKind {
    pub fn num_blocks(self) -> usize {
        match self {
            Self::Unsigned(n) | Self::Signed(n) => n,
            Self::Boolean => 1,
        }
    }
}

pub trait Compactable {
    fn compact_into(
        self,
        messages: &mut Vec<u64>,
        message_modulus: MessageModulus,
        num_blocks: Option<usize>,
    ) -> DataKind;
}

impl Compactable for bool {
    fn compact_into(
        self,
        messages: &mut Vec<u64>,
        _message_modulus: MessageModulus,
        _num_blocks: Option<usize>,
    ) -> DataKind {
        messages.push(self as u64);
        DataKind::Boolean
    }
}

impl<T> Compactable for T
where
    T: Numeric + DecomposableInto<u64> + std::ops::Shl<usize, Output = T>,
{
    fn compact_into(
        self,
        messages: &mut Vec<u64>,
        message_modulus: MessageModulus,
        num_blocks: Option<usize>,
    ) -> DataKind {
        let num_blocks =
            num_blocks.unwrap_or_else(|| T::BITS.div_ceil(message_modulus.0.ilog2() as usize));
        let decomposer = create_clear_radix_block_iterator(self, message_modulus, num_blocks);
        messages.extend(decomposer);

        // This works because rust always uses two's complement
        let is_signed = (T::ONE << (T::BITS - 1)) < T::ZERO;
        if is_signed {
            DataKind::Signed(num_blocks)
        } else {
            DataKind::Unsigned(num_blocks)
        }
    }
}

pub struct CompactCiphertextListBuilder {
    messages: Vec<u64>,
    info: Vec<DataKind>,
    pub(crate) pk: CompactPublicKey,
}

impl CompactCiphertextListBuilder {
    pub fn new(pk: &CompactPublicKey) -> Self {
        Self {
            messages: vec![],
            info: vec![],
            pk: pk.clone(),
        }
    }

    pub fn push<T>(&mut self, data: T) -> &mut Self
    where
        T: Compactable,
    {
        let n = self.messages.len();
        let kind = data.compact_into(&mut self.messages, self.pk.key.message_modulus(), None);
        assert_eq!(n + kind.num_blocks(), self.messages.len());

        if kind.num_blocks() != 0 {
            self.info.push(kind);
        }

        self
    }

    pub fn push_with_num_blocks<T>(&mut self, data: T, num_blocks: usize) -> &mut Self
    where
        // The extra `Numeric` bound is to prevent T from being `bool`
        T: Compactable + Numeric,
    {
        if num_blocks == 0 {
            return self;
        }

        let n = self.messages.len();
        let kind = data.compact_into(
            &mut self.messages,
            self.pk.key.message_modulus(),
            Some(num_blocks),
        );
        assert_eq!(n + kind.num_blocks(), self.messages.len());
        self.info.push(kind);
        self
    }

    pub fn extend<T>(&mut self, values: impl Iterator<Item = T>) -> &mut Self
    where
        T: Compactable,
    {
        for value in values {
            self.push(value);
        }
        self
    }

    pub fn extend_with_num_blocks<T>(
        &mut self,
        values: impl Iterator<Item = T>,
        num_blocks: usize,
    ) -> &mut Self
    where
        T: Compactable + Numeric,
    {
        for value in values {
            self.push_with_num_blocks(value, num_blocks);
        }
        self
    }

    pub fn build(&self) -> CompactCiphertextList {
        let ct_list = self.pk.key.encrypt_slice(self.messages.as_slice());
        CompactCiphertextList {
            ct_list,
            info: self.info.clone(),
        }
    }

    pub fn build_packed(&self) -> crate::Result<CompactCiphertextList> {
        if self.pk.key.parameters.carry_modulus.0 < self.pk.key.parameters.message_modulus.0 {
            return Err(crate::Error::new("In order to build a packed compact ciphertext list, parameters must have CarryModulus >= MessageModulus".to_string()));
        }

        // Here self.messages are decomposed blocks in range [0..message_modulus[
        let msg_mod = self.pk.key.message_modulus().0 as u64;
        let packed_messaged_iter = self
            .messages
            .chunks(2)
            .map(|two_values| (two_values.get(1).copied().unwrap_or(0) * msg_mod) + two_values[0]);
        let ct_list = self
            .pk
            .key
            .encrypt_iter_with_modulus(packed_messaged_iter, msg_mod * msg_mod);

        Ok(CompactCiphertextList {
            ct_list,
            info: self.info.clone(),
        })
    }

    #[cfg(feature = "zk-pok-experimental")]
    pub fn build_with_proof(
        &self,
        public_params: &CompactPkePublicParams,
        load: ZkComputeLoad,
    ) -> crate::Result<ProvenCompactCiphertextList> {
        let ct_list = self.pk.key.encrypt_and_prove_slice(
            self.messages.as_slice(),
            public_params,
            load,
            self.pk.key.parameters.message_modulus.0 as u64,
        )?;
        Ok(ProvenCompactCiphertextList {
            ct_list,
            info: self.info.clone(),
        })
    }

    #[cfg(feature = "zk-pok-experimental")]
    pub fn build_with_proof_packed(
        &self,
        public_params: &CompactPkePublicParams,
        load: ZkComputeLoad,
    ) -> crate::Result<ProvenCompactCiphertextList> {
        if self.pk.key.parameters.carry_modulus.0 < self.pk.key.parameters.message_modulus.0 {
            return Err(crate::Error::new(
                "In order to build a packed ProvenCompactCiphertextList, \
                parameters must have CarryModulus >= MessageModulus"
                    .to_string(),
            ));
        }

        let msg_mod = self.pk.key.parameters.message_modulus.0 as u64;
        let packed_messages = self
            .messages
            .chunks(2)
            .map(|two_values| (two_values.get(1).copied().unwrap_or(0) * msg_mod) + two_values[0])
            .collect::<Vec<_>>();
        let ct_list = self.pk.key.encrypt_and_prove_slice(
            packed_messages.as_slice(),
            public_params,
            load,
            msg_mod * msg_mod,
        )?;
        Ok(ProvenCompactCiphertextList {
            ct_list,
            info: self.info.clone(),
        })
    }
}

pub trait Expandable: Sized {
    fn from_expanded_blocks(blocks: &[Ciphertext], kind: DataKind) -> crate::Result<Self>;
}

impl<T> Expandable for T
where
    T: IntegerRadixCiphertext,
{
    fn from_expanded_blocks(blocks: &[Ciphertext], kind: DataKind) -> crate::Result<Self> {
        match (kind, T::IS_SIGNED) {
            (DataKind::Unsigned(_), false) | (DataKind::Signed(_), true) => {
                Ok(T::from_blocks(blocks.to_vec()))
            }
            (DataKind::Boolean, _) => {
                let signed_or_unsigned_str = if T::IS_SIGNED { "signed" } else { "unsigned" };
                Err(crate::Error::new(format!(
                    "Tried to expand a {signed_or_unsigned_str} radix while boolean is stored"
                )))
            }
            (DataKind::Unsigned(_), true) => Err(crate::Error::new(
                "Tried to expand a signed radix while an unsigned radix is stored".to_string(),
            )),
            (DataKind::Signed(_), false) => Err(crate::Error::new(
                "Tried to expand an unsigned radix while a signed radix is stored".to_string(),
            )),
        }
    }
}

impl Expandable for BooleanBlock {
    fn from_expanded_blocks(blocks: &[Ciphertext], kind: DataKind) -> crate::Result<Self> {
        match kind {
            DataKind::Unsigned(_) => Err(crate::Error::new(
                "Tried to expand a boolean block while an unsigned radix was stored".to_string(),
            )),
            DataKind::Signed(_) => Err(crate::Error::new(
                "Tried to expand a boolean block while a signed radix was stored".to_string(),
            )),
            DataKind::Boolean => Ok(Self::new_unchecked(blocks[0].clone())),
        }
    }
}

pub struct CompactCiphertextListExpander {
    expanded_blocks: Vec<Ciphertext>,
    info: Vec<DataKind>,
}

impl CompactCiphertextListExpander {
    fn new(expanded_blocks: Vec<Ciphertext>, info: Vec<DataKind>) -> Self {
        Self {
            expanded_blocks,
            info,
        }
    }

    pub fn len(&self) -> usize {
        self.info.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn blocks_of(&self, index: usize) -> Option<(&[Ciphertext], DataKind)> {
        let preceding_infos = self.info.get(..index)?;
        let current_info = self.info.get(index).copied()?;

        let start_block_index = preceding_infos
            .iter()
            .copied()
            .map(DataKind::num_blocks)
            .sum();
        let end_block_index = start_block_index + current_info.num_blocks();

        self.expanded_blocks
            .get(start_block_index..end_block_index)
            .map(|block| (block, current_info))
    }

    pub fn get_kind_of(&self, index: usize) -> Option<DataKind> {
        self.info.get(index).copied()
    }

    pub fn get<T>(&self, index: usize) -> Option<crate::Result<T>>
    where
        T: Expandable,
    {
        self.blocks_of(index)
            .map(|(blocks, kind)| T::from_expanded_blocks(blocks, kind))
    }

    pub(crate) fn message_modulus(&self) -> MessageModulus {
        self.expanded_blocks[0].message_modulus
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CompactCiphertextList {
    pub(crate) ct_list: crate::shortint::ciphertext::CompactCiphertextList,
    // Integers stored can have a heterogeneous number of blocks and signedness
    // We store this info to safeguard the expansion
    pub(crate) info: Vec<DataKind>,
}

impl ParameterSetConformant for CompactCiphertextList {
    type ParameterSet = CompactCiphertextListConformanceParams;

    fn is_conformant(&self, params: &CompactCiphertextListConformanceParams) -> bool {
        if !params.num_elements_constraint.is_valid(self.info.len()) {
            return false;
        }

        self.is_conformant_with_shortint_params(params.shortint_params)
    }
}

impl CompactCiphertextList {
    pub fn is_packed(&self) -> bool {
        self.ct_list.degree.get()
            > self
                .ct_list
                .message_modulus
                .corresponding_max_degree()
                .get()
    }

    pub fn needs_casting(&self) -> bool {
        self.ct_list.needs_casting()
    }

    pub fn builder(pk: &CompactPublicKey) -> CompactCiphertextListBuilder {
        CompactCiphertextListBuilder::new(pk)
    }

    /// Deconstruct a [`CompactCiphertextList`] into its constituents.
    pub fn into_raw_parts(
        self,
    ) -> (
        crate::shortint::ciphertext::CompactCiphertextList,
        Vec<DataKind>,
    ) {
        let Self { ct_list, info } = self;
        (ct_list, info)
    }

    /// Construct a [`CompactCiphertextList`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the constituents are not compatible with each others.
    pub fn from_raw_parts(
        ct_list: crate::shortint::ciphertext::CompactCiphertextList,
        info: Vec<DataKind>,
    ) -> Self {
        assert_eq!(
            ct_list.ct_list.lwe_ciphertext_count().0,
            info.len(),
            "CompactCiphertextList LweCiphertextCount is expected \
            to be equal to the info vec {} vs {:?}",
            info.len(),
            ct_list.ct_list.lwe_ciphertext_count()
        );

        Self { ct_list, info }
    }

    pub fn ciphertext_count(&self) -> usize {
        self.info.len()
    }

    pub fn expand(
        &self,
        unpacking_mode: IntegerCompactCiphertextListUnpackingMode<'_>,
        casting_mode: IntegerCompactCiphertextListCastingMode<'_>,
    ) -> crate::Result<CompactCiphertextListExpander> {
        let is_packed = self.is_packed();

        if is_packed
            && matches!(
                unpacking_mode,
                IntegerCompactCiphertextListUnpackingMode::NoUnpacking
            )
        {
            return Err(crate::Error::new(String::from(
                "Cannot expand a CompactCiphertextList that requires unpacking without \
                a server key, please provide a shortint::ServerKey passing it with the \
                enum variant CompactCiphertextListUnpackingMode::UnpackIfNecessary \
                as unpacking_mode.",
            )));
        }

        let expanded_blocks = self.ct_list.expand(casting_mode.into())?;

        let expanded_blocks = if is_packed {
            match unpacking_mode {
                IntegerCompactCiphertextListUnpackingMode::UnpackIfNecessary(sks) => {
                    if !self.is_compatible_with_unpacking_server_key(sks) {
                        return Err(crate::Error::new(
                            "This compact list is not conformant with the given server key"
                                .to_string(),
                        ));
                    }

                    extract_message_and_carries(expanded_blocks, sks)
                }
                IntegerCompactCiphertextListUnpackingMode::NoUnpacking => unreachable!(),
            }
        } else {
            expanded_blocks
        };

        Ok(CompactCiphertextListExpander::new(
            expanded_blocks,
            self.info.clone(),
        ))
    }

    pub fn size_elements(&self) -> usize {
        self.ct_list.size_elements()
    }

    pub fn size_bytes(&self) -> usize {
        self.ct_list.size_bytes()
    }

    pub fn is_compatible_with_unpacking_server_key(&self, sks: &ServerKey) -> bool {
        let mut conformance_params = sks.key.conformance_params();
        conformance_params.degree = self.ct_list.degree;

        self.is_conformant_with_shortint_params(conformance_params)
    }

    fn is_conformant_with_shortint_params(
        &self,
        shortint_params: CiphertextConformanceParams,
    ) -> bool {
        let mut num_blocks: usize = self.info.iter().copied().map(DataKind::num_blocks).sum();
        if shortint_params.degree.get()
            == (shortint_params.message_modulus.0 * shortint_params.carry_modulus.0) - 1
        {
            num_blocks = num_blocks.div_ceil(2);
        }
        let shortint_list_params = shortint_params
            .to_ct_list_conformance_parameters(ListSizeConstraint::exact_size(num_blocks));
        self.ct_list.is_conformant(&shortint_list_params)
    }
}

#[cfg(feature = "zk-pok-experimental")]
#[derive(Clone, Serialize, Deserialize)]
pub struct ProvenCompactCiphertextList {
    pub(crate) ct_list: crate::shortint::ciphertext::ProvenCompactCiphertextList,
    // Integers stored can have a heterogeneous number of blocks and signedness
    // We store this info to safeguard the expansion
    pub(crate) info: Vec<DataKind>,
}

#[cfg(feature = "zk-pok-experimental")]
impl ProvenCompactCiphertextList {
    pub fn builder(pk: &CompactPublicKey) -> CompactCiphertextListBuilder {
        CompactCiphertextListBuilder::new(pk)
    }

    pub fn verify_and_expand(
        &self,
        public_params: &CompactPkePublicParams,
        public_key: &CompactPublicKey,
        unpacking_mode: IntegerCompactCiphertextListUnpackingMode<'_>,
        casting_mode: IntegerCompactCiphertextListCastingMode<'_>,
    ) -> crate::Result<CompactCiphertextListExpander> {
        let is_packed = self.is_packed();

        if is_packed
            && matches!(
                unpacking_mode,
                IntegerCompactCiphertextListUnpackingMode::NoUnpacking
            )
        {
            return Err(crate::Error::new(String::from(
                "Cannot expand a CompactCiphertextList that requires unpacking without \
                a server key, please provide a shortint::ServerKey passing it with the \
                enum variant CompactCiphertextListUnpackingMode::UnpackIfNecessary \
                as unpacking_mode.",
            )));
        }

        let expanded_blocks =
            self.ct_list
                .verify_and_expand(public_params, &public_key.key, casting_mode.into())?;

        let expanded_blocks = if is_packed {
            match unpacking_mode {
                IntegerCompactCiphertextListUnpackingMode::UnpackIfNecessary(sks) => {
                    let degree = self.ct_list.proved_lists[0].0.degree;
                    let mut conformance_params = sks.key.conformance_params();
                    conformance_params.degree = degree;

                    for ct in expanded_blocks.iter() {
                        if !ct.is_conformant(&conformance_params) {
                            return Err(crate::Error::new(
                                "This compact list is not conformant with the given server key"
                                    .to_string(),
                            ));
                        }
                    }

                    extract_message_and_carries(expanded_blocks, sks)
                }
                IntegerCompactCiphertextListUnpackingMode::NoUnpacking => unreachable!(),
            }
        } else {
            expanded_blocks
        };

        Ok(CompactCiphertextListExpander::new(
            expanded_blocks,
            self.info.clone(),
        ))
    }

    pub fn is_packed(&self) -> bool {
        self.ct_list.proved_lists[0].0.degree.get()
            > self.ct_list.proved_lists[0]
                .0
                .message_modulus
                .corresponding_max_degree()
                .get()
    }

    pub fn needs_casting(&self) -> bool {
        self.ct_list.proved_lists[0].0.needs_casting()
    }
}

#[cfg(feature = "zk-pok-experimental")]
#[cfg(test)]
mod tests {
    use crate::integer::ciphertext::CompactCiphertextList;
    use crate::integer::parameters::{
        IntegerCompactCiphertextListCastingMode, IntegerCompactCiphertextListUnpackingMode,
    };
    use crate::integer::{ClientKey, CompactPublicKey, RadixCiphertext, ServerKey};
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M64;
    use crate::zk::{CompactPkeCrs, ZkComputeLoad};
    use rand::random;

    #[test]
    fn test_zk_compact_ciphertext_list_encryption_ci_run_filter() {
        let params = PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M64;

        let num_blocks = 4usize;
        let modulus = (params.message_modulus.0 as u64)
            .checked_pow(num_blocks as u32)
            .unwrap();

        let crs = CompactPkeCrs::from_shortint_params(params, 512).unwrap();
        let cks = ClientKey::new(params);
        let sk = ServerKey::new_radix_server_key(&cks);
        let pk = CompactPublicKey::new(&cks);

        let msgs = (0..512)
            .map(|_| random::<u64>() % modulus)
            .collect::<Vec<_>>();

        let proven_ct = CompactCiphertextList::builder(&pk)
            .extend_with_num_blocks(msgs.iter().copied(), num_blocks)
            .build_with_proof_packed(crs.public_params(), ZkComputeLoad::Proof)
            .unwrap();

        let expander = proven_ct
            .verify_and_expand(
                crs.public_params(),
                &pk,
                IntegerCompactCiphertextListUnpackingMode::UnpackIfNecessary(&sk),
                IntegerCompactCiphertextListCastingMode::NoCasting,
            )
            .unwrap();

        for (idx, msg) in msgs.iter().copied().enumerate() {
            let expanded = expander.get::<RadixCiphertext>(idx).unwrap().unwrap();
            let decrypted = cks.decrypt_radix::<u64>(&expanded);
            assert_eq!(msg, decrypted);
        }
    }
}
