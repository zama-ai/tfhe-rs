use super::{DataKind, Expandable};
use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
use crate::core_crypto::prelude::Numeric;
use crate::integer::backward_compatibility::ciphertext::CompactCiphertextListVersions;
#[cfg(feature = "zk-pok")]
use crate::integer::backward_compatibility::ciphertext::ProvenCompactCiphertextListVersions;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::encryption::{create_clear_radix_block_iterator, KnowsMessageModulus};
use crate::integer::parameters::CompactCiphertextListConformanceParams;
pub use crate::integer::parameters::IntegerCompactCiphertextListExpansionMode;
use crate::integer::{CompactPublicKey, ServerKey};
#[cfg(feature = "zk-pok")]
use crate::shortint::ciphertext::ProvenCompactCiphertextListConformanceParams;
use crate::shortint::parameters::{
    CastingFunctionsOwned, CiphertextConformanceParams, ShortintCompactCiphertextListCastingMode,
};
#[cfg(feature = "zk-pok")]
use crate::shortint::parameters::{
    CiphertextModulus, CompactCiphertextListExpansionKind, CompactPublicKeyEncryptionParameters,
    LweDimension,
};
use crate::shortint::{CarryModulus, Ciphertext, MessageModulus};
#[cfg(feature = "zk-pok")]
use crate::zk::{CompactPkeCrs, ZkComputeLoad, ZkVerificationOutCome};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// Unpack message and carries and additionally sanitizes blocks that correspond to boolean values
/// to make sure they encrypt a 0 or a 1.
fn unpack_and_sanitize_message_and_carries(
    packed_blocks: Vec<Ciphertext>,
    sks: &ServerKey,
    infos: &[DataKind],
) -> Vec<Ciphertext> {
    let IntegerUnpackingToShortintCastingModeHelper {
        msg_extract,
        carry_extract,
        msg_extract_bool,
        carry_extract_bool,
    } = IntegerUnpackingToShortintCastingModeHelper::new(
        sks.message_modulus(),
        sks.carry_modulus(),
    );
    let msg_extract = sks.key.generate_lookup_table(msg_extract);
    let carry_extract = sks.key.generate_lookup_table(carry_extract);
    let msg_extract_bool = sks.key.generate_lookup_table(msg_extract_bool);
    let carry_extract_bool = sks.key.generate_lookup_table(carry_extract_bool);

    let block_count: usize = infos.iter().map(|x| x.num_blocks()).sum();
    let packed_block_count = block_count.div_ceil(2);
    assert_eq!(
        packed_block_count,
        packed_blocks.len(),
        "Internal error, invalid packed blocks count during unpacking of a compact ciphertext list."
    );
    let mut functions = vec![[None; 2]; packed_block_count];

    let mut overall_block_idx = 0;

    for data_kind in infos {
        let block_count = data_kind.num_blocks();
        for _ in 0..block_count {
            let is_in_msg_part = overall_block_idx % 2 == 0;

            let unpacking_function = if is_in_msg_part {
                if matches!(data_kind, DataKind::Boolean) {
                    &msg_extract_bool
                } else {
                    &msg_extract
                }
            } else if matches!(data_kind, DataKind::Boolean) {
                &carry_extract_bool
            } else {
                &carry_extract
            };

            let packed_block_idx = overall_block_idx / 2;
            let idx_in_packed_block = overall_block_idx % 2;

            functions[packed_block_idx][idx_in_packed_block] = Some(unpacking_function);
            overall_block_idx += 1;
        }
    }

    packed_blocks
        .into_par_iter()
        .zip(functions.into_par_iter())
        .flat_map(|(block, extract_function)| {
            let mut low_block = block;
            let mut high_block = low_block.clone();
            let (msg_lut, carry_lut) = (extract_function[0], extract_function[1]);

            rayon::join(
                || {
                    if let Some(msg_lut) = msg_lut {
                        sks.key.apply_lookup_table_assign(&mut low_block, msg_lut);
                    }
                },
                || {
                    if let Some(carry_lut) = carry_lut {
                        sks.key
                            .apply_lookup_table_assign(&mut high_block, carry_lut);
                    }
                },
            );

            [low_block, high_block]
        })
        .collect::<Vec<_>>()
}

/// This function sanitizes boolean blocks to make sure they encrypt a 0 or a 1
fn sanitize_boolean_blocks(
    packed_blocks: Vec<Ciphertext>,
    sks: &ServerKey,
    infos: &[DataKind],
) -> Vec<Ciphertext> {
    let message_modulus = sks.message_modulus().0 as u64;
    let msg_extract_bool = sks.key.generate_lookup_table(|x: u64| {
        let tmp = x % message_modulus;
        if tmp == 0 {
            0u64
        } else {
            1u64
        }
    });

    let block_count: usize = infos.iter().map(|x| x.num_blocks()).sum();
    let mut functions = vec![None; block_count];

    let mut overall_block_idx = 0;

    for data_kind in infos {
        let block_count = data_kind.num_blocks();
        for _ in 0..block_count {
            let acc = if matches!(data_kind, DataKind::Boolean) {
                Some(&msg_extract_bool)
            } else {
                None
            };

            functions[overall_block_idx] = acc;
            overall_block_idx += 1;
        }
    }

    packed_blocks
        .into_par_iter()
        .zip(functions.into_par_iter())
        .map(|(mut block, sanitize_acc)| {
            if let Some(sanitize_acc) = sanitize_acc {
                sks.key.apply_lookup_table_assign(&mut block, sanitize_acc);
            }

            block
        })
        .collect::<Vec<_>>()
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

    #[cfg(feature = "zk-pok")]
    pub fn build_with_proof(
        &self,
        crs: &CompactPkeCrs,
        metadata: &[u8],
        load: ZkComputeLoad,
    ) -> crate::Result<ProvenCompactCiphertextList> {
        let ct_list = self.pk.key.encrypt_and_prove_slice(
            self.messages.as_slice(),
            crs,
            metadata,
            load,
            self.pk.key.parameters.message_modulus.0 as u64,
        )?;
        Ok(ProvenCompactCiphertextList {
            ct_list,
            info: self.info.clone(),
        })
    }

    #[cfg(feature = "zk-pok")]
    pub fn build_with_proof_packed(
        &self,
        crs: &CompactPkeCrs,
        metadata: &[u8],
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
            crs,
            metadata,
            load,
            msg_mod * msg_mod,
        )?;
        Ok(ProvenCompactCiphertextList {
            ct_list,
            info: self.info.clone(),
        })
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

    pub fn get_kind_of(&self, index: usize) -> Option<DataKind> {
        self.info.get(index).copied()
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

    pub fn get<T>(&self, index: usize) -> crate::Result<Option<T>>
    where
        T: Expandable,
    {
        self.blocks_of(index)
            .map(|(blocks, kind)| T::from_expanded_blocks(blocks.to_owned(), kind))
            .transpose()
    }

    pub(crate) fn message_modulus(&self) -> MessageModulus {
        self.expanded_blocks[0].message_modulus
    }
}

#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(CompactCiphertextListVersions)]
pub struct CompactCiphertextList {
    pub(crate) ct_list: crate::shortint::ciphertext::CompactCiphertextList,
    // Integers stored can have a heterogeneous number of blocks and signedness
    // We store this info to safeguard the expansion
    pub(crate) info: Vec<DataKind>,
}

impl ParameterSetConformant for CompactCiphertextList {
    type ParameterSet = CompactCiphertextListConformanceParams;

    fn is_conformant(&self, params: &CompactCiphertextListConformanceParams) -> bool {
        let Self { ct_list: _, info } = self;

        if !params.num_elements_constraint.is_valid(info.len()) {
            return false;
        }

        self.is_conformant_with_shortint_params(params.shortint_params)
    }
}

pub const WRONG_UNPACKING_MODE_ERR_MSG: &str =
    "Cannot expand a CompactCiphertextList that requires unpacking without \
    a server key, please provide a integer::ServerKey passing it with the \
    enum variant IntegerCompactCiphertextListExpansionMode::UnpackIfNecessary \
    or IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary \
    as unpacking_mode.";

struct IntegerUnpackingToShortintCastingModeHelper {
    msg_extract: Box<dyn Fn(u64) -> u64 + Sync>,
    carry_extract: Box<dyn Fn(u64) -> u64 + Sync>,
    msg_extract_bool: Box<dyn Fn(u64) -> u64 + Sync>,
    carry_extract_bool: Box<dyn Fn(u64) -> u64 + Sync>,
}

impl IntegerUnpackingToShortintCastingModeHelper {
    pub fn new(message_modulus: MessageModulus, carry_modulus: CarryModulus) -> Self {
        let message_modulus = message_modulus.0 as u64;
        let carry_modulus = carry_modulus.0 as u64;
        let msg_extract = Box::new(move |x: u64| x % message_modulus);
        let carry_extract = Box::new(move |x: u64| (x / carry_modulus) % message_modulus);
        let msg_extract_bool = Box::new(move |x: u64| {
            let tmp = x % message_modulus;
            u64::from(tmp != 0)
        });
        let carry_extract_bool = Box::new(move |x: u64| {
            let tmp = (x / carry_modulus) % message_modulus;
            u64::from(tmp != 0)
        });

        Self {
            msg_extract,
            carry_extract,
            msg_extract_bool,
            carry_extract_bool,
        }
    }

    pub fn generate_function(&self, infos: &[DataKind]) -> CastingFunctionsOwned {
        let block_count: usize = infos.iter().map(|x| x.num_blocks()).sum();
        let packed_block_count = block_count.div_ceil(2);
        let mut functions = vec![Some(Vec::with_capacity(2)); packed_block_count];

        let mut overall_block_idx = 0;

        for data_kind in infos {
            let block_count = data_kind.num_blocks();
            for _ in 0..block_count {
                let is_in_msg_part = overall_block_idx % 2 == 0;

                let unpacking_function: &(dyn Fn(u64) -> u64 + Sync) = if is_in_msg_part {
                    if matches!(data_kind, DataKind::Boolean) {
                        self.msg_extract_bool.as_ref()
                    } else {
                        self.msg_extract.as_ref()
                    }
                } else if matches!(data_kind, DataKind::Boolean) {
                    self.carry_extract_bool.as_ref()
                } else {
                    self.carry_extract.as_ref()
                };

                let packed_block_idx = overall_block_idx / 2;

                if let Some(block_fns) = functions[packed_block_idx].as_mut() {
                    block_fns.push(unpacking_function)
                }

                overall_block_idx += 1;
            }
        }

        functions
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

    pub fn len(&self) -> usize {
        self.info.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get_kind_of(&self, index: usize) -> Option<DataKind> {
        self.info.get(index).copied()
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
        let sself = Self { ct_list, info };
        let expected_lwe_count: usize = {
            let unpacked_expected_lwe_count: usize =
                sself.info.iter().copied().map(DataKind::num_blocks).sum();
            if sself.is_packed() {
                unpacked_expected_lwe_count.div_ceil(2)
            } else {
                unpacked_expected_lwe_count
            }
        };

        assert_eq!(
            sself.ct_list.ct_list.lwe_ciphertext_count().0,
            expected_lwe_count,
            "CompactCiphertextList LweCiphertextCount is expected \
            to be equal to the sum of blocks in the info vec {} vs {:?}",
            expected_lwe_count,
            sself.ct_list.ct_list.lwe_ciphertext_count()
        );

        sself
    }

    /// Allows to change the info about the data kind store in the [`CompactCiphertextList`].
    ///
    /// This can be useful if you are loading an old version of the [`CompactCiphertextList`] which
    /// did not store the metadata before.
    ///
    /// The user is responsible of ensuring data consistency as the library cannot do that
    /// automatically. This can be a problem for boolean data if a block does not encrypt a 0 or a
    /// 1.
    ///
    /// ```rust
    /// use tfhe::integer::ciphertext::{
    ///     CompactCiphertextList, DataKind, IntegerCompactCiphertextListExpansionMode,
    ///     RadixCiphertext, SignedRadixCiphertext,
    /// };
    /// use tfhe::integer::{ClientKey, CompactPublicKey};
    /// use tfhe::shortint::parameters::classic::compact_pk::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS;
    ///
    /// let fhe_params = PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS;
    ///
    /// let num_blocks = 4usize;
    ///
    /// let cks = ClientKey::new(fhe_params);
    /// let pk = CompactPublicKey::new(&cks);
    ///
    /// let mut compact_ct = CompactCiphertextList::builder(&pk).push(-1i8).build();
    ///
    /// let sanity_check_expander = compact_ct
    ///     .expand(IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking)
    ///     .unwrap();
    /// let sanity_expanded = sanity_check_expander
    ///     .get::<SignedRadixCiphertext>(0)
    ///     .unwrap()
    ///     .unwrap();
    /// let sanity_decrypted: i8 = cks.decrypt_signed_radix(&sanity_expanded);
    /// assert_eq!(-1i8, sanity_decrypted);
    ///
    /// compact_ct
    ///     .reinterpret_data(&[DataKind::Unsigned(num_blocks)])
    ///     .unwrap();
    ///
    /// let expander = compact_ct
    ///     .expand(IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking)
    ///     .unwrap();
    ///
    /// let expanded = expander.get::<RadixCiphertext>(0).unwrap().unwrap();
    /// let decrypted: u8 = cks.decrypt_radix(&expanded);
    /// // -1i8 == u8::MAX
    /// assert_eq!(u8::MAX, decrypted);
    /// ```
    pub fn reinterpret_data(&mut self, info: &[DataKind]) -> Result<(), crate::Error> {
        let current_lwe_count: usize = self.info.iter().copied().map(DataKind::num_blocks).sum();
        let new_lwe_count: usize = info.iter().copied().map(DataKind::num_blocks).sum();

        if current_lwe_count != new_lwe_count {
            return Err(crate::Error::new(
                "Unable to reintrepret CompactCiphertextList with information that does \
                not have the same number blocks stored as the list being modified"
                    .to_string(),
            ));
        }

        self.info.copy_from_slice(info);

        Ok(())
    }

    pub fn ciphertext_count(&self) -> usize {
        self.info.len()
    }

    pub fn expand(
        &self,
        expansion_mode: IntegerCompactCiphertextListExpansionMode<'_>,
    ) -> crate::Result<CompactCiphertextListExpander> {
        let is_packed = self.is_packed();

        if is_packed
            && matches!(
                expansion_mode,
                IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking
            )
        {
            return Err(crate::Error::new(String::from(
                WRONG_UNPACKING_MODE_ERR_MSG,
            )));
        }

        let expanded_blocks = match expansion_mode {
            IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(
                key_switching_key_view,
            ) => {
                let function_helper;
                let functions;
                let functions = if is_packed {
                    let dest_sks = &key_switching_key_view.key.dest_server_key;
                    function_helper = IntegerUnpackingToShortintCastingModeHelper::new(
                        dest_sks.message_modulus,
                        dest_sks.carry_modulus,
                    );
                    functions = function_helper.generate_function(&self.info);
                    Some(functions.as_slice())
                } else {
                    None
                };
                self.ct_list
                    .expand(ShortintCompactCiphertextListCastingMode::CastIfNecessary {
                        casting_key: key_switching_key_view.key,
                        functions,
                    })?
            }
            IntegerCompactCiphertextListExpansionMode::UnpackAndSanitizeIfNecessary(sks) => {
                let expanded_blocks = self
                    .ct_list
                    .expand(ShortintCompactCiphertextListCastingMode::NoCasting)?;

                if is_packed {
                    let degree = self.ct_list.degree;
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

                    unpack_and_sanitize_message_and_carries(expanded_blocks, sks, &self.info)
                } else {
                    sanitize_boolean_blocks(expanded_blocks, sks, &self.info)
                }
            }
            IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking => self
                .ct_list
                .expand(ShortintCompactCiphertextListCastingMode::NoCasting)?,
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

    fn is_conformant_with_shortint_params(
        &self,
        shortint_params: CiphertextConformanceParams,
    ) -> bool {
        let Self { ct_list, info } = self;

        let mut num_blocks: usize = info.iter().copied().map(DataKind::num_blocks).sum();
        // This expects packing, halve the number of blocks with enough capacity
        if shortint_params.degree.get()
            == (shortint_params.message_modulus.0 * shortint_params.carry_modulus.0) - 1
        {
            num_blocks = num_blocks.div_ceil(2);
        }
        let shortint_list_params = shortint_params
            .to_ct_list_conformance_parameters(ListSizeConstraint::exact_size(num_blocks));
        ct_list.is_conformant(&shortint_list_params)
    }
}

#[cfg(feature = "zk-pok")]
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(ProvenCompactCiphertextListVersions)]
pub struct ProvenCompactCiphertextList {
    pub(crate) ct_list: crate::shortint::ciphertext::ProvenCompactCiphertextList,
    // Integers stored can have a heterogeneous number of blocks and signedness
    // We store this info to safeguard the expansion
    pub(crate) info: Vec<DataKind>,
}

#[cfg(feature = "zk-pok")]
impl ProvenCompactCiphertextList {
    pub fn builder(pk: &CompactPublicKey) -> CompactCiphertextListBuilder {
        CompactCiphertextListBuilder::new(pk)
    }

    pub fn verify(
        &self,
        crs: &CompactPkeCrs,
        public_key: &CompactPublicKey,
        metadata: &[u8],
    ) -> ZkVerificationOutCome {
        self.ct_list.verify(crs, &public_key.key, metadata)
    }

    pub fn verify_and_expand(
        &self,
        crs: &CompactPkeCrs,
        public_key: &CompactPublicKey,
        metadata: &[u8],
        expansion_mode: IntegerCompactCiphertextListExpansionMode<'_>,
    ) -> crate::Result<CompactCiphertextListExpander> {
        let is_packed = self.is_packed();

        if is_packed
            && matches!(
                expansion_mode,
                IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking
            )
        {
            return Err(crate::Error::new(String::from(
                WRONG_UNPACKING_MODE_ERR_MSG,
            )));
        }

        let expanded_blocks = match expansion_mode {
            IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(
                key_switching_key_view,
            ) => {
                let function_helper;
                let functions;
                let functions = if is_packed {
                    let dest_sks = &key_switching_key_view.key.dest_server_key;
                    function_helper = IntegerUnpackingToShortintCastingModeHelper::new(
                        dest_sks.message_modulus,
                        dest_sks.carry_modulus,
                    );
                    functions = function_helper.generate_function(&self.info);
                    Some(functions.as_slice())
                } else {
                    None
                };
                self.ct_list.verify_and_expand(
                    crs,
                    &public_key.key,
                    metadata,
                    ShortintCompactCiphertextListCastingMode::CastIfNecessary {
                        casting_key: key_switching_key_view.key,
                        functions,
                    },
                )?
            }
            IntegerCompactCiphertextListExpansionMode::UnpackAndSanitizeIfNecessary(sks) => {
                let expanded_blocks = self.ct_list.verify_and_expand(
                    crs,
                    &public_key.key,
                    metadata,
                    ShortintCompactCiphertextListCastingMode::NoCasting,
                )?;

                if is_packed {
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

                    unpack_and_sanitize_message_and_carries(expanded_blocks, sks, &self.info)
                } else {
                    sanitize_boolean_blocks(expanded_blocks, sks, &self.info)
                }
            }
            IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking => {
                self.ct_list.verify_and_expand(
                    crs,
                    &public_key.key,
                    metadata,
                    ShortintCompactCiphertextListCastingMode::NoCasting,
                )?
            }
        };

        Ok(CompactCiphertextListExpander::new(
            expanded_blocks,
            self.info.clone(),
        ))
    }

    #[doc(hidden)]
    /// This function allows to expand a ciphertext without verifying the associated proof.
    ///
    /// If you are here you were probably looking for it: use at your own risks.
    pub fn expand_without_verification(
        &self,
        expansion_mode: IntegerCompactCiphertextListExpansionMode<'_>,
    ) -> crate::Result<CompactCiphertextListExpander> {
        let is_packed = self.is_packed();

        if is_packed
            && matches!(
                expansion_mode,
                IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking
            )
        {
            return Err(crate::Error::new(String::from(
                WRONG_UNPACKING_MODE_ERR_MSG,
            )));
        }

        let expanded_blocks = match expansion_mode {
            IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(
                key_switching_key_view,
            ) => {
                let function_helper;
                let functions;
                let functions = if is_packed {
                    let dest_sks = &key_switching_key_view.key.dest_server_key;
                    function_helper = IntegerUnpackingToShortintCastingModeHelper::new(
                        dest_sks.message_modulus,
                        dest_sks.carry_modulus,
                    );
                    functions = function_helper.generate_function(&self.info);
                    Some(functions.as_slice())
                } else {
                    None
                };
                self.ct_list.expand_without_verification(
                    ShortintCompactCiphertextListCastingMode::CastIfNecessary {
                        casting_key: key_switching_key_view.key,
                        functions,
                    },
                )?
            }
            IntegerCompactCiphertextListExpansionMode::UnpackAndSanitizeIfNecessary(sks) => {
                let expanded_blocks = self.ct_list.expand_without_verification(
                    ShortintCompactCiphertextListCastingMode::NoCasting,
                )?;

                if is_packed {
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

                    unpack_and_sanitize_message_and_carries(expanded_blocks, sks, &self.info)
                } else {
                    sanitize_boolean_blocks(expanded_blocks, sks, &self.info)
                }
            }
            IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking => self
                .ct_list
                .expand_without_verification(ShortintCompactCiphertextListCastingMode::NoCasting)?,
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

    pub fn proof_size(&self) -> usize {
        self.ct_list.proof_size()
    }

    pub fn message_modulus(&self) -> MessageModulus {
        self.ct_list.message_modulus()
    }

    pub fn len(&self) -> usize {
        self.info.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get_kind_of(&self, index: usize) -> Option<DataKind> {
        self.info.get(index).copied()
    }
}

#[cfg(feature = "zk-pok")]
#[derive(Copy, Clone)]
pub struct IntegerProvenCompactCiphertextListConformanceParams {
    pub encryption_lwe_dimension: LweDimension,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CiphertextModulus,
    pub expansion_kind: CompactCiphertextListExpansionKind,
    pub max_elements_per_compact_list: usize,
}

#[cfg(feature = "zk-pok")]
impl IntegerProvenCompactCiphertextListConformanceParams {
    pub fn from_crs_and_parameters(
        value: CompactPublicKeyEncryptionParameters,
        crs: &CompactPkeCrs,
    ) -> Self {
        Self::from_public_key_encryption_parameters_and_crs_parameters(value, crs)
    }

    pub fn from_public_key_encryption_parameters_and_crs_parameters(
        value: CompactPublicKeyEncryptionParameters,
        crs: &CompactPkeCrs,
    ) -> Self {
        Self {
            encryption_lwe_dimension: value.encryption_lwe_dimension,
            message_modulus: value.message_modulus,
            carry_modulus: value.carry_modulus,
            ciphertext_modulus: value.ciphertext_modulus,
            expansion_kind: value.expansion_kind,
            max_elements_per_compact_list: crs.max_num_messages(),
        }
    }
}

#[cfg(feature = "zk-pok")]
impl ParameterSetConformant for ProvenCompactCiphertextList {
    type ParameterSet = IntegerProvenCompactCiphertextListConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { ct_list, info } = self;

        let total_expected_num_blocks: usize = info.iter().map(|a| a.num_blocks()).sum();

        let a = ProvenCompactCiphertextListConformanceParams {
            expansion_kind: parameter_set.expansion_kind,
            encryption_lwe_dimension: parameter_set.encryption_lwe_dimension,
            message_modulus: parameter_set.message_modulus,
            carry_modulus: parameter_set.carry_modulus,
            ciphertext_modulus: parameter_set.ciphertext_modulus,
            max_lwe_count_per_compact_list: parameter_set.max_elements_per_compact_list,
            // packing by 2
            total_expected_lwe_count: total_expected_num_blocks.div_ceil(2),
        };

        ct_list.is_conformant(&a)
    }
}

#[cfg(feature = "zk-pok")]
#[cfg(test)]
mod tests {
    // Test utils for tests here
    impl ProvenCompactCiphertextList {
        /// For testing and creating potentially invalid lists
        fn infos_mut(&mut self) -> &mut Vec<DataKind> {
            &mut self.info
        }
    }

    use super::{DataKind, ProvenCompactCiphertextList};
    use crate::integer::ciphertext::CompactCiphertextList;
    use crate::integer::key_switching_key::KeySwitchingKey;
    use crate::integer::parameters::IntegerCompactCiphertextListExpansionMode;
    use crate::integer::{
        BooleanBlock, ClientKey, CompactPrivateKey, CompactPublicKey, RadixCiphertext, ServerKey,
    };
    use crate::shortint::parameters::classic::tuniform::p_fail_2_minus_64::ks_pbs::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::zk::{CompactPkeCrs, ZkComputeLoad};
    use rand::random;

    #[test]
    fn test_zk_compact_ciphertext_list_encryption_ci_run_filter() {
        let pke_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let ksk_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let fhe_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

        let metadata = [b'i', b'n', b't', b'e', b'g', b'e', b'r'];

        let num_blocks = 4usize;
        let modulus = (pke_params.message_modulus.0 as u64)
            .checked_pow(num_blocks as u32)
            .unwrap();

        let crs = CompactPkeCrs::from_shortint_params(pke_params, 512).unwrap();
        let cks = ClientKey::new(fhe_params);
        let sk = ServerKey::new_radix_server_key(&cks);
        let compact_private_key = CompactPrivateKey::new(pke_params);
        let ksk = KeySwitchingKey::new((&compact_private_key, None), (&cks, &sk), ksk_params);
        let pk = CompactPublicKey::new(&compact_private_key);

        let msgs = (0..512)
            .map(|_| random::<u64>() % modulus)
            .collect::<Vec<_>>();

        let proven_ct = CompactCiphertextList::builder(&pk)
            .extend_with_num_blocks(msgs.iter().copied(), num_blocks)
            .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
            .unwrap();

        let expander = proven_ct
            .verify_and_expand(
                &crs,
                &pk,
                &metadata,
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()),
            )
            .unwrap();

        for (idx, msg) in msgs.iter().copied().enumerate() {
            let expanded = expander.get::<RadixCiphertext>(idx).unwrap().unwrap();
            let decrypted = cks.decrypt_radix::<u64>(&expanded);
            assert_eq!(msg, decrypted);
        }

        let unverified_expander = proven_ct
            .expand_without_verification(
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()),
            )
            .unwrap();

        for (idx, msg) in msgs.iter().copied().enumerate() {
            let expanded = unverified_expander
                .get::<RadixCiphertext>(idx)
                .unwrap()
                .unwrap();
            let decrypted = cks.decrypt_radix::<u64>(&expanded);
            assert_eq!(msg, decrypted);
        }
    }

    #[test]
    fn test_several_proven_lists() {
        let pke_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let ksk_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let fhe_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

        let metadata = [b'i', b'n', b't', b'e', b'g', b'e', b'r'];

        let crs_blocks_for_64_bits =
            64 / ((pke_params.message_modulus.0 * pke_params.carry_modulus.0).ilog2() as usize);
        let encryption_num_blocks = 64 / (pke_params.message_modulus.0.ilog2() as usize);

        let crs = CompactPkeCrs::from_shortint_params(pke_params, crs_blocks_for_64_bits).unwrap();
        let cks = ClientKey::new(fhe_params);
        let sk = ServerKey::new_radix_server_key(&cks);
        let compact_private_key = CompactPrivateKey::new(pke_params);
        let ksk = KeySwitchingKey::new((&compact_private_key, None), (&cks, &sk), ksk_params);
        let pk = CompactPublicKey::new(&compact_private_key);

        let msgs = (0..2).map(|_| random::<u64>()).collect::<Vec<_>>();

        let proven_ct = CompactCiphertextList::builder(&pk)
            .extend_with_num_blocks(msgs.iter().copied(), encryption_num_blocks)
            .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
            .unwrap();

        let expander = proven_ct
            .verify_and_expand(
                &crs,
                &pk,
                &metadata,
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()),
            )
            .unwrap();

        for (idx, msg) in msgs.iter().copied().enumerate() {
            let expanded = expander.get::<RadixCiphertext>(idx).unwrap().unwrap();
            let decrypted = cks.decrypt_radix::<u64>(&expanded);
            assert_eq!(msg, decrypted);
        }

        let unverified_expander = proven_ct
            .expand_without_verification(
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()),
            )
            .unwrap();

        for (idx, msg) in msgs.iter().copied().enumerate() {
            let expanded = unverified_expander
                .get::<RadixCiphertext>(idx)
                .unwrap()
                .unwrap();
            let decrypted = cks.decrypt_radix::<u64>(&expanded);
            assert_eq!(msg, decrypted);
        }
    }

    #[test]
    fn test_malicious_boolean_proven_lists() {
        use super::DataKind;

        let pke_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let ksk_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let fhe_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

        let metadata = [b'i', b'n', b't', b'e', b'g', b'e', b'r'];

        let crs_blocks_for_64_bits =
            64 / ((pke_params.message_modulus.0 * pke_params.carry_modulus.0).ilog2() as usize);
        let encryption_num_blocks = 64 / (pke_params.message_modulus.0.ilog2() as usize);

        let crs = CompactPkeCrs::from_shortint_params(pke_params, crs_blocks_for_64_bits).unwrap();
        let cks = ClientKey::new(fhe_params);
        let sk = ServerKey::new_radix_server_key(&cks);
        let compact_private_key = CompactPrivateKey::new(pke_params);
        let ksk = KeySwitchingKey::new((&compact_private_key, None), (&cks, &sk), ksk_params);
        let pk = CompactPublicKey::new(&compact_private_key);

        let msgs = (0..2).map(|_| random::<u64>()).collect::<Vec<_>>();

        let proven_ct = CompactCiphertextList::builder(&pk)
            .extend_with_num_blocks(msgs.iter().copied(), encryption_num_blocks)
            .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
            .unwrap();

        let infos_block_count = {
            let mut infos_block_count = 0;
            let proven_ct_len = proven_ct.len();
            for idx in 0..proven_ct_len {
                infos_block_count += proven_ct.get_kind_of(idx).unwrap().num_blocks();
            }

            infos_block_count
        };

        let mut new_infos = Vec::new();

        let mut curr_block_count = 0;
        for _ in 0..infos_block_count {
            let map_to_fake_boolean = random::<u8>() % 2 == 1;
            if map_to_fake_boolean {
                if curr_block_count != 0 {
                    new_infos.push(DataKind::Unsigned(curr_block_count));
                    curr_block_count = 0;
                }
                new_infos.push(DataKind::Boolean);
            } else {
                curr_block_count += 1;
            }
        }
        if curr_block_count != 0 {
            new_infos.push(DataKind::Unsigned(curr_block_count));
        }

        assert_eq!(
            new_infos.iter().map(|x| x.num_blocks()).sum::<usize>(),
            infos_block_count
        );

        let boolean_block_idx = new_infos
            .iter()
            .enumerate()
            .filter(|(_, kind)| matches!(kind, DataKind::Boolean))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();

        let proven_ct = {
            let mut proven_ct = proven_ct;
            *proven_ct.infos_mut() = new_infos;
            proven_ct
        };

        let expander = proven_ct
            .verify_and_expand(
                &crs,
                &pk,
                &metadata,
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()),
            )
            .unwrap();

        for idx in boolean_block_idx.iter().copied() {
            let expanded = expander.get::<BooleanBlock>(idx).unwrap().unwrap();
            let decrypted = cks.key.decrypt_message_and_carry(&expanded.0);
            // check sanitization is applied even if the original data was not supposed to be
            // boolean
            assert!(decrypted < 2);
        }

        let unverified_expander = proven_ct
            .expand_without_verification(
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()),
            )
            .unwrap();

        for idx in boolean_block_idx.iter().copied() {
            let expanded = unverified_expander
                .get::<BooleanBlock>(idx)
                .unwrap()
                .unwrap();
            let decrypted = cks.key.decrypt_message_and_carry(&expanded.0);
            // check sanitization is applied even if the original data was not supposed to be
            // boolean
            assert!(decrypted < 2);
        }
    }
}
