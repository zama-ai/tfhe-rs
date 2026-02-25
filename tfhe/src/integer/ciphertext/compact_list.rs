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
use crate::core_crypto::commons::math::random::Seed;
use crate::shortint::ciphertext::Degree;
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
use crate::shortint::server_key::LookupTableOwned;
use crate::shortint::{CarryModulus, Ciphertext, MessageModulus};
#[cfg(feature = "zk-pok")]
use crate::zk::{
    CompactPkeCrs, CompactPkeProofConformanceParams, ZkComputeLoad, ZkPkeV2HashMode,
    ZkVerificationOutcome,
};
use std::num::NonZero;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// Unpack message and carries and additionally sanitizes blocks
///
/// * boolean blocks: make sure they encrypt a 0 or a 1
/// * last block of ascii char: make sure only necessary bits contain information
/// * default case: make sure they have no carries
fn unpack_and_sanitize(
    mut packed_blocks: Vec<Ciphertext>,
    sks: &ServerKey,
    infos: &[DataKind],
) -> Vec<Ciphertext> {
    let block_count: usize = infos
        .iter()
        .map(|x| x.num_blocks(sks.message_modulus()))
        .sum();
    let packed_block_count = block_count.div_ceil(2);
    assert_eq!(
        packed_block_count,
        packed_blocks.len(),
        "Internal error, invalid packed blocks count during unpacking of a compact ciphertext list."
    );
    let functions = IntegerUnpackingToShortintCastingModeHelper::new(
        sks.message_modulus(),
        sks.carry_modulus(),
    )
    .generate_unpacked_and_sanitize_luts(infos, sks);

    // Create a new vec with the input blocks doubled
    let mut unpacked = Vec::with_capacity(functions.len());
    for block in packed_blocks.drain(..packed_block_count - 1) {
        unpacked.push(block.clone());
        unpacked.push(block);
    }
    if block_count % 2 == 0 {
        unpacked.push(packed_blocks[0].clone());
    }
    unpacked.push(packed_blocks.pop().unwrap());

    unpacked
        .par_iter_mut()
        .zip(functions.par_iter())
        .for_each(|(block, lut)| sks.key.apply_lookup_table_assign(block, lut));

    unpacked
}

/// This function sanitizes blocks depending on the data kind:
///
/// * boolean blocks: make sure they encrypt a 0 or a 1
/// * last block of ascii char: make sure only necessary bits contain information
/// * default case: make sure they have no carries
fn sanitize_blocks(
    mut expanded_blocks: Vec<Ciphertext>,
    sks: &ServerKey,
    infos: &[DataKind],
) -> Vec<Ciphertext> {
    let functions = IntegerUnpackingToShortintCastingModeHelper::new(
        sks.message_modulus(),
        sks.carry_modulus(),
    )
    .generate_sanitize_without_unpacking_luts(infos, sks);

    assert_eq!(functions.len(), expanded_blocks.len());
    expanded_blocks
        .par_iter_mut()
        .zip(functions.par_iter())
        .for_each(|(block, sanitize_acc)| {
            sks.key.apply_lookup_table_assign(block, sanitize_acc);
        });

    expanded_blocks
}

pub trait Compactable {
    fn compact_into(
        self,
        messages: &mut Vec<u64>,
        message_modulus: MessageModulus,
        num_blocks: Option<usize>,
    ) -> Option<DataKind>;
}

impl Compactable for bool {
    fn compact_into(
        self,
        messages: &mut Vec<u64>,
        _message_modulus: MessageModulus,
        _num_blocks: Option<usize>,
    ) -> Option<DataKind> {
        messages.push(self as u64);
        Some(DataKind::Boolean)
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
    ) -> Option<DataKind> {
        let num_blocks =
            num_blocks.unwrap_or_else(|| T::BITS.div_ceil(message_modulus.0.ilog2() as usize));
        let num_blocks = NonZero::new(num_blocks)?;
        let decomposer = create_clear_radix_block_iterator(self, message_modulus, num_blocks.get());
        messages.extend(decomposer);

        // This works because rust always uses two's complement
        let is_signed = (T::ONE << (T::BITS - 1)) < T::ZERO;
        if is_signed {
            Some(DataKind::Signed(num_blocks))
        } else {
            Some(DataKind::Unsigned(num_blocks))
        }
    }
}

pub struct CompactCiphertextListBuilder {
    pub(crate) messages: Vec<u64>,
    pub(crate) info: Vec<DataKind>,
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

    /// Pushes Some(kind), and checks that the current block count
    /// is coherent with the pushed kind
    ///
    /// This is to be called after `Compactable::compact_into`
    ///
    /// `count_before` block count before calling Compactable::compact_into
    /// `maybe_kind`: the kind returned by the Compactable::compact_into call
    fn push_and_check_kind_coherence(
        &mut self,
        count_before: usize,
        maybe_kind: Option<DataKind>,
    ) -> Result<(), ()> {
        let added_blocks = match maybe_kind {
            Some(kind) => {
                let msg_modulus = self.pk.key.message_modulus();
                self.info.push(kind);
                kind.num_blocks(msg_modulus)
            }
            None => 0,
        };

        if self.messages.len() == count_before + added_blocks {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn push<T>(&mut self, data: T) -> &mut Self
    where
        T: Compactable,
    {
        let n = self.messages.len();
        let msg_modulus = self.pk.key.message_modulus();
        let maybe_kind = data.compact_into(&mut self.messages, msg_modulus, None);

        self.push_and_check_kind_coherence(n, maybe_kind)
            .expect("Internal error: non coherent block count after push");

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
        let msg_modulus = self.pk.key.message_modulus();
        let maybe_kind = data.compact_into(&mut self.messages, msg_modulus, Some(num_blocks));

        self.push_and_check_kind_coherence(n, maybe_kind)
            .expect("Internal error: non coherent block count after push");
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
        let msg_mod = self.pk.key.message_modulus().0;
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
            self.pk.key.parameters.message_modulus.0,
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

        let msg_mod = self.pk.key.parameters.message_modulus.0;
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

    #[cfg(feature = "zk-pok")]
    pub fn build_with_proof_packed_seeded(
        &self,
        crs: &CompactPkeCrs,
        metadata: &[u8],
        load: ZkComputeLoad,
        seed: Seed,
    ) -> crate::Result<ProvenCompactCiphertextList> {
        if self.pk.key.parameters.carry_modulus.0 < self.pk.key.parameters.message_modulus.0 {
            return Err(crate::Error::new(
                "In order to build a packed ProvenCompactCiphertextList, \
                parameters must have CarryModulus >= MessageModulus"
                    .to_string(),
            ));
        }

        let msg_mod = self.pk.key.parameters.message_modulus.0;
        let packed_messages = self
            .messages
            .chunks(2)
            .map(|two_values| (two_values.get(1).copied().unwrap_or(0) * msg_mod) + two_values[0])
            .collect::<Vec<_>>();
        let ct_list = self.pk.key.encrypt_and_prove_slice_seeded(
            packed_messages.as_slice(),
            crs,
            metadata,
            load,
            msg_mod * msg_mod,
            seed,
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
    pub(crate) fn new(expanded_blocks: Vec<Ciphertext>, info: Vec<DataKind>) -> Self {
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
        let msg_mod = self.expanded_blocks.first()?.message_modulus;

        let start_block_index = preceding_infos
            .iter()
            .copied()
            .map(|kind| kind.num_blocks(msg_mod))
            .sum();
        let end_block_index = start_block_index + current_info.num_blocks(msg_mod);

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
    msg_extract_last_char_block: Box<dyn Fn(u64) -> u64 + Sync>,
    carry_extract_last_char_block: Box<dyn Fn(u64) -> u64 + Sync>,
    message_modulus: MessageModulus,
}

impl IntegerUnpackingToShortintCastingModeHelper {
    pub fn new(message_modulus: MessageModulus, carry_modulus: CarryModulus) -> Self {
        let message_modulus = message_modulus.0;
        let carry_modulus = carry_modulus.0;
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
        let msg_extract_last_char_block = Box::new(move |x: u64| {
            let bits_of_last_char_block = 7u32 % message_modulus.ilog2();
            if bits_of_last_char_block == 0 {
                // The full msg_mod of last block of the char is needed
                x % message_modulus
            } else {
                // Only part of the msg_mod is needed
                x % (1 << bits_of_last_char_block)
            }
        });

        let carry_extract_last_char_block = Box::new(move |x: u64| {
            let x = x / message_modulus;
            let bits_of_last_char_block = 7u32 % message_modulus.ilog2();
            if bits_of_last_char_block == 0 {
                // The full msg_mod of last block of the char is needed
                x % message_modulus
            } else {
                // Only part of the msg_mod is needed
                x % (1 << bits_of_last_char_block)
            }
        });

        Self {
            msg_extract,
            carry_extract,
            msg_extract_bool,
            carry_extract_bool,
            msg_extract_last_char_block,
            carry_extract_last_char_block,
            message_modulus: MessageModulus(message_modulus),
        }
    }

    pub fn generate_unpack_and_sanitize_functions<'a>(
        &'a self,
        infos: &[DataKind],
    ) -> CastingFunctionsOwned<'a> {
        let block_count: usize = infos
            .iter()
            .map(|x| x.num_blocks(self.message_modulus))
            .sum();
        let packed_block_count = block_count.div_ceil(2);
        let mut functions: CastingFunctionsOwned<'a> =
            vec![Some(Vec::with_capacity(2)); packed_block_count];
        let mut overall_block_idx = 0;

        // Small helper that handles the dispatch between the msg_fn and carry_fn
        // depending on the overall block index (to know if the data is in the carry or msg)
        let mut push_functions =
            |block_count: usize,
             msg_fn: &'a (dyn Fn(u64) -> u64 + Sync),
             carry_fn: &'a (dyn Fn(u64) -> u64 + Sync)| {
                for _ in 0..block_count {
                    let is_in_msg_part = overall_block_idx % 2 == 0;
                    let sub_vec = functions[overall_block_idx / 2].as_mut().unwrap();
                    if is_in_msg_part {
                        sub_vec.push(msg_fn);
                    } else {
                        sub_vec.push(carry_fn);
                    }
                    overall_block_idx += 1;
                }
            };

        for data_kind in infos {
            let block_count = data_kind.num_blocks(self.message_modulus);
            match data_kind {
                DataKind::Boolean => {
                    push_functions(
                        block_count,
                        &self.msg_extract_bool,
                        &self.carry_extract_bool,
                    );
                }
                DataKind::String { n_chars, .. } => {
                    let blocks_per_char = 7u32.div_ceil(self.message_modulus.0.ilog2());
                    for _ in 0..*n_chars {
                        push_functions(
                            blocks_per_char as usize - 1,
                            &self.msg_extract,
                            &self.carry_extract,
                        );
                        push_functions(
                            1,
                            &self.msg_extract_last_char_block,
                            &self.carry_extract_last_char_block,
                        );
                    }
                }
                _ => {
                    push_functions(block_count, &self.msg_extract, &self.carry_extract);
                }
            }
        }

        functions
    }

    pub fn generate_sanitize_without_unpacking_functions<'a>(
        &'a self,
        infos: &[DataKind],
    ) -> CastingFunctionsOwned<'a> {
        let total_block_count: usize = infos
            .iter()
            .map(|x| x.num_blocks(self.message_modulus))
            .sum();
        let mut functions = Vec::with_capacity(total_block_count);

        let mut push_functions = |block_count: usize, func: &'a (dyn Fn(u64) -> u64 + Sync)| {
            for _ in 0..block_count {
                functions.push(Some(vec![func]));
            }
        };

        for data_kind in infos {
            let block_count = data_kind.num_blocks(self.message_modulus);
            match data_kind {
                DataKind::Boolean => {
                    push_functions(block_count, self.msg_extract_bool.as_ref());
                }
                DataKind::String { n_chars, .. } => {
                    let blocks_per_char = 7u32.div_ceil(self.message_modulus.0.ilog2());
                    for _ in 0..*n_chars {
                        push_functions(blocks_per_char as usize - 1, self.msg_extract.as_ref());
                        push_functions(1, self.msg_extract_last_char_block.as_ref());
                    }
                }
                _ => {
                    push_functions(block_count, self.msg_extract.as_ref());
                }
            }
        }

        functions
    }

    pub fn generate_sanitize_without_unpacking_luts(
        &self,
        infos: &[DataKind],
        sks: &ServerKey,
    ) -> Vec<LookupTableOwned> {
        let total_block_count: usize = infos
            .iter()
            .map(|x| x.num_blocks(self.message_modulus))
            .sum();
        let mut functions = Vec::with_capacity(total_block_count);

        let mut push_luts_for_function = |block_count: usize, func: &dyn Fn(u64) -> u64| {
            let lut = sks.key.generate_lookup_table(func);
            for _ in 0..block_count {
                functions.push(lut.clone());
            }
        };

        for data_kind in infos {
            let block_count = data_kind.num_blocks(self.message_modulus);
            match data_kind {
                DataKind::Boolean => {
                    push_luts_for_function(block_count, self.msg_extract_bool.as_ref());
                }
                DataKind::String { n_chars, .. } => {
                    let blocks_per_char = 7u32.div_ceil(self.message_modulus.0.ilog2());
                    for _ in 0..*n_chars {
                        push_luts_for_function(
                            blocks_per_char as usize - 1,
                            self.msg_extract.as_ref(),
                        );
                        push_luts_for_function(1, self.msg_extract_last_char_block.as_ref());
                    }
                }
                _ => {
                    push_luts_for_function(block_count, self.msg_extract.as_ref());
                }
            }
        }

        functions
    }

    /// Generates a vec of LUTs to apply to both unpack an sanitize data
    ///
    /// The LUTs are stored flattened, thus 2 consecutive LUTs must be applied to the same input
    /// block
    pub fn generate_unpacked_and_sanitize_luts(
        &self,
        infos: &[DataKind],
        sks: &ServerKey,
    ) -> Vec<LookupTableOwned> {
        let block_count: usize = infos
            .iter()
            .map(|x| x.num_blocks(self.message_modulus))
            .sum();
        let packed_block_count = block_count.div_ceil(2);
        let mut functions = Vec::with_capacity(packed_block_count);
        let mut overall_block_idx = 0;

        // Small help that handles the dispatch between the msg_fn and carry_fn
        // depending on the overall block index (to know if the data is in the carry or msg)
        let mut push_functions =
            |block_count: usize, msg_fn: &dyn Fn(u64) -> u64, carry_fn: &dyn Fn(u64) -> u64| {
                for _ in 0..block_count {
                    let is_in_msg_part = overall_block_idx % 2 == 0;
                    if is_in_msg_part {
                        functions.push(sks.key.generate_lookup_table(msg_fn));
                    } else {
                        functions.push(sks.key.generate_lookup_table(carry_fn));
                    }
                    overall_block_idx += 1;
                }
            };

        for data_kind in infos {
            let block_count = data_kind.num_blocks(self.message_modulus);
            match data_kind {
                DataKind::Boolean => {
                    push_functions(
                        block_count,
                        &self.msg_extract_bool,
                        &self.carry_extract_bool,
                    );
                }
                DataKind::String { n_chars, .. } => {
                    let blocks_per_char = 7u32.div_ceil(self.message_modulus.0.ilog2());
                    for _ in 0..*n_chars {
                        push_functions(
                            blocks_per_char as usize - 1,
                            &self.msg_extract,
                            &self.carry_extract,
                        );
                        push_functions(
                            1,
                            &self.msg_extract_last_char_block,
                            &self.carry_extract_last_char_block,
                        );
                    }
                }
                _ => {
                    push_functions(block_count, &self.msg_extract, &self.carry_extract);
                }
            }
        }

        functions
    }
}

type ExpansionHelperCallback<'a, ListType> = &'a dyn Fn(
    &ListType,
    ShortintCompactCiphertextListCastingMode<'_>,
) -> Result<Vec<Ciphertext>, crate::Error>;

fn expansion_helper<ListType>(
    expansion_mode: IntegerCompactCiphertextListExpansionMode<'_>,
    ct_list: &ListType,
    list_degree: Degree,
    info: &[DataKind],
    is_packed: bool,
    list_expansion_fn: ExpansionHelperCallback<'_, ListType>,
) -> Result<Vec<Ciphertext>, crate::Error> {
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

    match expansion_mode {
        IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(
            key_switching_key_view,
        ) => {
            let dest_sks = &key_switching_key_view.key.dest_server_key;
            let function_helper = IntegerUnpackingToShortintCastingModeHelper::new(
                dest_sks.message_modulus,
                dest_sks.carry_modulus,
            );
            let functions = if is_packed {
                function_helper.generate_unpack_and_sanitize_functions(info)
            } else {
                function_helper.generate_sanitize_without_unpacking_functions(info)
            };

            list_expansion_fn(
                ct_list,
                ShortintCompactCiphertextListCastingMode::CastIfNecessary {
                    casting_key: key_switching_key_view.key,
                    functions: Some(functions.as_slice()),
                },
            )
        }
        IntegerCompactCiphertextListExpansionMode::UnpackAndSanitizeIfNecessary(sks) => {
            let expanded_blocks =
                list_expansion_fn(ct_list, ShortintCompactCiphertextListCastingMode::NoCasting)?;

            if is_packed {
                let mut conformance_params = sks.key.conformance_params();
                conformance_params.degree = list_degree;

                for ct in expanded_blocks.iter() {
                    if !ct.is_conformant(&conformance_params) {
                        return Err(crate::Error::new(
                            "This compact list is not conformant with the given server key"
                                .to_string(),
                        ));
                    }
                }

                Ok(unpack_and_sanitize(expanded_blocks, sks, info))
            } else {
                Ok(sanitize_blocks(expanded_blocks, sks, info))
            }
        }
        IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking => {
            list_expansion_fn(ct_list, ShortintCompactCiphertextListCastingMode::NoCasting)
        }
    }
}

impl CompactCiphertextList {
    pub fn is_packed(&self) -> bool {
        self.ct_list.is_packed()
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
            let unpacked_expected_lwe_count: usize = sself
                .info
                .iter()
                .copied()
                .map(|kind| kind.num_blocks(sself.message_modulus()))
                .sum();
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let fhe_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
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
    ///     .reinterpret_data(&[DataKind::Unsigned(num_blocks.try_into().unwrap())])
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
        let current_lwe_count: usize = self
            .info
            .iter()
            .copied()
            .map(|kind| kind.num_blocks(self.message_modulus()))
            .sum();
        let new_lwe_count: usize = info
            .iter()
            .copied()
            .map(|kind| kind.num_blocks(self.message_modulus()))
            .sum();

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
        self.len()
    }

    pub fn expand(
        &self,
        expansion_mode: IntegerCompactCiphertextListExpansionMode<'_>,
    ) -> crate::Result<CompactCiphertextListExpander> {
        let is_packed = self.is_packed();

        let expanded_blocks = expansion_helper(
            expansion_mode,
            &self.ct_list,
            self.ct_list.degree,
            &self.info,
            is_packed,
            &crate::shortint::ciphertext::CompactCiphertextList::expand,
        )?;

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

    pub fn message_modulus(&self) -> MessageModulus {
        self.ct_list.message_modulus
    }

    fn is_conformant_with_shortint_params(
        &self,
        shortint_params: CiphertextConformanceParams,
    ) -> bool {
        let Self { ct_list, info } = self;

        let mut num_blocks: usize = info
            .iter()
            .copied()
            .map(|kind| kind.num_blocks(self.message_modulus()))
            .sum();
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
    ) -> ZkVerificationOutcome {
        self.ct_list.verify(crs, &public_key.key, metadata)
    }

    pub fn verify_and_expand(
        &self,
        crs: &CompactPkeCrs,
        public_key: &CompactPublicKey,
        metadata: &[u8],
        expansion_mode: IntegerCompactCiphertextListExpansionMode<'_>,
    ) -> crate::Result<CompactCiphertextListExpander> {
        if self.is_empty() {
            if self.verify(crs, public_key, metadata) == ZkVerificationOutcome::Invalid {
                return Err(crate::ErrorKind::InvalidZkProof.into());
            }
            return Ok(CompactCiphertextListExpander::new(vec![], vec![]));
        }

        let is_packed = self.is_packed();

        // Type annotation needed rust is not able to coerce the type on its own, also forces us to
        // use a trait object
        let callback: ExpansionHelperCallback<'_, _> = &|ct_list, expansion_mode| {
            crate::shortint::ciphertext::ProvenCompactCiphertextList::verify_and_expand(
                ct_list,
                crs,
                &public_key.key,
                metadata,
                expansion_mode,
            )
        };

        let expanded_blocks = expansion_helper(
            expansion_mode,
            &self.ct_list,
            self.ct_list.proved_lists[0].0.degree,
            &self.info,
            is_packed,
            callback,
        )?;

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

        let expanded_blocks = expansion_helper(
            expansion_mode,
            &self.ct_list,
            self.ct_list.proved_lists[0].0.degree,
            &self.info,
            is_packed,
            &crate::shortint::ciphertext::ProvenCompactCiphertextList::expand_without_verification,
        )?;

        Ok(CompactCiphertextListExpander::new(
            expanded_blocks,
            self.info.clone(),
        ))
    }

    pub fn is_packed(&self) -> bool {
        if self.is_empty() {
            return false;
        }

        self.ct_list.proved_lists[0].0.is_packed()
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
    pub zk_conformance_params: CompactPkeProofConformanceParams,
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
            max_elements_per_compact_list: crs.max_num_messages().0,
            zk_conformance_params: CompactPkeProofConformanceParams::new(crs.scheme_version()),
        }
    }

    /// Forbid proofs coming with the provided [`ZkComputeLoad`]
    pub fn forbid_compute_load(self, forbidden_compute_load: ZkComputeLoad) -> Self {
        Self {
            zk_conformance_params: self
                .zk_conformance_params
                .forbid_compute_load(forbidden_compute_load),
            ..self
        }
    }

    /// Forbid proofs coming with the provided [`ZkPkeV2HashMode`]. This has no effect on PkeV1
    /// proofs
    pub fn forbid_hash_mode(self, forbidden_hash_mode: ZkPkeV2HashMode) -> Self {
        Self {
            zk_conformance_params: self
                .zk_conformance_params
                .forbid_hash_mode(forbidden_hash_mode),
            ..self
        }
    }
}

#[cfg(feature = "zk-pok")]
impl ParameterSetConformant for ProvenCompactCiphertextList {
    type ParameterSet = IntegerProvenCompactCiphertextListConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { ct_list, info } = self;

        let is_packed = self.is_packed();

        let all_have_same_packing = ct_list
            .proved_lists
            .iter()
            .all(|(list, _)| list.is_packed() == is_packed);

        if !all_have_same_packing {
            return false;
        }

        let total_expected_num_blocks: usize = info
            .iter()
            .map(|a| a.num_blocks(self.message_modulus()))
            .sum();

        let total_expected_lwe_count =
            total_expected_num_blocks.div_ceil(if is_packed { 2 } else { 1 });

        let a = ProvenCompactCiphertextListConformanceParams {
            expansion_kind: parameter_set.expansion_kind,
            encryption_lwe_dimension: parameter_set.encryption_lwe_dimension,
            message_modulus: parameter_set.message_modulus,
            carry_modulus: parameter_set.carry_modulus,
            ciphertext_modulus: parameter_set.ciphertext_modulus,
            max_lwe_count_per_compact_list: parameter_set.max_elements_per_compact_list,
            // packing by 2
            total_expected_lwe_count,
            zk_conformance_params: parameter_set.zk_conformance_params,
        };

        ct_list.is_conformant(&a)
    }
}

#[cfg(feature = "zk-pok")]
#[cfg(test)]
mod zk_pok_tests {
    // Test utils for tests here
    impl ProvenCompactCiphertextList {
        /// For testing and creating potentially invalid lists
        fn infos_mut(&mut self) -> &mut Vec<DataKind> {
            &mut self.info
        }
    }

    use super::{DataKind, ProvenCompactCiphertextList};
    use crate::conformance::ParameterSetConformant;
    use crate::core_crypto::prelude::LweCiphertextCount;
    use crate::integer::ciphertext::{
        CompactCiphertextList, IntegerProvenCompactCiphertextListConformanceParams,
    };
    use crate::integer::key_switching_key::KeySwitchingKey;
    use crate::integer::parameters::IntegerCompactCiphertextListExpansionMode;
    use crate::integer::{
        BooleanBlock, ClientKey, CompactPrivateKey, CompactPublicKey, RadixCiphertext, ServerKey,
    };
    use crate::shortint::ciphertext::Degree;
    use crate::shortint::parameters::test_params::{
        TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
        TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
    };
    use crate::shortint::parameters::{
        PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::zk::{CompactPkeCrs, ZkComputeLoad, ZkVerificationOutcome};
    use rand::random;

    #[test]
    fn test_zk_compact_ciphertext_list_encryption_ci_run_filter() {
        let pke_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let ksk_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let fhe_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let metadata = [b'i', b'n', b't', b'e', b'g', b'e', b'r'];

        let num_blocks = 4usize;
        let modulus = pke_params
            .message_modulus
            .0
            .checked_pow(num_blocks as u32)
            .unwrap();

        let crs = CompactPkeCrs::from_shortint_params(pke_params, LweCiphertextCount(512)).unwrap();
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
    fn test_empty_list() {
        let pke_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let ksk_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let fhe_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let metadata = [b'i', b'n', b't', b'e', b'g', b'e', b'r'];

        let crs = CompactPkeCrs::from_shortint_params(pke_params, LweCiphertextCount(512)).unwrap();
        let cks = ClientKey::new(fhe_params);
        let sk = ServerKey::new_radix_server_key(&cks);
        let compact_private_key = CompactPrivateKey::new(pke_params);
        let ksk = KeySwitchingKey::new((&compact_private_key, None), (&cks, &sk), ksk_params);
        let pk = CompactPublicKey::new(&compact_private_key);

        // Test by pushing with zero blocks
        {
            let proven_ct = CompactCiphertextList::builder(&pk)
                .push_with_num_blocks(1u8, 0)
                .push_with_num_blocks(-1i8, 0)
                .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
                .unwrap();

            assert!(proven_ct.is_empty());
            assert_eq!(proven_ct.len(), 0);
            assert_eq!(
                proven_ct.verify(&crs, &pk, &metadata),
                ZkVerificationOutcome::Valid
            );
            assert!(matches!(
                proven_ct.verify_and_expand(
                    &crs,
                    &pk,
                    &metadata,
                    IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()),
                ),
                Ok(vec) if vec.is_empty()
            ));
        }

        // Test by pushing with nothing
        {
            let proven_ct = CompactCiphertextList::builder(&pk)
                .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
                .unwrap();

            assert!(proven_ct.is_empty());
            assert_eq!(proven_ct.len(), 0);
            assert_eq!(
                proven_ct.verify(&crs, &pk, &metadata),
                ZkVerificationOutcome::Valid
            );
            assert!(matches!(
                proven_ct.verify_and_expand(
                    &crs,
                    &pk,
                    &metadata,
                    IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()),
                ),
                Ok(vec) if vec.is_empty()
            ));
        }
    }

    /// In this test we check the behavior of the proven list when the info vec
    /// is modified
    #[test]
    fn test_attack_list_info() {
        let pke_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let ksk_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let fhe_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let metadata = [b'i', b'n', b't', b'e', b'g', b'e', b'r'];

        let crs = CompactPkeCrs::from_shortint_params(pke_params, LweCiphertextCount(2)).unwrap();
        let cks = ClientKey::new(fhe_params);
        let sk = ServerKey::new_radix_server_key(&cks);
        let compact_private_key = CompactPrivateKey::new(pke_params);
        let ksk = KeySwitchingKey::new((&compact_private_key, None), (&cks, &sk), ksk_params);
        let pk = CompactPublicKey::new(&compact_private_key);

        let conformance_params =
            IntegerProvenCompactCiphertextListConformanceParams::from_crs_and_parameters(
                pke_params, &crs,
            );

        let mut proven_ct = CompactCiphertextList::builder(&pk)
            .push_with_num_blocks(1u8, 4)
            .push_with_num_blocks(-1i8, 4)
            .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
            .unwrap();

        assert_eq!(proven_ct.len(), 2);
        assert!(!proven_ct.is_empty());
        assert_eq!(
            proven_ct.info,
            vec![
                DataKind::Unsigned(4.try_into().unwrap()),
                DataKind::Signed(4.try_into().unwrap())
            ]
        );
        assert_eq!(proven_ct.ct_list.proved_lists.len(), 2);
        assert!(proven_ct.is_conformant(&conformance_params));

        // Change the info vec, conformance should no longer work
        let saved_info = std::mem::take(&mut proven_ct.info);
        assert!(!proven_ct.is_conformant(&conformance_params));
        assert!(proven_ct.is_empty());
        assert_eq!(
            proven_ct.verify(&crs, &pk, &metadata),
            ZkVerificationOutcome::Valid
        );
        assert!(matches!(
            proven_ct.verify_and_expand(
                &crs,
                &pk,
                &metadata,
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.
                    as_view()),
            ),
            Ok(vec) if vec.is_empty()
        ));

        // The info vec will still not be coherent (block number wise)
        // so conformance fails, we still test verify_and_expand to know its
        // behavior
        proven_ct.info = vec![DataKind::Signed(4.try_into().unwrap())];
        assert!(!proven_ct.is_conformant(&conformance_params));
        assert!(!proven_ct.is_empty());
        assert!(proven_ct.is_packed());
        assert_eq!(
            proven_ct.verify(&crs, &pk, &metadata),
            ZkVerificationOutcome::Valid
        );
        assert!(proven_ct
            .verify_and_expand(
                &crs,
                &pk,
                &metadata,
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view())
            )
            .is_err());

        // The info vec will be coherent (block number wise)
        // so conformance passes. However, the info metadata is different from
        // what it was originally
        proven_ct
            .info
            .push(DataKind::Unsigned(4.try_into().unwrap()));
        assert_ne!(proven_ct.info, saved_info);
        assert!(proven_ct.is_conformant(&conformance_params));
        assert!(!proven_ct.is_empty());
        assert!(proven_ct.is_packed());
        assert_eq!(
            proven_ct.verify(&crs, &pk, &metadata),
            ZkVerificationOutcome::Valid
        );
        assert!(proven_ct
            .verify_and_expand(
                &crs,
                &pk,
                &metadata,
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view())
            )
            .is_ok());

        // The info vec now has more entry than there are blocks
        // so conformance fails.
        proven_ct.info.push(DataKind::Boolean);
        assert!(!proven_ct.is_conformant(&conformance_params));
        assert!(!proven_ct.is_empty());
        assert!(proven_ct.is_packed());
        assert_eq!(
            proven_ct.verify(&crs, &pk, &metadata),
            ZkVerificationOutcome::Valid
        );
        assert!(proven_ct
            .verify_and_expand(
                &crs,
                &pk,
                &metadata,
                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view())
            )
            .is_err());
    }

    #[test]
    fn test_attack_proven_list_metadata() {
        let pke_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let ksk_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let fhe_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let metadata = [b'i', b'n', b't', b'e', b'g', b'e', b'r'];

        let crs = CompactPkeCrs::from_shortint_params(pke_params, LweCiphertextCount(2)).unwrap();
        let cks = ClientKey::new(fhe_params);
        let sk = ServerKey::new_radix_server_key(&cks);
        let compact_private_key = CompactPrivateKey::new(pke_params);
        let ksk = KeySwitchingKey::new((&compact_private_key, None), (&cks, &sk), ksk_params);
        let pk = CompactPublicKey::new(&compact_private_key);

        let conformance_params =
            IntegerProvenCompactCiphertextListConformanceParams::from_crs_and_parameters(
                pke_params, &crs,
            );

        let mut proven_ct = CompactCiphertextList::builder(&pk)
            .push_with_num_blocks(1u8, 4)
            .push_with_num_blocks(-1i8, 4)
            .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
            .unwrap();

        assert!(proven_ct.is_conformant(&conformance_params));
        assert_eq!(proven_ct.len(), 2);
        assert!(proven_ct.is_packed());
        assert_eq!(proven_ct.ct_list.proved_lists.len(), 2);
        assert!(proven_ct.ct_list.proved_lists[0].0.is_packed());
        assert!(proven_ct.ct_list.proved_lists[1].0.is_packed());

        proven_ct.ct_list.proved_lists[0].0.degree = Degree::new(0);
        assert!(!proven_ct.is_packed());
        assert_eq!(proven_ct.ct_list.proved_lists.len(), 2);
        assert!(!proven_ct.ct_list.proved_lists[0].0.is_packed());
        assert!(proven_ct.ct_list.proved_lists[1].0.is_packed());
        assert!(!proven_ct.is_conformant(&conformance_params));
        let expander = proven_ct.verify_and_expand(
            &crs,
            &pk,
            &metadata,
            IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()),
        );
        assert!(expander.is_err());
    }

    /// Test a compact list encryption proven with the v1 zk scheme
    #[test]
    fn test_zkv1_compact_ciphertext_list_encryption_ci_run_filter() {
        let pke_params = TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1;
        let ksk_params =
            TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1;
        let fhe_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let metadata = [b'i', b'n', b't', b'e', b'g', b'e', b'r'];

        let num_blocks = 4usize;
        let modulus = pke_params
            .message_modulus
            .0
            .checked_pow(num_blocks as u32)
            .unwrap();

        let crs = CompactPkeCrs::from_shortint_params(pke_params, LweCiphertextCount(512)).unwrap();
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
        let pke_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let ksk_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let fhe_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let metadata = [b'i', b'n', b't', b'e', b'g', b'e', b'r'];

        let crs_blocks_for_64_bits =
            64 / ((pke_params.message_modulus.0 * pke_params.carry_modulus.0).ilog2() as usize);
        let encryption_num_blocks = 64 / (pke_params.message_modulus.0.ilog2() as usize);

        let crs = CompactPkeCrs::from_shortint_params(
            pke_params,
            LweCiphertextCount(crs_blocks_for_64_bits),
        )
        .unwrap();
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

        let pke_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let ksk_params = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let fhe_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let metadata = [b'i', b'n', b't', b'e', b'g', b'e', b'r'];

        let crs_blocks_for_64_bits =
            64 / ((pke_params.message_modulus.0 * pke_params.carry_modulus.0).ilog2() as usize);
        let encryption_num_blocks = 64 / (pke_params.message_modulus.0.ilog2() as usize);

        let crs = CompactPkeCrs::from_shortint_params(
            pke_params,
            LweCiphertextCount(crs_blocks_for_64_bits),
        )
        .unwrap();
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
                infos_block_count += proven_ct
                    .get_kind_of(idx)
                    .unwrap()
                    .num_blocks(pke_params.message_modulus);
            }

            infos_block_count
        };

        let mut new_infos = Vec::new();

        let mut curr_block_count = 0;
        for _ in 0..infos_block_count {
            let map_to_fake_boolean = random::<u8>() % 2 == 1;
            if map_to_fake_boolean {
                if curr_block_count != 0 {
                    new_infos.push(DataKind::Unsigned(curr_block_count.try_into().unwrap()));
                    curr_block_count = 0;
                }
                new_infos.push(DataKind::Boolean);
            } else {
                curr_block_count += 1;
            }
        }
        if curr_block_count != 0 {
            new_infos.push(DataKind::Unsigned(curr_block_count.try_into().unwrap()));
        }

        assert_eq!(
            new_infos
                .iter()
                .map(|x| x.num_blocks(pke_params.message_modulus))
                .sum::<usize>(),
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
