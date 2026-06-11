use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{LweBskGroupingFactor, LweCiphertextCount};
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::{
    AsShortintCiphertextSlice, DataKind, Expandable, IntegerRadixCiphertext,
};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextListBuilder;
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::list_compression::server_keys::CudaCompressionKey;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaDynamicKeyswitchingKey};
use crate::integer::gpu::{
    cuda_backend_kv_store_contains_key, cuda_backend_kv_store_get, cuda_backend_kv_store_map,
    cuda_backend_kv_store_update, CudaServerKey, PBSType,
};
use crate::integer::server_key::{CompressedKVStore, KVStore};
use crate::prelude::CastInto;
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::parameters::AtomicPatternKind;
use rayon::iter::IntoParallelRefIterator;
use rayon::prelude::ParallelIterator;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use tfhe_cuda_backend::cuda_bind::cuda_memcpy_async_gpu_to_gpu;

/// The KVStore is a specialized encrypted HashMap
///
/// * Keys are clear numbers
/// * Values are CudaUnsignedRadixCiphertext or CudaSignedRadixCiphertext
///
/// It supports getting/modifying existing pairs of (key,value)
/// using an encrypted key.
///
///
/// To serialize a KVStore, convert to CPU with `CudaKVStore::to_kv_store` then compress
pub struct CudaKVStore<Key, Ct> {
    data: BTreeMap<Key, Ct>,
    block_count: Option<NonZeroUsize>,
}

#[allow(dead_code)]
impl<Key, Ct> CudaKVStore<Key, Ct> {
    pub(crate) fn from_kv_store<CpuCt>(
        kv_store: &KVStore<Key, CpuCt>,
        streams: &CudaStreams,
    ) -> Self
    where
        Key: Clone + Ord,
        Ct: CudaIntegerRadixCiphertext,
        CpuCt: IntegerRadixCiphertext,
    {
        let mut gpu_kv_store = Self::new();
        kv_store.iter().for_each(|(key, value)| {
            let d_radix =
                CudaRadixCiphertext::from_cpu_blocks(value.as_ciphertext_slice(), streams);
            let d_value = Ct::from(d_radix);
            gpu_kv_store.insert(key.clone(), d_value);
        });
        gpu_kv_store
    }
}

impl<Key, Ct> CudaKVStore<Key, Ct> {
    /// Creates an empty KVStore
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
            block_count: None,
        }
    }

    /// Returns the value stored for the key if any
    ///
    /// Key is in clear, see [CudaServerKey::kv_store_get] if you wish to
    /// query using an encrypted key
    pub fn get(&self, key: &Key) -> Option<&Ct>
    where
        Key: Ord,
    {
        self.data.get(key)
    }

    /// Returns the value stored for the key if any
    ///
    /// Key is in clear, see [CudaServerKey::kv_store_get] if you wish to
    /// query using an encrypted key
    pub fn get_mut(&mut self, key: &Key) -> Option<&mut Ct>
    where
        Key: Ord,
    {
        self.data.get_mut(key)
    }

    /// Inserts the value for the key
    ///
    /// Returns the previous value stored for the key if there was any
    ///
    /// # Notes
    ///
    /// If the value does not contain blocks, nothing is inserted and None is returned
    ///
    /// # Panics
    ///
    /// Panics if the number of blocks of the value is not the same as all other
    /// values stored
    pub fn insert(&mut self, key: Key, value: Ct) -> Option<Ct>
    where
        Key: Ord,
        Ct: CudaIntegerRadixCiphertext,
    {
        let n_blocks = value.as_ref().d_blocks.lwe_ciphertext_count().0;
        if n_blocks == 0 {
            return None;
        }

        let n = self
            .block_count
            .get_or_insert_with(|| NonZeroUsize::new(n_blocks).unwrap());

        assert_eq!(
            n.get(),
            n_blocks,
            "All ciphertexts must have the same number of blocks"
        );
        self.data.insert(key, value)
    }

    /// Removes a key-value pair.
    pub fn remove(&mut self, key: &Key) -> Option<Ct>
    where
        Key: Ord,
    {
        self.data.remove(key)
    }

    /// Returns the value associated to the key given in clear
    pub fn clear_get(&self, key: &Key) -> Option<&Ct>
    where
        Key: Ord,
    {
        self.data.get(key)
    }

    /// Returns the number of key-value pairs currently stored
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns whether the store is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn contains_key(&self, key: &Key) -> bool
    where
        Key: Ord,
    {
        self.data.contains_key(key)
    }

    pub fn duplicate(&self, streams: &CudaStreams) -> Self
    where
        Key: Clone + Ord,
        Ct: CudaIntegerRadixCiphertext,
    {
        let data = self
            .data
            .iter()
            .map(|(k, v)| (k.clone(), v.duplicate(streams)))
            .collect();
        Self {
            data,
            block_count: self.block_count,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Key, &Ct)>
    where
        Key: Ord,
        Ct: Send,
    {
        self.data.iter()
    }

    #[allow(dead_code)]
    fn par_iter_keys(&self) -> impl ParallelIterator<Item = &Key>
    where
        Key: Send + Sync + Ord,
        Ct: Send + Sync,
    {
        self.data.par_iter().map(|(k, _)| k)
    }

    pub(crate) fn blocks_per_radix(&self) -> Option<NonZeroUsize> {
        self.block_count
    }

    #[allow(dead_code)]
    pub(crate) fn to_kv_store<CpuCt>(
        &self,
        streams: &CudaStreams,
    ) -> crate::integer::server_key::KVStore<Key, CpuCt>
    where
        Key: Clone + Ord,
        Ct: CudaIntegerRadixCiphertext,
        CpuCt: IntegerRadixCiphertext,
    {
        let mut kv_store = crate::integer::server_key::KVStore::new();
        for (key, d_value) in &self.data {
            let cpu_blocks = d_value.as_ref().to_cpu_blocks(streams);
            kv_store.insert(key.clone(), CpuCt::from(cpu_blocks));
        }
        kv_store
    }

    pub fn compress<CpuCt>(
        &self,
        compression_key: &CudaCompressionKey,
        streams: &CudaStreams,
    ) -> CompressedKVStore<Key, CpuCt>
    where
        Key: Copy,
        Ct: CudaIntegerRadixCiphertext,
        CpuCt: Expandable + IntegerRadixCiphertext,
    {
        assert_eq!(
            Ct::IS_SIGNED,
            CpuCt::IS_SIGNED,
            "GPU and CPU ciphertext signedness must match"
        );

        let mut builder = CudaCompressedCiphertextListBuilder::new();
        let mut keys = Vec::with_capacity(self.data.len());
        for (key, value) in &self.data {
            let ct = value.as_ref().duplicate(streams);
            let num_blocks = ct.d_blocks.lwe_ciphertext_count().0;
            if let Some(n) = NonZeroUsize::new(num_blocks) {
                keys.push(*key);
                builder.ciphertexts.push(ct);
                let kind = if Ct::IS_SIGNED {
                    DataKind::Signed(n)
                } else {
                    DataKind::Unsigned(n)
                };
                builder.info.push(kind);
            }
        }
        let cuda_compressed = builder.build(compression_key, streams);
        let compressed_list = cuda_compressed.to_compressed_ciphertext_list(streams);
        CompressedKVStore::new(keys, compressed_list)
    }

    // Extract each value and put a duplicate on a contiguous array
    // on device memory
    fn to_vec(&self, streams: &CudaStreams) -> CudaRadixCiphertext
    where
        Key: Ord,
        Ct: CudaIntegerRadixCiphertext + Send,
    {
        let d_blocks_refs: Vec<&CudaLweCiphertextList<u64>> =
            self.iter().map(|(_, v)| &v.as_ref().d_blocks).collect();
        let concatenated_d_blocks = CudaLweCiphertextList::from_vec_cuda_lwe_ciphertexts_list(
            d_blocks_refs.iter().copied(),
            streams,
        );
        let concatenated_info = CudaRadixCiphertextInfo {
            blocks: self
                .iter()
                .flat_map(|(_, v)| v.as_ref().info.blocks.iter())
                .copied()
                .collect(),
        };

        CudaRadixCiphertext {
            d_blocks: concatenated_d_blocks,
            info: concatenated_info,
        }
    }

    /// Scatters blocks from a concatenated `CudaRadixCiphertext` back into each value
    /// in the BTreeMap. Entry i (in iteration order) receives blocks [i*N..(i+1)*N)
    /// from `concatenated`, where N is `blocks_per_radix`.
    fn update_from_concatenated(
        &mut self,
        concatenated: &CudaRadixCiphertext,
        streams: &CudaStreams,
    ) where
        Key: Ord,
        Ct: CudaIntegerRadixCiphertext,
    {
        let blocks_per_value = self
            .block_count
            .expect("Cannot scatter into an empty store")
            .get();
        let lwe_size = concatenated.d_blocks.0.lwe_dimension.to_lwe_size().0;
        let elements_per_value = blocks_per_value * lwe_size;

        for (idx, (_key, value)) in self.data.iter_mut().enumerate() {
            let src_offset = idx * elements_per_value;
            let byte_offset = src_offset * std::mem::size_of::<u64>();
            let copy_size = elements_per_value * std::mem::size_of::<u64>();

            // SAFETY: both pointers are valid GPU allocations on the same device,
            // and the slice [src_offset..src_offset+elements_per_value) is within
            // the concatenated buffer's allocation. The destination buffer owns at
            // least `elements_per_value` elements. All copies are on the same
            // stream, so no concurrent-access hazard.
            unsafe {
                cuda_memcpy_async_gpu_to_gpu(
                    value.as_mut().d_blocks.0.d_vec.as_mut_c_ptr(0),
                    concatenated
                        .d_blocks
                        .0
                        .d_vec
                        .as_c_ptr(0)
                        .wrapping_byte_add(byte_offset),
                    copy_size as u64,
                    streams.ptr[0],
                    streams.gpu_indexes[0].get(),
                );
            }

            let info_start = idx * blocks_per_value;
            let info_end = info_start + blocks_per_value;
            value
                .as_mut()
                .info
                .blocks
                .copy_from_slice(&concatenated.info.blocks[info_start..info_end]);
        }
        streams.synchronize();
    }
}

impl<Key, Ct> Default for CudaKVStore<Key, Ct> {
    fn default() -> Self {
        Self::new()
    }
}

impl CudaServerKey {
    //    Input: encrypted_key (Ct), kv_store data (concatenated values and clear keys)
    //    Output: (retrieved value Ct, found boolean CudaBooleanBlock, selector ciphertexts
    // CudaLweCiphertextList)
    //
    //    We want to return and keep the selectors in the output because we can avoid recomputing
    // them on consecutive operations. For instance, map:
    //
    //     1. map needs to read the current value (that's a get)
    //     2. map needs to write back the new value (that's an update)
    //
    // Both steps need the same selectors, "which entry matches the encrypted key?". If `get`
    // discards the selectors, map would have to compute them twice: once to read, once to
    // write.
    fn kv_store_get_impl<Key, Ct>(
        &self,
        kv_store: &CudaKVStore<Key, Ct>,
        encrypted_key: &Ct,
        streams: &CudaStreams,
    ) -> (Ct, CudaBooleanBlock, CudaLweCiphertextList<u64>)
    where
        Key: DecomposableInto<u64> + CastInto<usize> + Ord + Copy + Sync,
        Ct: CudaIntegerRadixCiphertext + Send,
    {
        let num_blocks_per_value = if let Some(n) = kv_store.blocks_per_radix() {
            n.get()
        } else {
            // In case the store is empty, returns a trivial radix ciphertext
            let num_blocks = encrypted_key.as_ref().d_blocks.lwe_ciphertext_count().0;
            let trivial_ct: Ct = self.create_trivial_zero_radix(num_blocks, streams);

            let trivial_bool_ct: Ct = self.create_trivial_zero_radix(1, streams);
            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_bool_ct.duplicate(streams).into_inner(),
            );

            let trivial_selectors = trivial_ct.as_ref().d_blocks.duplicate(streams);
            return (trivial_ct, trivial_bool, trivial_selectors);
        };

        let num_entries = kv_store.len();

        // Concatenate all lwe ciphertexts on a single array
        let concatenated_values = kv_store.to_vec(streams);
        let clear_keys: Vec<Key> = kv_store.iter().map(|(k, _)| *k).collect();

        let mut result_ct: Ct = self.create_trivial_zero_radix(num_blocks_per_value, streams);
        let mut result_bool = CudaBooleanBlock(
            self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams),
        );

        // Prepare the selectors to be returned
        // We need to initialize them here instead the backend because we return them
        let selector_block_info = CudaBlockInfo {
            degree: Degree::new(0),
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            atomic_pattern: AtomicPatternKind::Standard(self.pbs_order),
            noise_level: NoiseLevel::ZERO,
        };
        let selectors_info = CudaRadixCiphertextInfo {
            blocks: vec![selector_block_info; num_entries],
        };
        let selectors_d_blocks = CudaLweCiphertextList::new(
            self.bootstrapping_key.output_lwe_dimension(),
            LweCiphertextCount(num_entries),
            encrypted_key.as_ref().d_blocks.ciphertext_modulus(),
            streams,
        );
        let mut selectors_ct = CudaRadixCiphertext {
            d_blocks: selectors_d_blocks,
            info: selectors_info,
        };

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        // num_blocks_per_value is bounded by GPU memory; it cannot exceed u32::MAX
        let num_blocks_per_value_u32 =
            u32::try_from(num_blocks_per_value).expect("num_blocks_per_value exceeds u32::MAX");

        // SAFETY: result_ct, result_bool and selectors_ct are freshly allocated on
        // the device bound to `streams` and are passed mutably for exclusive write
        // access; the keys, concatenated values and bootstrapping/keyswitching keys
        // are read-only and live on that same device. clear_keys has one entry per
        // store value, matching the num_entries used to size selectors_ct, and every
        // value holds num_blocks_per_value blocks. The kernels are enqueued on
        // `streams`; the returned ciphertexts carry those same streams, so any
        // downstream host access only happens after a synchronization on the
        // ordered stream.
        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_kv_store_get(
                        streams,
                        &mut result_ct,
                        &mut result_bool,
                        &mut selectors_ct,
                        encrypted_key.as_ref(),
                        &concatenated_values,
                        &clear_keys,
                        num_blocks_per_value_u32,
                        self.message_modulus,
                        self.carry_modulus,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_kv_store_get(
                        streams,
                        &mut result_ct,
                        &mut result_bool,
                        &mut selectors_ct,
                        encrypted_key.as_ref(),
                        &concatenated_values,
                        &clear_keys,
                        num_blocks_per_value_u32,
                        self.message_modulus,
                        self.carry_modulus,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }

        (result_ct, result_bool, selectors_ct.d_blocks)
    }

    pub fn kv_store_contains_key<Key, Ct>(
        &self,
        map: &CudaKVStore<Key, Ct>,
        encrypted_key: &Ct,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Ct: CudaIntegerRadixCiphertext + Send,
        Key: DecomposableInto<u64> + CastInto<usize> + Ord + Copy + Sync,
    {
        if map.is_empty() {
            return CudaBooleanBlock::from_cuda_radix_ciphertext(
                self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams)
                    .into_inner(),
            );
        }

        let clear_keys: Vec<Key> = map.iter().map(|(k, _)| *k).collect();

        let mut result_bool = CudaBooleanBlock(
            self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams),
        );

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        // SAFETY: all GPU buffers are valid allocations on the same device,
        // the FFI function has exclusive access to result_bool and read-only
        // access to the other buffers.
        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_kv_store_contains_key(
                        streams,
                        &mut result_bool,
                        encrypted_key.as_ref(),
                        &clear_keys,
                        self.message_modulus,
                        self.carry_modulus,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_kv_store_contains_key(
                        streams,
                        &mut result_bool,
                        encrypted_key.as_ref(),
                        &clear_keys,
                        self.message_modulus,
                        self.carry_modulus,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }

        result_bool
    }

    pub fn kv_store_contains_value<Key, Ct>(
        &self,
        map: &CudaKVStore<Key, Ct>,
        encrypted_value: &Ct,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Ct: CudaIntegerRadixCiphertext + Send,
        Key: Ord + Sync,
    {
        let values: Vec<_> = map.iter().map(|(_, v)| v.duplicate(streams)).collect();
        self.contains(&values, encrypted_value, streams)
    }

    pub fn kv_store_contains_clear_value<Key, Ct, Clear>(
        &self,
        map: &CudaKVStore<Key, Ct>,
        clear_value: Clear,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Ct: CudaIntegerRadixCiphertext + Send,
        Key: Ord + Sync,
        Clear: DecomposableInto<u64>,
    {
        let values: Vec<_> = map.iter().map(|(_, v)| v.duplicate(streams)).collect();
        self.contains_clear(&values, clear_value, streams)
    }

    pub fn kv_store_get<Key, Ct>(
        &self,
        map: &CudaKVStore<Key, Ct>,
        encrypted_key: &Ct,
        streams: &CudaStreams,
    ) -> (Ct, CudaBooleanBlock)
    where
        Ct: CudaIntegerRadixCiphertext + Send,
        Key: DecomposableInto<u64> + CastInto<usize> + Ord + Copy + Sync,
    {
        let (result, check_block, _selectors) = self.kv_store_get_impl(map, encrypted_key, streams);
        (result, check_block)
    }

    /// Updates the value at the given key by the given value
    ///
    /// `map[encrypted_key] = new_value`
    ///
    /// This finds the value that corresponds to the given `encrypted_key`,
    /// then updates the value stored with the `new_value`.
    ///
    /// Returns a boolean block that encrypts `true` if an entry for
    /// the `encrypted_key` was found, and thus the update was done
    pub fn kv_store_update<Key, Ct>(
        &self,
        map: &mut CudaKVStore<Key, Ct>,
        encrypted_key: &Ct,
        new_value: &Ct,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Ct: CudaIntegerRadixCiphertext + Send,
        Key: DecomposableInto<u64> + CastInto<usize> + Ord + Copy + Sync,
    {
        let num_blocks_per_value = match map.blocks_per_radix() {
            Some(n) => n.get(),
            None => {
                return CudaBooleanBlock::from_cuda_radix_ciphertext(
                    self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams)
                        .into_inner(),
                );
            }
        };

        let concatenated_old_values = map.to_vec(streams);
        let clear_keys: Vec<Key> = map.iter().map(|(k, _)| *k).collect();

        let mut d_check_block: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(1, streams);

        let total_blocks = map.len() * num_blocks_per_value;
        let mut d_updated_values: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(total_blocks, streams);

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        // num_blocks_per_value is bounded by GPU memory; it cannot exceed u32::MAX
        let num_blocks_per_value_u32 =
            u32::try_from(num_blocks_per_value).expect("num_blocks_per_value exceeds u32::MAX");

        // SAFETY: d_check_block and d_updated_values are freshly allocated on the
        // device bound to `streams` and passed mutably for exclusive write access;
        // d_updated_values holds map.len() * num_blocks_per_value blocks, matching
        // the concatenated old values. The key, new value, old values and
        // bootstrapping/keyswitching keys are read-only and live on the same device.
        // clear_keys has one entry per store value. All buffers outlive the call,
        // which synchronizes the stream before returning.
        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_kv_store_update(
                        streams,
                        &mut d_check_block.ciphertext,
                        &mut d_updated_values.ciphertext,
                        encrypted_key.as_ref(),
                        &concatenated_old_values,
                        new_value.as_ref(),
                        &clear_keys,
                        num_blocks_per_value_u32,
                        self.message_modulus,
                        self.carry_modulus,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_kv_store_update(
                        streams,
                        &mut d_check_block.ciphertext,
                        &mut d_updated_values.ciphertext,
                        encrypted_key.as_ref(),
                        &concatenated_old_values,
                        new_value.as_ref(),
                        &clear_keys,
                        num_blocks_per_value_u32,
                        self.message_modulus,
                        self.carry_modulus,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }

        map.update_from_concatenated(&d_updated_values.ciphertext, streams);

        CudaBooleanBlock(d_check_block)
    }

    /// Updates the value at the given key by applying a function
    ///
    /// `map[encrypted_key] = func(map[encrypted_value])`
    ///
    /// This finds the value that corresponds to the given `encrypted_key`, then
    /// calls `func` then updates the value stored with the one returned by the `func`.
    ///
    /// Returns the (old_value, new_value, check_block) where `check_block` encrypts `true` if an
    /// entry for the `encrypted_key` was found.
    pub fn kv_store_map<Key, Ct, F>(
        &self,
        map: &mut CudaKVStore<Key, Ct>,
        encrypted_key: &Ct,
        func: F,
        streams: &CudaStreams,
    ) -> (Ct, Ct, CudaBooleanBlock)
    where
        Ct: CudaIntegerRadixCiphertext + Send,
        Key: DecomposableInto<u64> + CastInto<usize> + Ord,
        F: Fn(Ct) -> Ct,
    {
        let (old_value, _, selectors) = self.kv_store_get_impl(map, encrypted_key, streams);
        let old_value_copy = old_value.duplicate(streams);
        let new_value = func(old_value);

        let num_entries = map.len();
        let num_blocks_per_value = if let Some(n) = map.blocks_per_radix() {
            n.get()
        } else {
            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams)
                    .into_inner(),
            );
            return (old_value_copy, new_value, trivial_bool);
        };

        let concatenated_old_values = map.to_vec(streams);

        // Wrap the selectors (CudaLweCiphertextList<u64>) as a CudaRadixCiphertext
        // so the FFI function can consume it uniformly
        let selector_block_info = CudaBlockInfo {
            degree: Degree::new(1),
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            atomic_pattern: AtomicPatternKind::Standard(self.pbs_order),
            noise_level: NoiseLevel::NOMINAL,
        };
        let selectors_info = CudaRadixCiphertextInfo {
            blocks: vec![selector_block_info; num_entries],
        };
        let selectors_ct = CudaRadixCiphertext {
            d_blocks: selectors,
            info: selectors_info,
        };

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        // num_blocks_per_value is bounded by GPU memory; it cannot exceed u32::MAX
        let num_blocks_per_value_u32 =
            u32::try_from(num_blocks_per_value).expect("num_blocks_per_value exceeds u32::MAX");

        let mut d_check_block: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(1, streams);

        let total_blocks = map.len() * num_blocks_per_value;
        let mut d_updated_values: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(total_blocks, streams);

        // SAFETY: d_check_block and d_updated_values are freshly allocated on the
        // device bound to `streams` and passed mutably for exclusive write access;
        // d_updated_values holds map.len() * num_blocks_per_value blocks, matching
        // the concatenated old values. The old values, new value and selectors are
        // read-only, as are the bootstrapping/keyswitching keys, and all live on the
        // same device. selectors_ct carries num_entries blocks, one per store value.
        // All buffers outlive the call, which synchronizes the stream before returning.
        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_kv_store_map(
                        streams,
                        &mut d_check_block.ciphertext,
                        &mut d_updated_values.ciphertext,
                        &concatenated_old_values,
                        new_value.as_ref(),
                        &selectors_ct,
                        num_blocks_per_value_u32,
                        self.message_modulus,
                        self.carry_modulus,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_kv_store_map(
                        streams,
                        &mut d_check_block.ciphertext,
                        &mut d_updated_values.ciphertext,
                        &concatenated_old_values,
                        new_value.as_ref(),
                        &selectors_ct,
                        num_blocks_per_value_u32,
                        self.message_modulus,
                        self.carry_modulus,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }

        map.update_from_concatenated(&d_updated_values.ciphertext, streams);

        (old_value_copy, new_value, CudaBooleanBlock(d_check_block))
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;
    use crate::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
    use crate::integer::{
        gen_keys, ClientKey, IntegerKeyKind, RadixCiphertext, SignedRadixCiphertext,
    };
    use crate::shortint::parameters::test_params::{
        TEST_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::shortint::ShortintParameterSet;
    use std::collections::BTreeMap;

    use crate::core_crypto::gpu::CudaStreams;
    use crate::integer::server_key::CompressedKVStore;

    fn assert_store_unsigned_matches(
        clear_store: &BTreeMap<u32, u64>,
        kv_store: &CudaKVStore<u32, CudaUnsignedRadixCiphertext>,
        cks: &ClientKey,
    ) {
        assert_eq!(
            clear_store.len(),
            kv_store.len(),
            "Clear and Encrypted stores do no have the same number of pairs"
        );

        let streams = CudaStreams::new_multi_gpu();

        for (key, value) in clear_store {
            let d_ct = kv_store
                .get(key)
                .expect("Missing entry in decompressed KVStore");
            let ct = d_ct.to_radix_ciphertext(&streams);

            let decrypted: u64 = cks.decrypt_radix(&ct);

            assert_eq!(
                *value, decrypted,
                "Invalid value stored for key '{key}', expected '{value}' got '{decrypted}'"
            );
        }
    }

    #[test]
    fn test_compression_serialization_unsigned() {
        let params =
            TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();

        let (cks, _) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

        let private_compression_key = cks.new_compression_private_key(
            TEST_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        );

        let (compression_key, decompression_key) =
            cks.new_compression_decompression_keys(&private_compression_key);

        let num_blocks = 32;
        let num_keys = 100;
        let streams = CudaStreams::new_multi_gpu();

        let mut rng = rand::thread_rng();

        let mut clear_store = BTreeMap::new();
        let mut gpu_kv_store = CudaKVStore::new();
        for _ in 0..num_keys {
            let key = rng.gen::<u32>();
            let value = rng.gen::<u64>();

            let ct = cks.encrypt_radix(value, num_blocks);
            let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);

            let _ = clear_store.insert(key, value);
            gpu_kv_store.insert(key, d_ct);
        }

        assert_store_unsigned_matches(&clear_store, &gpu_kv_store, &cks);

        // Validates the flow GPU -> CPU -> Compress -> Decompress -> CPU -> GPU
        let kv_store: KVStore<u32, RadixCiphertext> = gpu_kv_store.to_kv_store(&streams);
        let compressed = kv_store.compress(&compression_key);
        let kv_store = compressed.decompress(&decompression_key).unwrap();
        let gpu_kv_store = CudaKVStore::from_kv_store(&kv_store, &streams);

        assert_store_unsigned_matches(&clear_store, &gpu_kv_store, &cks);

        // Validates the flow GPU -> CPU -> Serialize -> Deserialize -> CPU -> GPU
        let mut data = vec![];
        crate::safe_serialization::safe_serialize(&compressed, &mut data, 1 << 20).unwrap();
        let compressed: CompressedKVStore<u32, RadixCiphertext> =
            crate::safe_serialization::safe_deserialize(data.as_slice(), 1 << 20).unwrap();
        let kv_store = compressed.decompress(&decompression_key).unwrap();
        let gpu_kv_store = CudaKVStore::from_kv_store(&kv_store, &streams);
        assert_store_unsigned_matches(&clear_store, &gpu_kv_store, &cks);
    }

    fn assert_store_signed_matches(
        clear_store: &BTreeMap<u32, i64>,
        kv_store: &CudaKVStore<u32, CudaSignedRadixCiphertext>,
        cks: &ClientKey,
    ) {
        assert_eq!(
            clear_store.len(),
            kv_store.len(),
            "Clear and Encrypted stores do no have the same number of pairs"
        );

        let streams = CudaStreams::new_multi_gpu();

        for (key, value) in clear_store {
            let d_ct = kv_store
                .get(key)
                .expect("Missing entry in decompressed KVStore");
            let ct = d_ct.to_signed_radix_ciphertext(&streams);

            let decrypted: i64 = cks.decrypt_signed_radix(&ct);

            assert_eq!(
                *value, decrypted,
                "Invalid value stored for key '{key}', expected '{value}' got '{decrypted}'"
            );
        }
    }

    #[test]
    fn test_compression_serialization_signed() {
        let params =
            TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();

        let (cks, _) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

        let private_compression_key = cks.new_compression_private_key(
            TEST_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        );

        let (compression_key, decompression_key) =
            cks.new_compression_decompression_keys(&private_compression_key);

        let num_blocks = 32;
        let num_keys = 100;
        let streams = CudaStreams::new_multi_gpu();

        let mut rng = rand::thread_rng();

        let mut clear_store = BTreeMap::new();
        let mut gpu_kv_store = CudaKVStore::new();
        for _ in 0..num_keys {
            let key = rng.gen::<u32>();
            let value = rng.gen::<i64>();

            let ct = cks.encrypt_signed_radix(value, num_blocks);
            let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams);

            let _ = clear_store.insert(key, value);
            gpu_kv_store.insert(key, d_ct);
        }

        assert_store_signed_matches(&clear_store, &gpu_kv_store, &cks);

        // Validates the flow GPU -> CPU -> Compress -> Decompress -> CPU -> GPU
        let kv_store: KVStore<u32, SignedRadixCiphertext> = gpu_kv_store.to_kv_store(&streams);
        let compressed = kv_store.compress(&compression_key);
        let kv_store = compressed.decompress(&decompression_key).unwrap();
        let gpu_kv_store = CudaKVStore::from_kv_store(&kv_store, &streams);

        assert_store_signed_matches(&clear_store, &gpu_kv_store, &cks);

        // Validates the flow GPU -> CPU -> Serialize -> Deserialize -> CPU -> GPU
        let mut data = vec![];
        crate::safe_serialization::safe_serialize(&compressed, &mut data, 1 << 20).unwrap();
        let compressed: CompressedKVStore<u32, SignedRadixCiphertext> =
            crate::safe_serialization::safe_deserialize(data.as_slice(), 1 << 20).unwrap();
        let kv_store = compressed.decompress(&decompression_key).unwrap();
        let gpu_kv_store = CudaKVStore::from_kv_store(&kv_store, &streams);
        assert_store_signed_matches(&clear_store, &gpu_kv_store, &cks);
    }

    #[test]
    fn test_kv_store_get() {
        let params =
            TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();
        let (cks, _) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

        let streams = CudaStreams::new_multi_gpu();
        let sks = CudaServerKey::new(&cks, &streams);
        streams.synchronize();

        let num_value_blocks = 4;
        let num_key_blocks = 4; // u8 key with message_modulus=4 => 8/2 = 4 blocks
        let modulus = 1u64 << (2 * num_value_blocks); // 2 bits per block

        let clear_entries: Vec<(u8, u64)> =
            vec![(1, 10), (2, 42), (3, 100), (5, 200), (7, modulus - 1)];

        // Builds a KVStore
        let mut gpu_kv_store: CudaKVStore<u8, CudaUnsignedRadixCiphertext> = CudaKVStore::new();
        for &(key, value) in &clear_entries {
            let ct = cks.encrypt_radix(value, num_value_blocks);
            let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
            gpu_kv_store.insert(key, d_ct);
        }

        // Verify each stored entry is really there
        for &(key, expected_value) in &clear_entries {
            let encrypted_key = cks.encrypt_radix(key as u64, num_key_blocks);
            let d_encrypted_key =
                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&encrypted_key, &streams);

            let (result, found_bool) = sks.kv_store_get(&gpu_kv_store, &d_encrypted_key, &streams);

            let cpu_result = result.to_radix_ciphertext(&streams);
            let decrypted: u64 = cks.decrypt_radix(&cpu_result);
            let found = cks.decrypt_bool(&found_bool.to_boolean_block(&streams));

            assert!(found, "Key {key} should be found in the store");
            assert_eq!(
                decrypted, expected_value,
                "Key {key}: expected {expected_value}, got {decrypted}"
            );
        }

        // Verify non-stored entries are really *NOT* there
        let missing_key = 4u8;
        let encrypted_key = cks.encrypt_radix(missing_key as u64, num_key_blocks);
        let d_encrypted_key =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&encrypted_key, &streams);

        let (result, found_bool) = sks.kv_store_get(&gpu_kv_store, &d_encrypted_key, &streams);

        let cpu_result = result.to_radix_ciphertext(&streams);
        let decrypted: u64 = cks.decrypt_radix(&cpu_result);
        let found = cks.decrypt_bool(&found_bool.to_boolean_block(&streams));

        assert!(!found, "Key {missing_key} should not be found in the store");
        assert_eq!(decrypted, 0, "Missing key should return 0");

        // Checks what happens with an empty store
        let empty_store: CudaKVStore<u8, CudaUnsignedRadixCiphertext> = CudaKVStore::new();
        let encrypted_key = cks.encrypt_radix(1u64, num_key_blocks);
        let d_encrypted_key =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&encrypted_key, &streams);

        let (result, found_bool, _selectors) =
            sks.kv_store_get_impl(&empty_store, &d_encrypted_key, &streams);

        let cpu_result = result.to_radix_ciphertext(&streams);
        let decrypted: u64 = cks.decrypt_radix(&cpu_result);
        let found = cks.decrypt_bool(&found_bool.to_boolean_block(&streams));

        assert!(!found, "Empty store should not find any key");
        assert_eq!(decrypted, 0, "Empty store should return 0");
    }

    #[test]
    fn test_kv_store_contains_key() {
        let params =
            TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();
        let (cks, _) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

        let streams = CudaStreams::new_multi_gpu();
        let sks = CudaServerKey::new(&cks, &streams);
        streams.synchronize();

        let num_value_blocks = 4;
        let num_key_blocks = 4;

        let clear_entries: Vec<(u8, u64)> = vec![(1, 10), (2, 42), (3, 100), (5, 200)];

        let mut gpu_kv_store: CudaKVStore<u8, CudaUnsignedRadixCiphertext> = CudaKVStore::new();
        for &(key, value) in &clear_entries {
            let ct = cks.encrypt_radix(value, num_value_blocks);
            let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
            gpu_kv_store.insert(key, d_ct);
        }

        // Keys that are in the store must return true
        for &(key, _) in &clear_entries {
            let encrypted_key = cks.encrypt_radix(key as u64, num_key_blocks);
            let d_encrypted_key =
                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&encrypted_key, &streams);

            let result_bool = sks.kv_store_contains_key(&gpu_kv_store, &d_encrypted_key, &streams);
            let found = cks.decrypt_bool(&result_bool.to_boolean_block(&streams));
            assert!(found, "Key {key} should be found in the store");
        }

        // A key that is not in the store must return false
        let missing_key = 4u8;
        let encrypted_key = cks.encrypt_radix(missing_key as u64, num_key_blocks);
        let d_encrypted_key =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&encrypted_key, &streams);

        let result_bool = sks.kv_store_contains_key(&gpu_kv_store, &d_encrypted_key, &streams);
        let found = cks.decrypt_bool(&result_bool.to_boolean_block(&streams));
        assert!(!found, "Key {missing_key} should not be found in the store");

        // An empty store must always return false
        let empty_store: CudaKVStore<u8, CudaUnsignedRadixCiphertext> = CudaKVStore::new();
        let encrypted_key = cks.encrypt_radix(1u64, num_key_blocks);
        let d_encrypted_key =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&encrypted_key, &streams);

        let result_bool = sks.kv_store_contains_key(&empty_store, &d_encrypted_key, &streams);
        let found = cks.decrypt_bool(&result_bool.to_boolean_block(&streams));
        assert!(!found, "Empty store should not find any key");
    }

    #[test]
    fn test_kv_store_contains_value() {
        let params =
            TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();
        let (cks, _) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

        let streams = CudaStreams::new_multi_gpu();
        let sks = CudaServerKey::new(&cks, &streams);
        streams.synchronize();

        let num_value_blocks = 4;

        let clear_entries: Vec<(u8, u64)> = vec![(1, 10), (2, 42), (3, 100), (5, 200)];

        let mut gpu_kv_store: CudaKVStore<u8, CudaUnsignedRadixCiphertext> = CudaKVStore::new();
        for &(key, value) in &clear_entries {
            let ct = cks.encrypt_radix(value, num_value_blocks);
            let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
            gpu_kv_store.insert(key, d_ct);
        }

        // Values that are in the store must return true
        for &(_, value) in &clear_entries {
            let encrypted_value = cks.encrypt_radix(value, num_value_blocks);
            let d_encrypted_value =
                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&encrypted_value, &streams);

            let result_bool =
                sks.kv_store_contains_value(&gpu_kv_store, &d_encrypted_value, &streams);
            let found = cks.decrypt_bool(&result_bool.to_boolean_block(&streams));
            assert!(found, "Value {value} should be found in the store");
        }

        // A value that is not in the store must return false
        let missing_value = 99u64;
        let encrypted_value = cks.encrypt_radix(missing_value, num_value_blocks);
        let d_encrypted_value =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&encrypted_value, &streams);

        let result_bool = sks.kv_store_contains_value(&gpu_kv_store, &d_encrypted_value, &streams);
        let found = cks.decrypt_bool(&result_bool.to_boolean_block(&streams));
        assert!(
            !found,
            "Value {missing_value} should not be found in the store"
        );
    }

    #[test]
    fn test_kv_store_contains_clear_value() {
        let params =
            TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();
        let (cks, _) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

        let streams = CudaStreams::new_multi_gpu();
        let sks = CudaServerKey::new(&cks, &streams);
        streams.synchronize();

        let num_value_blocks = 4;

        let clear_entries: Vec<(u8, u64)> = vec![(1, 10), (2, 42), (3, 100), (5, 200)];

        let mut gpu_kv_store: CudaKVStore<u8, CudaUnsignedRadixCiphertext> = CudaKVStore::new();
        for &(key, value) in &clear_entries {
            let ct = cks.encrypt_radix(value, num_value_blocks);
            let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
            gpu_kv_store.insert(key, d_ct);
        }

        // Clear values that are in the store must return true
        for &(_, value) in &clear_entries {
            let result_bool = sks.kv_store_contains_clear_value(&gpu_kv_store, value, &streams);
            let found = cks.decrypt_bool(&result_bool.to_boolean_block(&streams));
            assert!(found, "Clear value {value} should be found in the store");
        }

        // A clear value that is not in the store must return false
        let missing_value = 99u64;
        let result_bool = sks.kv_store_contains_clear_value(&gpu_kv_store, missing_value, &streams);
        let found = cks.decrypt_bool(&result_bool.to_boolean_block(&streams));
        assert!(
            !found,
            "Clear value {missing_value} should not be found in the store"
        );
    }

    #[test]
    fn test_kv_store_map() {
        // It's not possible to test kv_store_map using the generic test templates, so we use this
        // test
        let params =
            TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();
        let (cks, _) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

        let streams = CudaStreams::new_multi_gpu();
        let sks = CudaServerKey::new(&cks, &streams);
        streams.synchronize();

        let num_value_blocks = 4;
        let num_key_blocks = 4; // u8 key with message_modulus=4 => 8/2 = 4 blocks
        let modulus = 1u64 << (2 * num_value_blocks); // 2 bits per block

        let clear_entries: Vec<(u8, u64)> =
            vec![(1, 10), (2, 42), (3, 100), (5, 200), (7, modulus - 1)];

        // Builds a KVStore
        let mut gpu_kv_store: CudaKVStore<u8, CudaUnsignedRadixCiphertext> = CudaKVStore::new();
        for &(key, value) in &clear_entries {
            let ct = cks.encrypt_radix(value, num_value_blocks);
            let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
            gpu_kv_store.insert(key, d_ct);
        }

        // Updates a value and checks if it was really updated
        let key: u64 = 2;
        let s: u64 = 10;
        let f = |ct: CudaUnsignedRadixCiphertext| sks.scalar_mul(&ct, s, &streams);

        let encrypted_key = cks.encrypt_radix(key, num_key_blocks);
        let d_encrypted_key =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&encrypted_key, &streams);

        sks.kv_store_map(&mut gpu_kv_store, &d_encrypted_key, f, &streams);
    }
}
