use crate::integer::backward_compatibility::ciphertext::CompressedKVStoreVersions;
use crate::integer::block_decomposition::{Decomposable, DecomposableInto};
use crate::integer::ciphertext::{
    CompressedCiphertextList, CompressedCiphertextListBuilder, Compressible, Expandable,
};
use crate::integer::compression_keys::{CompressionKey, DecompressionKey};
use crate::integer::prelude::ServerKeyDefaultCMux;
use crate::integer::{BooleanBlock, IntegerRadixCiphertext, ServerKey};
use crate::prelude::CastInto;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::num::NonZeroUsize;
use tfhe_versionable::Versionize;

/// The KVStore is a specialized encrypted HashMap
///
/// * Keys are clear numbers
/// * Values are RadixCiphertext or SignedRadixCiphertext
///
/// It supports getting/modifying existing pairs of (key,value)
/// using an encrypted key.
///
///
/// To serialize a KVStore it must first be compressed with [KVStore::compress]
pub struct KVStore<Key, Ct> {
    data: HashMap<Key, Ct>,
    block_count: Option<NonZeroUsize>,
}

impl<Key, Ct> KVStore<Key, Ct> {
    /// Creates an empty KVStore
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            block_count: None,
        }
    }

    /// Returns the value stored for the key if any
    ///
    /// Key is in clear, see [ServerKey::kv_store_get] if you wish to
    /// query using an encrypted key
    pub fn get(&self, key: &Key) -> Option<&Ct>
    where
        Key: Eq + Hash,
    {
        self.data.get(key)
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
        Key: PartialEq + Eq + Hash,
        Ct: IntegerRadixCiphertext,
    {
        let n_blocks = value.blocks().len();
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

    /// Returns the number of key-value pairs currently stored
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns whether the store is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Key, &Ct)>
    where
        Key: Eq + Hash + Sync,
        Ct: Send,
    {
        self.data.iter()
    }

    fn par_iter_keys(&self) -> impl ParallelIterator<Item = &Key>
    where
        Key: Send + Sync + Hash + Eq,
        Ct: Send + Sync,
    {
        self.data.par_iter().map(|(k, _)| k)
    }
}

impl<Key, Ct> Default for KVStore<Key, Ct>
where
    Self: Sized,
{
    fn default() -> Self {
        Self::new()
    }
}

impl ServerKey {
    /// Internal function used to perform a binary operation
    /// on an entry.
    ///
    /// `encrypted_key`: The key of the slot
    /// `func`: function that receives to arguments:
    ///     * A boolean block that encrypts `true` if the corresponding key is the same as the
    ///       `encrypted_key`
    ///     * a `& mut` to the ciphertext which stores the value
    fn kv_store_binary_op_to_slot<Key, Ct, F>(
        &self,
        map: &mut KVStore<Key, Ct>,
        encrypted_key: &Ct,
        func: F,
    ) where
        Ct: IntegerRadixCiphertext,
        Key: Decomposable + CastInto<usize> + Hash + Eq,
        F: Fn(&BooleanBlock, &mut Ct) + Sync + Send,
    {
        let kv_vec: Vec<(&Key, &mut Ct)> = map.data.iter_mut().collect();

        // For each clear key, get a boolean ciphertext that tells if it's
        // equal to the encrypted key
        let selectors =
            self.compute_equality_selectors(encrypted_key, kv_vec.par_iter().map(|(k, _v)| **k));

        kv_vec
            .into_par_iter()
            .zip(selectors.par_iter())
            .for_each(|((_k, current_ct), selector)| func(selector, current_ct));
    }

    /// Performs an addition on an entry of the store
    ///
    /// `map[encrypted_key] += value`
    ///
    /// This finds the value that corresponds to the given `encrypted_key `
    /// and adds `value` to it.
    pub fn kv_store_add_to_slot<Key, Ct>(
        &self,
        map: &mut KVStore<Key, Ct>,
        encrypted_key: &Ct,
        value: &Ct,
    ) where
        Ct: IntegerRadixCiphertext,
        Key: Decomposable + CastInto<usize> + Hash + Eq,
    {
        self.kv_store_binary_op_to_slot(map, encrypted_key, |selector, v| {
            let mut ct_to_add = value.clone();
            self.zero_out_if_condition_is_false(&mut ct_to_add, &selector.0);
            self.add_assign_parallelized(v, &ct_to_add);
        });
    }

    /// Performs an addition by a clear on an entry of the store
    ///
    /// `map[encrypted_key] += value`
    ///
    /// This finds the value that corresponds to the given `encrypted_key `
    /// and adds `value` to it.
    pub fn kv_store_scalar_add_to_slot<Key, Ct, Clear>(
        &self,
        map: &mut KVStore<Key, Ct>,
        encrypted_key: &Ct,
        value: Clear,
    ) where
        Ct: IntegerRadixCiphertext,
        Key: Decomposable + CastInto<usize> + Hash + Eq,
        Clear: DecomposableInto<u64>,
    {
        self.kv_store_binary_op_to_slot(map, encrypted_key, |selector, v| {
            let ct_to_add =
                self.scalar_cmux_parallelized(selector, value, Clear::ZERO, v.blocks().len());
            self.add_assign_parallelized(v, &ct_to_add);
        });
    }

    /// Performs a subtraction on an entry of the store
    ///
    /// `map[encrypted_key] -= value`
    ///
    /// This finds the value that corresponds to the given `encrypted_key`,
    /// and subtracts `value` to it.
    pub fn kv_store_sub_to_slot<Key, Ct>(
        &self,
        map: &mut KVStore<Key, Ct>,
        encrypted_key: &Ct,
        value: &Ct,
    ) where
        Ct: IntegerRadixCiphertext,
        Key: Decomposable + CastInto<usize> + Hash + Eq,
    {
        self.kv_store_binary_op_to_slot(map, encrypted_key, |selector, v| {
            let mut ct_to_sub = value.clone();
            self.zero_out_if_condition_is_false(&mut ct_to_sub, &selector.0);
            self.sub_assign_parallelized(v, &ct_to_sub);
        });
    }

    /// Performs a multiplication on an entry of the store
    ///
    /// `map[encrypted_key] *= value`
    ///
    /// This finds the value that corresponds to the given `encrypted_key`,
    /// and multiplies it by `value`.
    pub fn kv_store_mul_to_slot<Key, Ct>(
        &self,
        map: &mut KVStore<Key, Ct>,
        encrypted_key: &Ct,
        value: &Ct,
    ) where
        Ct: IntegerRadixCiphertext,
        Key: Decomposable + CastInto<usize> + Hash + Eq,
        Self: for<'a> ServerKeyDefaultCMux<u64, &'a Ct, Output = Ct>,
    {
        self.kv_store_binary_op_to_slot(map, encrypted_key, |selector, v| {
            let selector = self.boolean_bitnot(selector);
            let ct_to_mul = self.if_then_else_parallelized(&selector, 1u64, value);
            self.mul_assign_parallelized(v, &ct_to_mul);
        });
    }

    /// Implementation of the get function that additionally returns the Vec of selectors
    /// so it can be reused to avoid re-computing it.
    fn kv_store_get_impl<Key, Ct>(
        &self,
        map: &KVStore<Key, Ct>,
        encrypted_key: &Ct,
    ) -> (Ct, BooleanBlock, Vec<BooleanBlock>)
    where
        Ct: IntegerRadixCiphertext,
        Key: Decomposable + CastInto<usize> + Hash + Eq,
    {
        let selectors =
            self.compute_equality_selectors(encrypted_key, map.par_iter_keys().copied());

        let (result, check_block) = rayon::join(
            || {
                let kv_vec: Vec<(&Key, &Ct)> = map.data.iter().collect();
                let one_hot = kv_vec
                    .into_par_iter()
                    .zip(selectors.par_iter())
                    .map(|((_, v), s)| {
                        let mut result = v.clone();
                        self.zero_out_if_condition_is_false(&mut result, &s.0);
                        result
                    })
                    .collect::<Vec<_>>();

                self.aggregate_one_hot_vector(one_hot)
            },
            || {
                let selectors = selectors.iter().map(|s| s.0.clone()).collect::<Vec<_>>();
                BooleanBlock::new_unchecked(self.is_at_least_one_comparisons_block_true(selectors))
            },
        );

        (result, check_block, selectors)
    }

    /// Returns the value at the given key
    ///
    /// `return map[encrypted_key]`
    ///
    /// This finds the value that corresponds to the given `encrypted_key`,
    /// and returns it.
    /// It also returns a boolean block that encrypts `true` if an entry for
    /// the `encrypted_key` was found.
    ///
    /// If the key was not found, the returned value is an encryption of zero
    pub fn kv_store_get<Key, Ct>(
        &self,
        map: &KVStore<Key, Ct>,
        encrypted_key: &Ct,
    ) -> (Ct, BooleanBlock)
    where
        Ct: IntegerRadixCiphertext,
        Key: Decomposable + CastInto<usize> + Hash + Eq,
    {
        let (result, check_block, _selectors) = self.kv_store_get_impl(map, encrypted_key);
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
        map: &mut KVStore<Key, Ct>,
        encrypted_key: &Ct,
        new_value: &Ct,
    ) -> BooleanBlock
    where
        Ct: IntegerRadixCiphertext,
        Key: Decomposable + CastInto<usize> + Hash + Eq,
    {
        let selectors =
            self.compute_equality_selectors(encrypted_key, map.par_iter_keys().copied());

        rayon::join(
            || {
                let kv_vec: Vec<(&Key, &mut Ct)> = map.data.iter_mut().collect();
                kv_vec
                    .into_par_iter()
                    .zip(selectors.par_iter())
                    .for_each(|((_, old_value), s)| {
                        *old_value = self.if_then_else_parallelized(s, new_value, old_value);
                    });
            },
            || {
                let selectors = selectors.iter().map(|s| s.0.clone()).collect::<Vec<_>>();
                BooleanBlock::new_unchecked(self.is_at_least_one_comparisons_block_true(selectors))
            },
        )
        .1
    }

    /// Updates the value at the given key by applying a function
    ///
    /// `map[encrypted_key] = func(map[encrypted_value])`
    ///
    /// This finds the value that corresponds to the given `encrypted_key`, then
    /// calls `func` then updates the value stored with the one returned by the `func`.
    ///
    /// Returns the new value and a boolean block that encrypts `true` if an entry for
    /// the `encrypted_key` was found.
    pub fn kv_store_map<Key, Ct, F>(
        &self,
        map: &mut KVStore<Key, Ct>,
        encrypted_key: &Ct,
        func: F,
    ) -> (Ct, BooleanBlock)
    where
        Ct: IntegerRadixCiphertext,
        Key: Decomposable + CastInto<usize> + Hash + Eq,
        F: Fn(Ct) -> Ct,
    {
        let (result, check_block, selectors) = self.kv_store_get_impl(map, encrypted_key);
        let new_value = func(result);

        let kv_vec: Vec<(&Key, &mut Ct)> = map.data.iter_mut().collect();
        kv_vec
            .into_par_iter()
            .zip(selectors.par_iter())
            .for_each(|((_, old_value), s)| {
                *old_value = self.if_then_else_parallelized(s, &new_value, old_value);
            });

        (new_value, check_block)
    }
}

impl<Key, Ct> KVStore<Key, Ct>
where
    Key: Copy,
    Ct: Compressible + Clone,
{
    /// Compress the KVStore to be able to serialize it
    pub fn compress(&self, compression_key: &CompressionKey) -> CompressedKVStore<Key> {
        let mut builder = CompressedCiphertextListBuilder::new();
        let mut keys = Vec::with_capacity(self.data.len());
        for (key, value) in self.data.iter() {
            keys.push(*key);
            builder.push(value.clone());
        }

        let values = builder.build(compression_key);

        CompressedKVStore { keys, values }
    }
}

/// Compressed KVStore
///
/// This type is the serializable and deserializable form of a KVStore
#[derive(Serialize, Deserialize, Versionize)]
#[versionize(CompressedKVStoreVersions)]
pub struct CompressedKVStore<Key> {
    keys: Vec<Key>,
    values: CompressedCiphertextList,
}

impl<Key> CompressedKVStore<Key>
where
    Key: Copy + Display + Eq + Hash,
{
    /// Decompressed the KVStore
    ///
    /// Returns an error if:
    /// * A key does not have a corresponding value
    /// * A value (which is a radix ciphertext) does not have the same number of blocks as the
    ///   others.
    ///
    /// Both these errors indicate corrupted or malformed data
    pub fn decompress<Ct>(
        &self,
        decompression_key: &DecompressionKey,
    ) -> crate::Result<KVStore<Key, Ct>>
    where
        Ct: Expandable + IntegerRadixCiphertext,
    {
        let mut block_count = None;
        let mut store = KVStore::new();
        for (i, key) in self.keys.iter().enumerate() {
            let value: Ct = self
                .values
                .get(i, decompression_key)?
                .ok_or_else(|| crate::error!("Missing value for key '{key}'"))?;

            let n = *block_count.get_or_insert_with(|| value.blocks().len());

            if n != value.blocks().len() {
                return Err(crate::error!(
                    "The value for key {key} does not have the same number \
                        of blocks as other values. {} instead of {n}",
                    value.blocks().len()
                ));
            }

            let _ = store.insert(*key, value);
        }

        Ok(store)
    }
}

macro_rules! impl_named_for_kv_store {
    ($Key:ty) => {
        impl crate::named::Named for CompressedKVStore<$Key> {
            const NAME: &'static str =
                concat!("integer::CompressedKVStore<", stringify!($Key), ">");
        }
    };
}

impl_named_for_kv_store!(u8);
impl_named_for_kv_store!(u16);
impl_named_for_kv_store!(u32);
impl_named_for_kv_store!(u64);
impl_named_for_kv_store!(u128);
impl_named_for_kv_store!(i8);
impl_named_for_kv_store!(i16);
impl_named_for_kv_store!(i32);
impl_named_for_kv_store!(i64);
impl_named_for_kv_store!(i128);

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;
    use crate::integer::{
        gen_keys, ClientKey, IntegerKeyKind, RadixCiphertext, SignedRadixCiphertext,
    };
    use crate::shortint::parameters::test_params::{
        TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::shortint::ShortintParameterSet;

    fn assert_store_unsigned_matches(
        clear_store: &HashMap<u32, u64>,
        kv_store: &KVStore<u32, RadixCiphertext>,
        cks: &ClientKey,
    ) {
        assert_eq!(
            clear_store.len(),
            kv_store.len(),
            "Clear and Encrypted stores do no have the same number of pairs"
        );

        for (key, value) in clear_store {
            let ct = kv_store
                .get(key)
                .expect("Missing entry in decompressed KVStore");

            let decrypted: u64 = cks.decrypt_radix(ct);
            assert_eq!(
                *value, decrypted,
                "Invalid value stored for key '{key}', expected '{value}' got '{decrypted}'"
            );
        }
    }

    #[test]
    fn test_compression_serialization_unsigned() {
        let params = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();

        let (cks, _) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

        let private_compression_key = cks
            .new_compression_private_key(TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

        let (compression_key, decompression_key) =
            cks.new_compression_decompression_keys(&private_compression_key);

        let num_blocks = 32;
        let num_keys = 100;

        let mut rng = rand::thread_rng();

        let mut clear_store = HashMap::new();
        let mut kv_store = KVStore::new();
        for _ in 0..num_keys {
            let key = rng.gen::<u32>();
            let value = rng.gen::<u64>();

            let ct = cks.encrypt_radix(value, num_blocks);

            let _ = clear_store.insert(key, value);
            kv_store.insert(key, ct);
        }

        assert_store_unsigned_matches(&clear_store, &kv_store, &cks);

        let compressed = kv_store.compress(&compression_key);
        let kv_store = compressed.decompress(&decompression_key).unwrap();
        assert_store_unsigned_matches(&clear_store, &kv_store, &cks);

        let mut data = vec![];
        crate::safe_serialization::safe_serialize(&compressed, &mut data, 1 << 20).unwrap();
        let compressed: CompressedKVStore<u32> =
            crate::safe_serialization::safe_deserialize(data.as_slice(), 1 << 20).unwrap();
        let kv_store = compressed.decompress(&decompression_key).unwrap();
        assert_store_unsigned_matches(&clear_store, &kv_store, &cks);
    }

    fn assert_store_signed_matches(
        clear_store: &HashMap<u32, i64>,
        kv_store: &KVStore<u32, SignedRadixCiphertext>,
        cks: &ClientKey,
    ) {
        assert_eq!(
            clear_store.len(),
            kv_store.len(),
            "Clear and Encrypted stores do no have the same number of pairs"
        );

        for (key, value) in clear_store {
            let ct = kv_store
                .get(key)
                .expect("Missing entry in decompressed KVStore");

            let decrypted: i64 = cks.decrypt_signed_radix(ct);
            assert_eq!(
                *value, decrypted,
                "Invalid value stored for key '{key}', expected '{value}' got '{decrypted}'"
            );
        }
    }

    #[test]
    fn test_compression_serialization_signed() {
        let params = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();

        let (cks, _) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

        let private_compression_key = cks
            .new_compression_private_key(TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

        let (compression_key, decompression_key) =
            cks.new_compression_decompression_keys(&private_compression_key);

        let num_blocks = 32;
        let num_keys = 100;

        let mut rng = rand::thread_rng();

        let mut clear_store = HashMap::new();
        let mut kv_store = KVStore::new();
        for _ in 0..num_keys {
            let key = rng.gen::<u32>();
            let value = rng.gen::<i64>();

            let ct = cks.encrypt_signed_radix(value, num_blocks);

            let _ = clear_store.insert(key, value);
            kv_store.insert(key, ct);
        }

        assert_store_signed_matches(&clear_store, &kv_store, &cks);

        let compressed = kv_store.compress(&compression_key);
        let kv_store = compressed.decompress(&decompression_key).unwrap();
        assert_store_signed_matches(&clear_store, &kv_store, &cks);

        let mut data = vec![];
        crate::safe_serialization::safe_serialize(&compressed, &mut data, 1 << 20).unwrap();
        let compressed: CompressedKVStore<u32> =
            crate::safe_serialization::safe_deserialize(data.as_slice(), 1 << 20).unwrap();
        let kv_store = compressed.decompress(&decompression_key).unwrap();
        assert_store_signed_matches(&clear_store, &kv_store, &cks);
    }
}
