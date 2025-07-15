use crate::integer::block_decomposition::{Decomposable, DecomposableInto};
use crate::integer::prelude::ServerKeyDefaultCMux;
use crate::integer::{BooleanBlock, IntegerRadixCiphertext, ServerKey};
use crate::prelude::CastInto;
use rayon::prelude::*;
use std::collections::HashMap;
use std::hash::Hash;
use std::num::NonZeroUsize;

pub struct KVStore<Key, Ct> {
    data: HashMap<Key, Ct>,
    block_count: Option<NonZeroUsize>,
}

impl<Key, Ct> KVStore<Key, Ct> {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            block_count: None,
        }
    }

    pub fn get(&self, key: &Key) -> Option<&Ct>
    where
        Key: Eq + Hash,
    {
        self.data.get(key)
    }

    pub fn insert(&mut self, key: Key, value: Ct) -> Option<Ct>
    where
        Key: PartialEq + Ord + Eq + Hash,
        Ct: IntegerRadixCiphertext,
    {
        let n_blocks = value.blocks().len();
        assert_ne!(n_blocks, 0, "Cannot insert an empty ciphertext");
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

    pub fn len(&self) -> usize {
        self.data.len()
    }

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
