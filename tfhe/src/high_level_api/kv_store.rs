use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::backward_compatibility::kv_store::CompressedKVStoreVersions;
use crate::high_level_api::global_state;
use crate::high_level_api::integers::FheIntegerType;
use crate::high_level_api::keys::InternalServerKey;
use crate::integer::block_decomposition::Decomposable;
use crate::integer::ciphertext::{Compressible, Expandable};
use crate::integer::server_key::{
    CompressedKVStore as CompressedIntegerKVStore, KVStore as IntegerKVStore,
};
use crate::prelude::CastInto;
use crate::{FheBool, IntegerId, ReRandomizationMetadata, Tag};
use std::fmt::Display;

#[derive(Clone)]
enum InnerKVStore<Key, T>
where
    T: FheIntegerType,
{
    Cpu(IntegerKVStore<Key, <T::Id as IntegerId>::InnerCpu>),
}

/// The KVStore is a specialized encrypted HashMap
///
/// * Keys are clear numbers
/// * Values are FheInt or FheUint
///
/// This stores allows to insert, removed, get using clear keys.
/// It also allows to do some operations using encrypted keys.
///
/// To serialize a KVStore it must first be compressed with [KVStore::compress]
///
/// # Tag System
///
/// Ciphertexts inserted into the KVStore will drop their tag.
/// Operations on the KVStore that return a ciphertext will set a tag
/// using the currently set server key.
/// Even operations that do not require FHE operations will require
/// a server key to be set in order to set the tag
#[derive(Clone)]
pub struct KVStore<Key, T>
where
    T: FheIntegerType,
{
    inner: InnerKVStore<Key, T>,
}

impl<Key, T> KVStore<Key, T>
where
    T: FheIntegerType,
{
    /// Creates a new empty `KVStore`.
    pub fn new() -> Self {
        Self {
            inner: InnerKVStore::Cpu(IntegerKVStore::new()),
        }
    }

    /// Returns the number of key-value pairs in the store.
    pub fn len(&self) -> usize {
        match &self.inner {
            InnerKVStore::Cpu(kvstore) => kvstore.len(),
        }
    }

    /// Returns `true` if the store contains no key-value pairs
    pub fn is_empty(&self) -> bool {
        match &self.inner {
            InnerKVStore::Cpu(kvstore) => kvstore.is_empty(),
        }
    }

    /// Inserts a key-value pair.
    ///
    /// Returns the old value if there was any
    pub fn insert_with_clear_key(&mut self, key: Key, value: T) -> Option<T>
    where
        Key: Ord,
    {
        #[allow(unreachable_patterns)]
        global_state::with_internal_keys(|server_key| match (server_key, &mut self.inner) {
            (InternalServerKey::Cpu(cpu_key), InnerKVStore::Cpu(inner_store)) => {
                let inner = inner_store.insert(key, value.into_cpu())?;
                Some(T::from_cpu(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                ))
            }
            #[cfg(feature = "gpu")]
            (InternalServerKey::Cuda(_cuda_key), _) => {
                panic!("GPU does not support KVStore yet")
            }
            #[cfg(feature = "hpu")]
            (InternalServerKey::Hpu(_device), _) => {
                panic!("HPU does not support KVStore yet")
            }
            _ => panic!("The KVStore's current backend does not match the current key backend"),
        })
    }

    /// Updates the value in a key-value pair.
    ///
    /// Returns the old value if there was any
    /// Returns None if the key had no previous value
    ///
    /// If your key is encrypted see [Self::update]
    ///
    ///
    /// # Note
    ///
    /// Contraty to [Self::insert_with_clear_key], this does not insert the key,value pair
    /// if its not present
    pub fn update_with_clear_key(&mut self, key: &Key, value: T) -> Option<T>
    where
        Key: Ord,
    {
        #[allow(unreachable_patterns)]
        global_state::with_internal_keys(|server_key| match (server_key, &mut self.inner) {
            (InternalServerKey::Cpu(cpu_key), InnerKVStore::Cpu(inner_store)) => {
                inner_store.get_mut(key).map_or_else(
                    || None,
                    |old_value_ref| {
                        let old_value = std::mem::replace(old_value_ref, value.into_cpu());
                        Some(T::from_cpu(
                            old_value,
                            cpu_key.tag.clone(),
                            ReRandomizationMetadata::default(),
                        ))
                    },
                )
            }
            #[cfg(feature = "gpu")]
            (InternalServerKey::Cuda(_cuda_key), _) => {
                panic!("GPU does not support KVStore yet")
            }
            #[cfg(feature = "hpu")]
            (InternalServerKey::Hpu(_device), _) => {
                panic!("HPU does not support KVStore yet")
            }
            _ => panic!("The KVStore's current backend does not match the current key backend"),
        })
    }

    /// Removes a key-value pair.
    ///
    /// Returns Some(_) if the key was present, None otherwise
    ///
    /// # Note
    ///
    /// Even though no FHE computations are done, a server key must
    /// be set when calling this function is order to set the Tag of the resulting ciphertext
    pub fn remove_with_clear_key(&mut self, key: &Key) -> Option<T>
    where
        Key: Ord,
    {
        #[allow(unreachable_patterns)]
        global_state::with_internal_keys(|server_key| match (server_key, &mut self.inner) {
            (InternalServerKey::Cpu(cpu_key), InnerKVStore::Cpu(inner_store)) => {
                let inner = inner_store.remove(key)?;
                Some(T::from_cpu(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                ))
            }
            #[cfg(feature = "gpu")]
            (InternalServerKey::Cuda(_cuda_key), _) => {
                panic!("GPU does not support KVStore yet")
            }
            #[cfg(feature = "hpu")]
            (InternalServerKey::Hpu(_device), _) => {
                panic!("HPU does not support KVStore yet")
            }
            _ => panic!("The KVStore's current backend does not match the current key backend"),
        })
    }

    /// Returns the value associated to a key.
    ///
    /// Returns Some(_) if the key was present, None otherwise
    ///
    /// If your key is encrypted see [Self::get]
    ///
    /// # Note
    ///
    /// Even though no FHE computations are done, a server key must
    /// be set when calling this function is order to set the Tag of the resulting ciphertext
    pub fn get_with_clear_key(&self, key: &Key) -> Option<T>
    where
        Key: Ord,
    {
        #[allow(unreachable_patterns)]
        global_state::with_internal_keys(|server_key| match (server_key, &self.inner) {
            (InternalServerKey::Cpu(cpu_key), InnerKVStore::Cpu(inner_store)) => {
                let inner = inner_store.get(key)?;
                Some(T::from_cpu(
                    inner.clone(),
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                ))
            }
            #[cfg(feature = "gpu")]
            (InternalServerKey::Cuda(_cuda_key), _) => {
                panic!("GPU does not support KVStore yet")
            }
            #[cfg(feature = "hpu")]
            (InternalServerKey::Hpu(_device), _) => {
                panic!("HPU does not support KVStore yet")
            }
            _ => panic!("The KVStore's current backend does not match the current key backend"),
        })
    }
}

impl<Key, T> Default for KVStore<Key, T>
where
    T: FheIntegerType,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Key, T> KVStore<Key, T>
where
    Key: Decomposable + CastInto<usize> + Ord,
    T: FheIntegerType,
{
    /// Gets the value corresponding to the encrypted key.
    ///
    /// Returns the encrypted value and an encrypted boolean.
    /// The boolean is an encryption of true if the key was present,
    /// thus the value is meaningful.
    ///
    /// If your key is clear see [Self::get_with_clear_key]
    pub fn get<EK>(&self, encrypted_key: &EK) -> (T, FheBool)
    where
        EK: FheIntegerType,
        EK::Id: IntegerId<
            InnerCpu = <T::Id as IntegerId>::InnerCpu,
            InnerGpu = <T::Id as IntegerId>::InnerGpu,
        >,
    {
        #[allow(unreachable_patterns)]
        global_state::with_internal_keys(|key| match (key, &self.inner) {
            (InternalServerKey::Cpu(cpu_key), InnerKVStore::Cpu(inner_store)) => {
                let (inner_ct, inner_bool) = cpu_key
                    .pbs_key()
                    .kv_store_get(inner_store, &*encrypted_key.on_cpu());
                (
                    T::from_cpu(
                        inner_ct,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                    FheBool::new(
                        inner_bool,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                )
            }
            #[cfg(feature = "gpu")]
            (InternalServerKey::Cuda(_cuda_key), _) => {
                panic!("GPU does not support KVStore yet")
            }
            #[cfg(feature = "hpu")]
            (InternalServerKey::Hpu(_device), _) => {
                panic!("HPU does not support KVStore yet")
            }
            _ => panic!("The KVStore's current backend does not match the current key backend"),
        })
    }

    /// Replaces the value corresponding to the encrypted key.
    ///
    /// i.e. `kvstore[encrypted_value] = new_value`
    ///
    /// The boolean is an encryption of true if the key was present,
    /// thus the value is was replaced.
    ///
    /// If your key is clear see [Self::update_with_clear_key]
    pub fn update<EK>(&mut self, encrypted_key: &EK, new_value: &T) -> FheBool
    where
        EK: FheIntegerType,
        EK::Id: IntegerId<
            InnerCpu = <T::Id as IntegerId>::InnerCpu,
            InnerGpu = <T::Id as IntegerId>::InnerGpu,
        >,
    {
        #[allow(unreachable_patterns)]
        global_state::with_internal_keys(|key| match (key, &mut self.inner) {
            (InternalServerKey::Cpu(cpu_key), InnerKVStore::Cpu(inner_store)) => {
                let inner = cpu_key.pbs_key().kv_store_update(
                    inner_store,
                    &*encrypted_key.on_cpu(),
                    &*new_value.on_cpu(),
                );
                FheBool::new(
                    inner,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            (InternalServerKey::Cuda(_cuda_key), _) => {
                panic!("GPU does not support KVStore yet")
            }
            #[cfg(feature = "hpu")]
            (InternalServerKey::Hpu(_device), _) => {
                panic!("HPU does not support KVStore yet")
            }
            _ => panic!("The KVStore's current backend does not match the current key backend"),
        })
    }

    /// Replaces the value corresponding to the encrypted key, with the
    /// result of applying the function to the current value.
    ///
    /// i.e. `kvstore[encrypted_value] = func(kvstore[encrypted_value])`
    ///
    /// Returns (old_value, new_value, check)
    ///
    /// The `check` boolean is an encryption of true if the key was present,
    /// thus the value is was replaced.
    pub fn map<EK, F>(&mut self, encrypted_key: &EK, func: F) -> (T, T, FheBool)
    where
        EK: FheIntegerType,
        EK::Id: IntegerId<
            InnerCpu = <T::Id as IntegerId>::InnerCpu,
            InnerGpu = <T::Id as IntegerId>::InnerGpu,
        >,
        F: Fn(T) -> T,
    {
        #[allow(unreachable_patterns)]
        global_state::with_internal_keys(|key| match (key, &mut self.inner) {
            (InternalServerKey::Cpu(cpu_key), InnerKVStore::Cpu(inner_store)) => {
                let (inner_old, inner_new, inner_bool) = cpu_key.pbs_key().kv_store_map(
                    inner_store,
                    &*encrypted_key.on_cpu(),
                    |radix| {
                        let wrapped =
                            T::from_cpu(radix, Tag::default(), ReRandomizationMetadata::default());
                        let wrapped_result = func(wrapped);
                        wrapped_result.into_cpu()
                    },
                );
                (
                    T::from_cpu(
                        inner_old,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                    T::from_cpu(
                        inner_new,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                    FheBool::new(
                        inner_bool,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                )
            }
            #[cfg(feature = "gpu")]
            (InternalServerKey::Cuda(_cuda_key), _) => {
                panic!("GPU does not support KVStore yet")
            }
            #[cfg(feature = "hpu")]
            (InternalServerKey::Hpu(_device), _) => {
                panic!("HPU does not support KVStore yet")
            }
            _ => panic!("The KVStore's current backend does not match the current key backend"),
        })
    }

    /// Compressed the KVStore, making it serializable
    pub fn compress(&self) -> crate::Result<CompressedKVStore<Key, T>>
    where
        Key: Copy + Display + Ord,
        <T::Id as IntegerId>::InnerCpu: Compressible + Clone,
    {
        #[allow(unreachable_patterns)]
        global_state::with_internal_keys(|key| match (key, &self.inner) {
            (InternalServerKey::Cpu(cpu_key), InnerKVStore::Cpu(inner_store)) => {
                let comp_key = cpu_key
                    .key
                    .compression_key
                    .as_ref()
                    .ok_or(crate::high_level_api::errors::UninitializedCompressionKey)?;
                let compressed_inner = inner_store.compress(comp_key);
                Ok(CompressedKVStore {
                    inner: compressed_inner,
                })
            }
            #[cfg(feature = "gpu")]
            (InternalServerKey::Cuda(_cuda_key), _) => {
                panic!("GPU does not support KVStore yet")
            }
            #[cfg(feature = "hpu")]
            (InternalServerKey::Hpu(_device), _) => {
                panic!("HPU does not support KVStore yet")
            }
            _ => panic!("The KVStore's current backend does not match the current key backend"),
        })
    }
}

/// Compressed KVStore
///
/// This type is the serializable and deserializable form of a KVStore
#[derive(Serialize, Deserialize, Versionize)]
#[versionize(CompressedKVStoreVersions)]
pub struct CompressedKVStore<Key, Value>
where
    Value: FheIntegerType,
{
    inner: CompressedIntegerKVStore<Key, <Value::Id as IntegerId>::InnerCpu>,
}

macro_rules! impl_named_for_kv_store {
    ($Key:ty) => {
        impl<Id> crate::named::Named for CompressedKVStore<$Key, crate::high_level_api::FheUint<Id>>
        where
            Id: crate::high_level_api::FheUintId,
        {
            const NAME: &'static str = concat!(
                "high_level_api::CompressedKVStore<",
                stringify!($Key),
                ", high_level_api::FheUint>"
            );
        }

        impl<Id> crate::named::Named for CompressedKVStore<$Key, crate::high_level_api::FheInt<Id>>
        where
            Id: crate::high_level_api::FheIntId,
        {
            const NAME: &'static str = concat!(
                "high_level_api::CompressedKVStore<",
                stringify!($Key),
                ", high_level_api::FheInt>"
            );
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

impl<Key, Value> CompressedKVStore<Key, Value>
where
    Value: FheIntegerType,
{
    /// Decompressed the KVStore
    ///
    /// Returns an error if:
    /// * A key does not have a corresponding value
    /// * A value does not have the same number of blocks as the others.
    /// * If the requested value type is not compatible with the data stored
    ///
    /// Both these errors indicate corrupted or malformed data
    pub fn decompress(&self) -> crate::Result<KVStore<Key, Value>>
    where
        <Value::Id as IntegerId>::InnerCpu: Expandable,
        Key: Copy + Display + Ord,
    {
        global_state::try_with_internal_keys(|key| match key {
            Some(InternalServerKey::Cpu(cpu_key)) => {
                let decomp_key = cpu_key
                    .key
                    .decompression_key
                    .as_ref()
                    .ok_or(crate::high_level_api::errors::UninitializedDecompressionKey)?;
                let inner_kv_store = self.inner.decompress(decomp_key)?;

                let Some(actual_block_count) = inner_kv_store.blocks_per_radix() else {
                    return Ok(KVStore::new()); // The KVstore was empty
                };

                let expected_block_count = Value::Id::num_blocks(cpu_key.message_modulus());

                if actual_block_count.get() != expected_block_count {
                    return Err(crate::error!("Inconsistent block count in KVStore: expected {expected_block_count} but got {actual_block_count}"));
                }

                Ok(KVStore {
                    inner: InnerKVStore::Cpu(inner_kv_store),
                })
            }
            #[cfg(feature = "gpu")]
            Some(InternalServerKey::Cuda(_cuda_key)) => {
                panic!("Decompressing KVStore to GPU is not implemented yet")
            }
            #[cfg(feature = "hpu")]
            Some(InternalServerKey::Hpu(_device)) => {
                panic!("Decompressing KVStore to HPU is not implemented yet")
            }
            None => Err(crate::high_level_api::errors::UninitializedServerKey.into()),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::core_crypto::prelude::Numeric;
    use crate::high_level_api::kv_store::CompressedKVStore;
    use crate::prelude::*;
    use crate::{ClientKey, FheInt32, FheIntegerType, FheUint32, FheUint64, FheUint8, KVStore};
    use rand::prelude::*;
    use std::collections::BTreeMap;

    fn create_kv_store<K, V, FheType>(
        num_keys: usize,
        ck: &ClientKey,
    ) -> (KVStore<K, FheType>, BTreeMap<K, V>)
    where
        K: Numeric + CastInto<usize> + Ord,
        V: Numeric,
        rand::distributions::Standard:
            rand::distributions::Distribution<K> + rand::distributions::Distribution<V>,
        FheType: FheIntegerType + FheEncrypt<V, ClientKey>,
    {
        assert!((K::MAX).cast_into() >= num_keys);
        let mut rng = rand::rng();

        let mut kv_store = KVStore::new();
        let mut clear_store = BTreeMap::new();
        while kv_store.len() != num_keys {
            let k = rng.gen::<K>();
            let v = rng.gen::<V>();

            let e_v = FheType::encrypt(v, ck);

            let _ = kv_store.insert_with_clear_key(k, e_v);
            let _ = clear_store.insert(k, v);
        }

        assert_eq!(kv_store.len(), clear_store.len());

        (kv_store, clear_store)
    }

    fn kv_store_get_test_case(ck: &ClientKey) {
        let num_keys = 10;
        let num_tests = 10;

        let (kv_store, clear_store) = create_kv_store::<u8, u32, FheUint32>(num_keys, ck);
        let mut rng = rand::rng();

        for _ in 0..num_tests {
            let k = rng.gen::<u8>();
            let e_k = FheUint8::encrypt(k, ck);

            let (e_v, e_is_some) = kv_store.get(&e_k);
            let is_some = e_is_some.decrypt(ck);
            let v: u32 = e_v.decrypt(ck);

            if let Some(expected_value) = clear_store.get(&k) {
                assert_eq!(v, *expected_value);
                assert!(is_some);
            } else {
                assert!(!is_some);
                assert_eq!(v, 0);
            }
        }
    }

    fn kv_store_update_test_case(ck: &ClientKey) {
        let num_keys = 10;
        let num_tests = 10;

        let (mut kv_store, mut clear_store) = create_kv_store::<u8, u32, FheUint32>(num_keys, ck);
        let mut rng = rand::rng();

        for _ in 0..num_tests {
            let k = rng.gen::<u8>();
            let e_k = FheUint8::encrypt(k, ck);

            let new_value = rng.gen::<u32>();
            let e_new_value = FheUint32::encrypt(new_value, ck);

            let e_was_updated = kv_store.update(&e_k, &e_new_value);
            let was_updated = e_was_updated.decrypt(ck);

            let is_contained = clear_store.contains_key(&k);
            if is_contained {
                let _ = clear_store.insert(k, new_value);
            }
            assert_eq!(was_updated, is_contained);
        }

        for (k, expected_v) in clear_store.iter() {
            let e_k = FheUint8::encrypt(*k, ck);

            let (e_v, e_is_some) = kv_store.get(&e_k);
            let is_some = e_is_some.decrypt(ck);
            let v: u32 = e_v.decrypt(ck);
            assert!(is_some);
            assert_eq!(v, *expected_v);
        }
    }

    fn kv_store_map_test_case(ck: &ClientKey) {
        let num_keys = 10;
        let num_tests = 10;

        let (mut kv_store, mut clear_store) = create_kv_store::<u8, u32, FheUint32>(num_keys, ck);
        let mut rng = rand::rng();

        for _ in 0..num_tests {
            let k = rng.gen::<u8>();
            let e_k = FheUint8::encrypt(k, ck);

            let expected_new_value = rng.gen::<u32>();

            let (e_old_value, e_new_value, e_was_updated) =
                kv_store.map(&e_k, |_old| FheUint32::encrypt(expected_new_value, ck));
            let was_updated = e_was_updated.decrypt(ck);
            let new_value: u32 = e_new_value.decrypt(ck);
            let old_value: u32 = e_old_value.decrypt(ck);

            if let Some(expected_old_value) = clear_store.get(&k).copied() {
                assert_eq!(old_value, expected_old_value);
                let _ = clear_store.insert(k, expected_new_value);
                assert_eq!(new_value, expected_new_value);
                assert!(was_updated);
            } else {
                assert!(!was_updated);
            }
        }

        for (k, expected_v) in clear_store.iter() {
            let e_k = FheUint8::encrypt(*k, ck);

            let (e_v, e_is_some) = kv_store.get(&e_k);
            let is_some = e_is_some.decrypt(ck);
            let v: u32 = e_v.decrypt(ck);
            assert!(is_some);
            assert_eq!(v, *expected_v);
        }
    }

    fn kv_store_serialization_test_case(ck: &ClientKey) {
        let num_keys = 10;

        let (kv_store, clear_store) = create_kv_store::<u8, u32, FheUint32>(num_keys, ck);

        let compressed = kv_store.compress().unwrap();

        let mut data = vec![];
        crate::safe_serialization::safe_serialize(&compressed, &mut data, 1 << 30).unwrap();

        // Key type is incorrect
        let maybe_compressed = crate::safe_serialization::safe_deserialize::<
            CompressedKVStore<u16, FheUint32>,
        >(data.as_slice(), 1 << 30);
        // safe_deserialize catch the error
        assert!(maybe_compressed.is_err());

        let maybe_compressed = crate::safe_serialization::safe_deserialize::<
            CompressedKVStore<u8, FheInt32>,
        >(data.as_slice(), 1 << 30);
        assert!(maybe_compressed.is_err());

        // Invalid value types
        let compressed = crate::safe_serialization::safe_deserialize::<
            CompressedKVStore<u8, FheUint8>,
        >(data.as_slice(), 1 << 30)
        .unwrap();
        assert!(compressed.decompress().is_err());

        let compressed = crate::safe_serialization::safe_deserialize::<
            CompressedKVStore<u8, FheUint64>,
        >(data.as_slice(), 1 << 30)
        .unwrap();
        assert!(compressed.decompress().is_err());

        let compressed = crate::safe_serialization::safe_deserialize::<
            CompressedKVStore<u8, FheUint32>,
        >(data.as_slice(), 1 << 30)
        .unwrap();

        let kv_store = compressed.decompress().unwrap();

        for (k, expected_v) in clear_store.iter() {
            let e_k = FheUint8::encrypt(*k, ck);

            let (e_v, e_is_some) = kv_store.get(&e_k);
            let is_some = e_is_some.decrypt(ck);
            let v: u32 = e_v.decrypt(ck);
            assert!(is_some);
            assert_eq!(v, *expected_v);
        }
    }

    mod cpu {
        use crate::shortint::parameters::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        use crate::{set_server_key, ConfigBuilder};

        use super::*;

        pub(crate) fn setup_default_cpu() -> ClientKey {
            let config = ConfigBuilder::default()
                .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
                .build();

            let client_key = ClientKey::generate(config);
            let csks = crate::CompressedServerKey::new(&client_key);
            let server_key = csks.decompress();

            set_server_key(server_key);

            client_key
        }

        #[test]
        fn test_kv_store_get() {
            let ck = setup_default_cpu();

            kv_store_get_test_case(&ck);
        }

        #[test]
        fn test_kv_store_update() {
            let ck = setup_default_cpu();

            kv_store_update_test_case(&ck);
        }

        #[test]
        fn test_kv_store_map() {
            let ck = setup_default_cpu();

            kv_store_map_test_case(&ck);
        }

        #[test]
        fn test_kv_store_serialization() {
            let ck = setup_default_cpu();

            kv_store_serialization_test_case(&ck);
        }
    }
}
