use crate::shortint::parameters::parameters_wopbs::*;
use crate::shortint::parameters::parameters_wopbs_message_carry::*;
use crate::shortint::parameters::parameters_wopbs_prime_moduli::*;
use crate::shortint::parameters::*;
use crate::shortint::wopbs::WopbsKey;
use crate::shortint::{ClientKey, ServerKey};
use lazy_static::*;
use serde::{Deserialize, Serialize};

pub use utils::{
    FileStorage, KeyCache as ImplKeyCache, NamedParam, PersistentStorage,
    SharedKey as GenericSharedKey,
};

#[macro_use]
pub mod utils {
    use fs2::FileExt;
    use once_cell::sync::OnceCell;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use std::fs::File;
    use std::io::{BufReader, BufWriter};
    use std::ops::Deref;
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};

    pub trait PersistentStorage<P, K> {
        fn load(&self, param: P) -> Option<K>;
        fn store(&self, param: P, key: &K);
    }

    pub trait NamedParam {
        fn name(&self) -> String;
    }

    #[macro_export]
    macro_rules! named_params_impl(
    ( $thing:ident == ( $($const_param:ident),* $(,)? )) => {
        named_params_impl!({ *$thing } == ( $($const_param),* ))
    };

    ( { $thing:expr } == ( $($const_param:ident),* $(,)? )) => {
        $(
            if $thing == $const_param {
                return stringify!($const_param).to_string();
            }
        )*

        panic!("Unnamed parameters");
    }
    );

    pub struct FileStorage {
        prefix: String,
    }

    impl FileStorage {
        pub fn new(prefix: String) -> Self {
            Self { prefix }
        }
    }

    impl<P, K> PersistentStorage<P, K> for FileStorage
    where
        P: NamedParam + DeserializeOwned + Serialize + PartialEq,
        K: DeserializeOwned + Serialize,
    {
        fn load(&self, param: P) -> Option<K> {
            let mut path_buf = PathBuf::with_capacity(256);
            path_buf.push(&self.prefix);
            path_buf.push(param.name());
            path_buf.set_extension("bin");

            if path_buf.exists() {
                let file = File::open(&path_buf).unwrap();
                // Lock for reading
                file.lock_shared().unwrap();
                let file_reader = BufReader::new(file);
                bincode::deserialize_from::<_, (P, K)>(file_reader)
                    .ok()
                    .and_then(|(p, k)| if p == param { Some(k) } else { None })
            } else {
                None
            }
        }

        fn store(&self, param: P, key: &K) {
            let mut path_buf = PathBuf::with_capacity(256);
            path_buf.push(&self.prefix);
            std::fs::create_dir_all(&path_buf).unwrap();
            path_buf.push(param.name());
            path_buf.set_extension("bin");

            let file = File::create(&path_buf).unwrap();
            // Lock for writing
            file.lock_exclusive().unwrap();

            let file_writer = BufWriter::new(file);
            bincode::serialize_into(file_writer, &(param, key)).unwrap();
        }
    }

    pub struct SharedKey<K> {
        inner: Arc<OnceCell<K>>,
    }

    impl<K> Clone for SharedKey<K> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    impl<K> Deref for SharedKey<K> {
        type Target = K;

        fn deref(&self) -> &Self::Target {
            self.inner.get().unwrap()
        }
    }

    pub struct KeyCache<P, K, S> {
        // Where the keys will be stored persistently
        // So they are not generated between each run
        persistent_storage: S,
        // Temporary memory storage to avoid querying the persistent storage each time
        // the outer Arc makes it so that we don't clone the OnceCell contents when initializing it
        memory_storage: RwLock<Vec<(P, SharedKey<K>)>>,
    }

    impl<P, K, S> KeyCache<P, K, S> {
        pub fn new(storage: S) -> Self {
            Self {
                persistent_storage: storage,
                memory_storage: RwLock::new(vec![]),
            }
        }

        pub fn clear_in_memory_cache(&self) {
            let mut memory_storage = self.memory_storage.write().unwrap();
            memory_storage.clear();
        }
    }

    impl<P, K, S> KeyCache<P, K, S>
    where
        P: Copy + PartialEq + NamedParam,
        S: PersistentStorage<P, K>,
        K: From<P> + Clone,
    {
        pub fn get(&self, param: P) -> SharedKey<K> {
            self.with_key(param, |k| k.clone())
        }

        pub fn with_key<F, R>(&self, param: P, f: F) -> R
        where
            F: FnOnce(&SharedKey<K>) -> R,
        {
            let load_from_persistent_storage = || {
                // we check if we can load the key from persistent storage
                let persistent_storage = &self.persistent_storage;
                let maybe_key = persistent_storage.load(param);
                match maybe_key {
                    Some(key) => key,
                    None => {
                        let key = K::from(param);
                        persistent_storage.store(param, &key);
                        key
                    }
                }
            };

            let try_load_from_memory_and_init = || {
                // we only hold a read lock for a short duration to find the key
                let maybe_shared_cell = {
                    let memory_storage = self.memory_storage.read().unwrap();
                    memory_storage
                        .iter()
                        .find(|(p, _)| *p == param)
                        .map(|param_key| param_key.1.clone())
                };

                if let Some(shared_cell) = maybe_shared_cell {
                    shared_cell.inner.get_or_init(load_from_persistent_storage);
                    Ok(shared_cell)
                } else {
                    Err(())
                }
            };

            match try_load_from_memory_and_init() {
                Ok(result) => f(&result),
                Err(()) => {
                    {
                        // we only hold a write lock for a short duration to push the lazily
                        // evaluated key without actually evaluating the key
                        let mut memory_storage = self.memory_storage.write().unwrap();
                        if !memory_storage.iter().any(|(p, _)| *p == param) {
                            memory_storage.push((
                                param,
                                SharedKey {
                                    inner: Arc::new(OnceCell::new()),
                                },
                            ));
                        }
                    }
                    f(&try_load_from_memory_and_init().ok().unwrap())
                }
            }
        }
    }
}

impl NamedParam for Parameters {
    fn name(&self) -> String {
        named_params_impl!(
            self == (
                PARAM_MESSAGE_1_CARRY_0,
                PARAM_MESSAGE_1_CARRY_1,
                PARAM_MESSAGE_1_CARRY_2,
                PARAM_MESSAGE_1_CARRY_3,
                PARAM_MESSAGE_1_CARRY_4,
                PARAM_MESSAGE_1_CARRY_5,
                PARAM_MESSAGE_1_CARRY_6,
                PARAM_MESSAGE_1_CARRY_7,
                PARAM_MESSAGE_2_CARRY_0,
                PARAM_MESSAGE_2_CARRY_1,
                PARAM_MESSAGE_2_CARRY_2,
                PARAM_MESSAGE_2_CARRY_3,
                PARAM_MESSAGE_2_CARRY_4,
                PARAM_MESSAGE_2_CARRY_5,
                PARAM_MESSAGE_2_CARRY_6,
                PARAM_MESSAGE_3_CARRY_0,
                PARAM_MESSAGE_3_CARRY_1,
                PARAM_MESSAGE_3_CARRY_2,
                PARAM_MESSAGE_3_CARRY_3,
                PARAM_MESSAGE_3_CARRY_4,
                PARAM_MESSAGE_3_CARRY_5,
                PARAM_MESSAGE_4_CARRY_0,
                PARAM_MESSAGE_4_CARRY_1,
                PARAM_MESSAGE_4_CARRY_2,
                PARAM_MESSAGE_4_CARRY_3,
                PARAM_MESSAGE_4_CARRY_4,
                PARAM_MESSAGE_5_CARRY_0,
                PARAM_MESSAGE_5_CARRY_1,
                PARAM_MESSAGE_5_CARRY_2,
                PARAM_MESSAGE_5_CARRY_3,
                PARAM_MESSAGE_6_CARRY_0,
                PARAM_MESSAGE_6_CARRY_1,
                PARAM_MESSAGE_6_CARRY_2,
                PARAM_MESSAGE_7_CARRY_0,
                PARAM_MESSAGE_7_CARRY_1,
                PARAM_MESSAGE_8_CARRY_0,
                // Small
                PARAM_SMALL_MESSAGE_1_CARRY_1,
                PARAM_SMALL_MESSAGE_2_CARRY_2,
                PARAM_SMALL_MESSAGE_3_CARRY_3,
                PARAM_SMALL_MESSAGE_4_CARRY_4,
                // Wops
                WOPBS_PARAM_MESSAGE_1_NORM2_2,
                WOPBS_PARAM_MESSAGE_1_NORM2_4,
                WOPBS_PARAM_MESSAGE_1_NORM2_6,
                WOPBS_PARAM_MESSAGE_1_NORM2_8,
                WOPBS_PARAM_MESSAGE_2_NORM2_2,
                WOPBS_PARAM_MESSAGE_2_NORM2_4,
                WOPBS_PARAM_MESSAGE_2_NORM2_6,
                WOPBS_PARAM_MESSAGE_2_NORM2_8,
                WOPBS_PARAM_MESSAGE_3_NORM2_2,
                WOPBS_PARAM_MESSAGE_3_NORM2_4,
                WOPBS_PARAM_MESSAGE_3_NORM2_6,
                WOPBS_PARAM_MESSAGE_3_NORM2_8,
                WOPBS_PARAM_MESSAGE_4_NORM2_2,
                WOPBS_PARAM_MESSAGE_4_NORM2_4,
                WOPBS_PARAM_MESSAGE_4_NORM2_6,
                WOPBS_PARAM_MESSAGE_4_NORM2_8,
                WOPBS_PARAM_MESSAGE_5_NORM2_2,
                WOPBS_PARAM_MESSAGE_5_NORM2_4,
                WOPBS_PARAM_MESSAGE_5_NORM2_6,
                WOPBS_PARAM_MESSAGE_5_NORM2_8,
                WOPBS_PARAM_MESSAGE_6_NORM2_2,
                WOPBS_PARAM_MESSAGE_6_NORM2_4,
                WOPBS_PARAM_MESSAGE_6_NORM2_6,
                WOPBS_PARAM_MESSAGE_6_NORM2_8,
                WOPBS_PARAM_MESSAGE_7_NORM2_2,
                WOPBS_PARAM_MESSAGE_7_NORM2_4,
                WOPBS_PARAM_MESSAGE_7_NORM2_6,
                WOPBS_PARAM_MESSAGE_7_NORM2_8,
                WOPBS_PARAM_MESSAGE_8_NORM2_2,
                WOPBS_PARAM_MESSAGE_8_NORM2_4,
                //WOPBS_PARAM_MESSAGE_8_NORM2_5,
                WOPBS_PARAM_MESSAGE_8_NORM2_6,
                WOPBS_PARAM_MESSAGE_1_CARRY_0,
                WOPBS_PARAM_MESSAGE_1_CARRY_1,
                WOPBS_PARAM_MESSAGE_1_CARRY_2,
                WOPBS_PARAM_MESSAGE_1_CARRY_3,
                WOPBS_PARAM_MESSAGE_1_CARRY_4,
                WOPBS_PARAM_MESSAGE_1_CARRY_5,
                WOPBS_PARAM_MESSAGE_1_CARRY_6,
                WOPBS_PARAM_MESSAGE_1_CARRY_7,
                WOPBS_PARAM_MESSAGE_2_CARRY_0,
                WOPBS_PARAM_MESSAGE_2_CARRY_1,
                WOPBS_PARAM_MESSAGE_2_CARRY_2,
                WOPBS_PARAM_MESSAGE_2_CARRY_3,
                WOPBS_PARAM_MESSAGE_2_CARRY_4,
                WOPBS_PARAM_MESSAGE_2_CARRY_5,
                WOPBS_PARAM_MESSAGE_2_CARRY_6,
                WOPBS_PARAM_MESSAGE_3_CARRY_0,
                WOPBS_PARAM_MESSAGE_3_CARRY_1,
                WOPBS_PARAM_MESSAGE_3_CARRY_2,
                WOPBS_PARAM_MESSAGE_3_CARRY_3,
                WOPBS_PARAM_MESSAGE_3_CARRY_4,
                WOPBS_PARAM_MESSAGE_3_CARRY_5,
                WOPBS_PARAM_MESSAGE_4_CARRY_0,
                WOPBS_PARAM_MESSAGE_4_CARRY_1,
                WOPBS_PARAM_MESSAGE_4_CARRY_2,
                WOPBS_PARAM_MESSAGE_4_CARRY_3,
                WOPBS_PARAM_MESSAGE_4_CARRY_4,
                WOPBS_PARAM_MESSAGE_5_CARRY_0,
                WOPBS_PARAM_MESSAGE_5_CARRY_1,
                WOPBS_PARAM_MESSAGE_5_CARRY_2,
                WOPBS_PARAM_MESSAGE_5_CARRY_3,
                WOPBS_PARAM_MESSAGE_6_CARRY_0,
                WOPBS_PARAM_MESSAGE_6_CARRY_1,
                WOPBS_PARAM_MESSAGE_6_CARRY_2,
                WOPBS_PARAM_MESSAGE_7_CARRY_0,
                WOPBS_PARAM_MESSAGE_7_CARRY_1,
                WOPBS_PARAM_MESSAGE_8_CARRY_0,
                WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_2,
                WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_3,
                WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_4,
                WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_5,
                WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_6,
                WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_7,
                WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_8,
                WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_2,
                WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_3,
                WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_4,
                WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_5,
                WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_6,
                WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_7,
                WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_8,
                WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_2,
                WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_3,
                WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_4,
                WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_5,
                WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_6,
                WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_7,
                WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_8,
                WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_2,
                WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_3,
                WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_4,
                WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_5,
                WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_6,
                WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_7,
                WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_8,
                WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_2,
                WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_3,
                WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_4,
                WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_5,
                WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_6,
                WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_7,
                WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_8,
                WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_2,
                WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_3,
                WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_4,
                WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_5,
                WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_6,
                WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_7,
                WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_8,
                WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_2,
                WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_3,
                WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_4,
                WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_5,
                WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_6,
                WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_7,
                PARAM_4_BITS_5_BLOCKS,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            )
        );
    }
}

impl From<Parameters> for (ClientKey, ServerKey) {
    fn from(param: Parameters) -> Self {
        let cks = ClientKey::new(param);
        let sks = ServerKey::new(&cks);
        (cks, sks)
    }
}

pub struct Keycache {
    inner: ImplKeyCache<Parameters, (ClientKey, ServerKey), FileStorage>,
}

impl Default for Keycache {
    fn default() -> Self {
        Self {
            inner: ImplKeyCache::new(FileStorage::new(
                "../keys/shortint/client_server".to_string(),
            )),
        }
    }
}

pub struct SharedKey {
    inner: GenericSharedKey<(ClientKey, ServerKey)>,
}

pub struct SharedWopbsKey {
    inner: GenericSharedKey<(ClientKey, ServerKey)>,
    wopbs: GenericSharedKey<WopbsKey>,
}

impl SharedKey {
    pub fn client_key(&self) -> &ClientKey {
        &self.inner.0
    }
    pub fn server_key(&self) -> &ServerKey {
        &self.inner.1
    }
}

impl SharedWopbsKey {
    pub fn client_key(&self) -> &ClientKey {
        &self.inner.0
    }
    pub fn server_key(&self) -> &ServerKey {
        &self.inner.1
    }
    pub fn wopbs_key(&self) -> &WopbsKey {
        &self.wopbs
    }
}

impl Keycache {
    pub fn get_from_param(&self, param: Parameters) -> SharedKey {
        SharedKey {
            inner: self.inner.get(param),
        }
    }

    pub fn clear_in_memory_cache(&self) {
        self.inner.clear_in_memory_cache();
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WopbsParamPair(pub Parameters, pub Parameters);

impl From<(Parameters, Parameters)> for WopbsParamPair {
    fn from(tuple: (Parameters, Parameters)) -> Self {
        Self(tuple.0, tuple.1)
    }
}

impl From<WopbsParamPair> for WopbsKey {
    fn from(params: WopbsParamPair) -> Self {
        // use with_key to avoid doing a temporary cloning
        KEY_CACHE.inner.with_key(params.0, |keys| {
            WopbsKey::new_wopbs_key(&keys.0, &keys.1, &params.1)
        })
    }
}

impl NamedParam for WopbsParamPair {
    fn name(&self) -> String {
        self.1.name()
    }
}

/// The KeyCache struct for shortint.
///
/// You should not create an instance yourself,
/// but rather use the global variable defined: [KEY_CACHE_WOPBS]
pub struct KeycacheWopbsV0 {
    inner: ImplKeyCache<WopbsParamPair, WopbsKey, FileStorage>,
}

impl Default for KeycacheWopbsV0 {
    fn default() -> Self {
        Self {
            inner: ImplKeyCache::new(FileStorage::new("../keys/shortint/wopbs_v0".to_string())),
        }
    }
}

impl KeycacheWopbsV0 {
    pub fn get_from_param<T: Into<WopbsParamPair>>(&self, params: T) -> SharedWopbsKey {
        let params = params.into();
        let key = KEY_CACHE.get_from_param(params.0);
        let wk = self.inner.get(params);
        SharedWopbsKey {
            inner: key.inner,
            wopbs: wk,
        }
    }

    pub fn clear_in_memory_cache(&self) {
        self.inner.clear_in_memory_cache();
    }
}

lazy_static! {
    pub static ref KEY_CACHE: Keycache = Default::default();
    pub static ref KEY_CACHE_WOPBS: KeycacheWopbsV0 = Default::default();
}
