pub use utils::{
    FileStorage, KeyCache as ImplKeyCache, NamedParam, PersistentStorage,
    SharedKey as GenericSharedKey,
};

pub mod utils {
    use fs2::FileExt;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use std::fs::File;
    use std::io::{BufReader, BufWriter};
    use std::ops::Deref;
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock, RwLock};

    pub trait PersistentStorage<P, K> {
        fn load(&self, param: P) -> Option<K>;
        fn store(&self, param: P, key: &K);
    }

    pub trait NamedParam {
        fn name(&self) -> String;
    }

    // Useful when defining custom parameters that may need an access to the keycache logic
    #[macro_export]
    macro_rules! named_params_impl(
        (expose $($const_param:ident),* $(,)? ) => {
            $(
                ::paste::paste! {
                    pub const [<$const_param _NAME>]: &'static str = stringify!($const_param);
                }
            )*
        };

        ($param_type:ty => $($(#[$cfg:meta])? $const_param:ident),* $(,)? ) => {
            $(
                $(#[$cfg])?
                named_params_impl!(expose $const_param);
            )*

            impl NamedParam for $param_type {
                fn name(&self) -> String {
                    $(
                        $(#[$cfg])?
                        named_params_impl!({*self; $param_type} == ( $const_param ));
                    )*
                    panic!("Unnamed parameters");
                }
            }
        };

        ({$thing:expr; $param_type:ty} == ( $($const_param:ident),* $(,)? )) => {
            $(
                ::paste::paste! {
                    if $thing == <$param_type>::from($const_param) {
                        return [<$const_param _NAME>].to_string();
                    }
                }
            )*
        }
    );

    pub use named_params_impl;

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
                fs2::FileExt::lock_shared(&file).unwrap();
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
        inner: Arc<OnceLock<K>>,
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
        // the outer Arc makes it so that we don't clone the OnceLock contents when initializing it
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
            self.get_with_closure(param, &mut K::from)
        }
    }

    impl<P, K, S> KeyCache<P, K, S>
    where
        P: Copy + PartialEq + NamedParam,
        S: PersistentStorage<P, K>,
    {
        pub fn get_with_closure<C: FnMut(P) -> K>(
            &self,
            param: P,
            key_gen_closure: &mut C,
        ) -> SharedKey<K> {
            self.with_closure(param, key_gen_closure)
        }

        pub fn with_closure<C>(&self, param: P, key_gen_closure: &mut C) -> SharedKey<K>
        where
            C: FnMut(P) -> K,
        {
            let load_from_persistent_storage = || {
                // we check if we can load the key from persistent storage
                let persistent_storage = &self.persistent_storage;
                let maybe_key = persistent_storage.load(param);
                maybe_key.map_or_else(
                    || {
                        let key = key_gen_closure(param);
                        persistent_storage.store(param, &key);
                        key
                    },
                    |key| key,
                )
            };

            let try_load_from_memory_and_init = || -> Result<_, ()> {
                let maybe_shared_key = {
                    let mut res = None;
                    let lock = &*self.memory_storage.read().unwrap();
                    for (p, key) in lock.iter() {
                        if *p == param {
                            res = Some(key.clone());
                            break;
                        }
                    }
                    res
                };

                maybe_shared_key.map_or_else(
                    || {
                        let shared_key = SharedKey {
                            inner: Arc::new(OnceLock::new()),
                        };
                        shared_key.inner.get_or_init(load_from_persistent_storage);
                        {
                            // we only hold a write lock for a short duration to push the key
                            // if it doesn't already exists.
                            let mut memory_storage = self.memory_storage.write().unwrap();
                            if memory_storage.iter().all(|(p, _)| *p != param) {
                                memory_storage.push((param, shared_key.clone()));
                            }
                        }
                        Ok(shared_key)
                    },
                    Ok,
                )
            };

            try_load_from_memory_and_init().ok().unwrap()
        }
    }
}
