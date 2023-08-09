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
        fn name(&self) -> &'static str;
    }

    #[macro_export]
    macro_rules! named_params_impl(
        (expose $($const_param:ident),* $(,)? ) => {
            $(
                paste::paste! {
                    pub const [<$const_param _NAME>]: &'static str = stringify!($const_param);
                }
            )*
        };

        ($param_type:ty => $($const_param:ident),* $(,)? ) => {
            named_params_impl!(expose $($const_param),*);

            impl NamedParam for $param_type {
                fn name(&self) -> &'static str {
                    named_params_impl!({*self; $param_type} == ( $($const_param),* ));
                }
            }
        };

        ({$thing:expr; $param_type:ty} == ( $($const_param:ident),* $(,)? )) => {
            $(
                paste::paste! {
                    if $thing == <$param_type>::from($const_param) {
                        return [<$const_param _NAME>];
                    }
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
