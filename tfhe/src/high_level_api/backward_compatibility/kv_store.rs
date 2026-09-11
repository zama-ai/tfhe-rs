use crate::high_level_api::kv_store::CompressedKVStore;
use crate::integer::server_key::CompressedKVStore as CompressedIntegerKVStore;
use crate::{FheIntegerType, IntegerId, Tag};
use std::convert::Infallible;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

#[derive(Version)]
pub struct CompressedKVStoreV0<Key, Value>
where
    Value: FheIntegerType,
{
    pub(in crate::high_level_api) inner:
        CompressedIntegerKVStore<Key, <Value::Id as IntegerId>::InnerCpu>,
}

impl<Key, Value> Upgrade<CompressedKVStore<Key, Value>> for CompressedKVStoreV0<Key, Value>
where
    Value: FheIntegerType,
{
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedKVStore<Key, Value>, Self::Error> {
        Ok(CompressedKVStore {
            inner: self.inner,
            tag: Tag::default(),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedKVStoreVersions<Key, Value>
where
    Value: FheIntegerType,
{
    V0(CompressedKVStoreV0<Key, Value>),
    V1(CompressedKVStore<Key, Value>),
}
