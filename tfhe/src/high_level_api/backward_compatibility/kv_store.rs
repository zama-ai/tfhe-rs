use crate::high_level_api::kv_store::CompressedKVStore;
use crate::FheIntegerType;
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum CompressedKVStoreVersions<Key, Value>
where
    Value: FheIntegerType,
{
    V0(CompressedKVStore<Key, Value>),
}
