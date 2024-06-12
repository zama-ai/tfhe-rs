//! These traits are not meant to be manually implemented, they are just used in the derive macro
//! for easier access to generated types

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::UnversionizeError;

/// This trait is used to mark a specific version of a given type
pub trait Version: Sized {
    type Ref<'vers>: From<&'vers Self> + Serialize
    where
        Self: 'vers;
    type Owned: From<Self> + TryInto<Self, Error = UnversionizeError> + DeserializeOwned + Serialize;
}

/// This trait is implemented on the dispatch enum for a given type. The dispatch enum
/// is an enum that holds all the versions of the type. Each variant should implement the
/// `Version` trait.
pub trait VersionsDispatch<Unversioned>: Sized {
    type Ref<'vers>: From<&'vers Unversioned> + Serialize
    where
        Unversioned: 'vers;
    type Owned: From<Unversioned>
        + TryInto<Unversioned, Error = UnversionizeError>
        + DeserializeOwned
        + Serialize;
}
