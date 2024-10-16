//! Handle the deprecation of older versions of some types

use std::error::Error;
use std::fmt::Display;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::{UnversionizeError, Upgrade, Version};

/// This trait should be implemented for types that have deprecated versions. You can then use them
/// inside the dispatch enum by wrapping them into the [`Deprecated`] type.
pub trait Deprecable {
    const TYPE_NAME: &'static str;
    const MIN_SUPPORTED_APP_VERSION: &'static str;

    fn error() -> DeprecatedVersionError {
        DeprecatedVersionError {
            type_name: Self::TYPE_NAME.to_string(),
            min_supported_app_version: Self::MIN_SUPPORTED_APP_VERSION.to_string(),
        }
    }
}

/// An error returned when trying to interact (unserialize or unversionize) with a deprecated type.
#[derive(Debug)]
pub struct DeprecatedVersionError {
    type_name: String,
    min_supported_app_version: String,
}

impl Display for DeprecatedVersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Deprecated {} found in serialized data, minimal supported version is {}",
            self.type_name, self.min_supported_app_version
        )
    }
}

impl Error for DeprecatedVersionError {}

/// Wrapper type that can be used inside the dispatch enum for a type to mark a version that has
/// been deprecated.
///
/// For example:
/// ```rust
/// use tfhe_versionable::deprecation::{Deprecable, Deprecated};
/// use tfhe_versionable::{Versionize, VersionsDispatch};
/// #[derive(Versionize)]
/// #[versionize(MyStructVersions)]
/// struct MyStruct;
///
/// impl Deprecable for MyStruct {
///     const TYPE_NAME: &'static str = "MyStruct";
///     const MIN_SUPPORTED_APP_VERSION: &'static str = "my_app v2";
/// }
///
/// #[derive(VersionsDispatch)]
/// #[allow(unused)]
/// pub enum MyStructVersions {
///     V0(Deprecated<MyStruct>),
///     V1(Deprecated<MyStruct>),
///     V2(MyStruct),
/// }
/// ```
pub struct Deprecated<T> {
    _phantom: PhantomData<T>,
}

/// This type is used in the [`Version`] trait but should not be manually used.
pub struct DeprecatedVersion<T> {
    _phantom: PhantomData<T>,
}

// Manual impl of Serialize/Deserialize to be able to catch them and return a meaningful error to
// the user.

impl<T: Deprecable> Serialize for DeprecatedVersion<T> {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(serde::ser::Error::custom(
            "a DeprecatedVersion should never be serialized",
        ))
    }
}

impl<'de, T: Deprecable> Deserialize<'de> for DeprecatedVersion<T> {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(<D::Error as serde::de::Error>::custom(T::error()))
    }
}

impl<T: Deprecable> Version for Deprecated<T> {
    // Since the type is a ZST we directly use it without a reference
    type Ref<'vers>
        = DeprecatedVersion<T>
    where
        T: 'vers;

    type Owned = DeprecatedVersion<T>;
}

impl<T: Deprecable> From<Deprecated<T>> for DeprecatedVersion<T> {
    fn from(_value: Deprecated<T>) -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<T: Deprecable> From<&Deprecated<T>> for DeprecatedVersion<T> {
    fn from(_value: &Deprecated<T>) -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<T: Deprecable> TryFrom<DeprecatedVersion<T>> for Deprecated<T> {
    type Error = UnversionizeError;

    fn try_from(_value: DeprecatedVersion<T>) -> Result<Self, Self::Error> {
        Err(UnversionizeError::DeprecatedVersion(T::error()))
    }
}

impl<T: Deprecable, U> Upgrade<U> for Deprecated<T> {
    type Error = DeprecatedVersionError;

    fn upgrade(self) -> Result<U, Self::Error> {
        Err(T::error())
    }
}
