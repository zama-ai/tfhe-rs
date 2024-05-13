//! Provides a way to add versioning informations/backward compatibility on rust types used for
//! serialization.
//!
//! This crates provides a set of traits [`Versionize`] and [`Unversionize`] that perform a
//! conversion between a type and its `Versioned` counterpart. The versioned type is an enum
//! that has a variant for each version of the type.
//! These traits can be generated using the [`tfhe_versionable_derive::Versionize`] proc macro.

pub mod derived_traits;
pub mod upgrade;

use std::convert::Infallible;
use std::fmt::Display;
use std::marker::PhantomData;

pub use derived_traits::{Version, VersionsDispatch};
pub use upgrade::Upgrade;

use serde::de::DeserializeOwned;
use serde::Serialize;
pub use tfhe_versionable_derive::{NotVersioned, Version, Versionize, VersionsDispatch};

/// This trait means that the type can be converted into a versioned equivalent
/// type.
pub trait Versionize {
    /// The equivalent versioned type. It should have a variant for each version.
    /// It may own the underlying data or only hold a read-only reference to it.
    type Versioned<'vers>: Serialize
    where
        Self: 'vers;

    /// Wraps the object into a versioned enum with a variant for each version. This will
    /// use references on the underlying types if possible.
    fn versionize(&self) -> Self::Versioned<'_>;

    type VersionedOwned: Serialize + DeserializeOwned;

    /// Wraps the object into a versioned enum with a variant for each version. This will
    /// clone the underlying types.
    fn versionize_owned(&self) -> Self::VersionedOwned;
}

#[derive(Debug)]
/// Errors that can arise in the unversionizing process.
pub enum UnversionizeError {
    /// An error in the upgrade between `vers_from` and `vers_into`
    Upgrade {
        from_vers: String,
        into_vers: String,
        message: String,
    },

    /// An error has been returned in the conversion method provided by the `try_from` parameter
    /// attribute
    Conversion { from_type: String, message: String },
}

impl Display for UnversionizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upgrade {
                from_vers,
                into_vers,
                message,
            } => write!(
                f,
                "Failed to upgrade from {from_vers} into {into_vers}: {message}"
            ),
            Self::Conversion { from_type, message } => {
                write!(f, "Failed to convert from {from_type}: {message}")
            }
        }
    }
}

impl UnversionizeError {
    pub fn upgrade(from_vers: &str, into_vers: &str, message: &str) -> Self {
        Self::Upgrade {
            from_vers: from_vers.to_string(),
            into_vers: into_vers.to_string(),
            message: message.to_string(),
        }
    }

    pub fn conversion(from_type: &str, message: &str) -> Self {
        Self::Conversion {
            from_type: from_type.to_string(),
            message: message.to_string(),
        }
    }
}

impl From<Infallible> for UnversionizeError {
    fn from(_value: Infallible) -> Self {
        panic!("Infallible error type should never be reached")
    }
}

/// This trait means that we can convert from a versioned enum into the target type. This trait
/// can only be implemented on Owned/static types, whereas `Versionize` can also be implemented
/// on reference types.
pub trait Unversionize: Versionize + Sized {
    /// Creates an object from a versioned enum, and eventually upgrades from previous
    /// variants.
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError>;
}

/// Marker trait for a type that it not really versioned, where the `versionize` method returns
/// Self or &Self.
pub trait NotVersioned: Versionize {}

/// Implements the versionable traits for a rust primitive scalar type (integer, float, bool and
/// char) Since these types won't move between versions, we consider that they are their own
/// versionized types
macro_rules! impl_scalar_versionize {
    ($t:ty) => {
        impl Versionize for $t {
            type Versioned<'a> = $t;

            type VersionedOwned = $t;

            fn versionize(&self) -> Self::Versioned<'_> {
                *self
            }

            fn versionize_owned(&self) -> Self::VersionedOwned {
                *self
            }
        }

        impl Unversionize for $t {
            fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
                Ok(versioned)
            }
        }

        impl NotVersioned for $t {}
    };
}

impl_scalar_versionize!(bool);

impl_scalar_versionize!(u8);
impl_scalar_versionize!(u16);
impl_scalar_versionize!(u32);
impl_scalar_versionize!(u64);
impl_scalar_versionize!(u128);
impl_scalar_versionize!(usize);

impl_scalar_versionize!(i8);
impl_scalar_versionize!(i16);
impl_scalar_versionize!(i32);
impl_scalar_versionize!(i64);
impl_scalar_versionize!(i128);

impl_scalar_versionize!(f32);
impl_scalar_versionize!(f64);

impl_scalar_versionize!(char);

impl<T: NotVersioned + Clone + Serialize + DeserializeOwned> Versionize for Vec<T> {
    type Versioned<'vers> = &'vers [T] where T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.as_slice()
    }

    type VersionedOwned = Self;

    fn versionize_owned(&self) -> Self::VersionedOwned {
        self.clone()
    }
}

impl<T: NotVersioned + Clone + Serialize + DeserializeOwned> Unversionize for Vec<T> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(versioned)
    }
}

impl<T: NotVersioned + Clone + Serialize + DeserializeOwned> NotVersioned for Vec<T> {}

impl<T: NotVersioned + Clone + Serialize + DeserializeOwned> Versionize for [T] {
    type Versioned<'vers> = &'vers [T] where T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self
    }

    type VersionedOwned = Vec<T>;

    fn versionize_owned(&self) -> Self::VersionedOwned {
        self.to_vec()
    }
}

impl<T: NotVersioned + Clone + Serialize + DeserializeOwned> NotVersioned for [T] {}

impl Versionize for String {
    type Versioned<'vers> = &'vers str;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.as_ref()
    }

    type VersionedOwned = Self;

    fn versionize_owned(&self) -> Self::VersionedOwned {
        self.clone()
    }
}

impl Unversionize for String {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(versioned)
    }
}

impl NotVersioned for String {}

impl Versionize for str {
    type Versioned<'vers> = &'vers str;

    fn versionize(&self) -> Self::Versioned<'_> {
        self
    }

    type VersionedOwned = String;

    fn versionize_owned(&self) -> Self::VersionedOwned {
        self.to_string()
    }
}

impl NotVersioned for str {}

impl<T: Versionize> Versionize for Option<T> {
    type Versioned<'vers> = Option<T::Versioned<'vers>> where T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.as_ref().map(|val| val.versionize())
    }

    type VersionedOwned = Option<T::VersionedOwned>;

    fn versionize_owned(&self) -> Self::VersionedOwned {
        self.as_ref().map(|val| val.versionize_owned())
    }
}

impl<T: Unversionize> Unversionize for Option<T> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        versioned.map(|val| T::unversionize(val)).transpose()
    }
}

impl<T> Versionize for PhantomData<T> {
    type Versioned<'vers> = Self
    where
        Self: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        *self
    }

    type VersionedOwned = Self;

    fn versionize_owned(&self) -> Self::VersionedOwned {
        *self
    }
}

impl<T> Unversionize for PhantomData<T> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(versioned)
    }
}

impl<T> NotVersioned for PhantomData<T> {}
