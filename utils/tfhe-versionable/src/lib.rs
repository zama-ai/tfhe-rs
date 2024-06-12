//! Provides a way to add versioning informations/backward compatibility on rust types used for
//! serialization.
//!
//! This crates provides a set of traits [`Versionize`] and [`Unversionize`] that perform a
//! conversion between a type and its `Versioned` counterpart. The versioned type is an enum
//! that has a variant for each version of the type.
//! These traits can be generated using the [`tfhe_versionable_derive::Versionize`] proc macro.

pub mod derived_traits;
pub mod upgrade;

use aligned_vec::{ABox, AVec};
use num_complex::Complex;
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
}

pub trait VersionizeOwned {
    type VersionedOwned: Serialize + DeserializeOwned;

    /// Wraps the object into a versioned enum with a variant for each version. This will
    /// clone the underlying types.
    fn versionize_owned(self) -> Self::VersionedOwned;
}

/// This trait is used as a proxy to be more felxible when deriving Versionize for Vec<T>.
/// This way, we can chose to skip versioning Vec<T> if T is a native types but still versionize in
/// a loop if T is a custom type.
/// This is used as a workaround for feature(specialization) and to bypass the orphan rule.
pub trait VersionizeSlice: Sized {
    type VersionedSlice<'vers>: Serialize
    where
        Self: 'vers;

    fn versionize_slice(slice: &[Self]) -> Self::VersionedSlice<'_>;
}

pub trait VersionizeVec: Sized {
    type VersionedVec: Serialize + DeserializeOwned;

    fn versionize_vec(vec: Vec<Self>) -> Self::VersionedVec;
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
pub trait Unversionize: VersionizeOwned + Sized {
    /// Creates an object from a versioned enum, and eventually upgrades from previous
    /// variants.
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError>;
}

pub trait UnversionizeVec: VersionizeVec {
    fn unversionize_vec(versioned: Self::VersionedVec) -> Result<Vec<Self>, UnversionizeError>;
}

/// Marker trait for a type that it not really versioned, where the `versionize` method returns
/// Self or &Self.
pub trait NotVersioned: Versionize {}

impl<T: NotVersioned + Serialize + DeserializeOwned + Clone> VersionizeSlice for T {
    type VersionedSlice<'vers> = &'vers [T] where T: 'vers;

    fn versionize_slice(slice: &[Self]) -> Self::VersionedSlice<'_> {
        slice
    }
}

impl<T: NotVersioned + Serialize + DeserializeOwned + Clone> VersionizeVec for T {
    type VersionedVec = Vec<T>;

    fn versionize_vec(vec: Vec<Self>) -> Self::VersionedVec {
        vec
    }
}

impl<T: NotVersioned + Serialize + DeserializeOwned + Clone> UnversionizeVec for T {
    fn unversionize_vec(versioned: Self::VersionedVec) -> Result<Vec<Self>, UnversionizeError> {
        Ok(versioned)
    }
}

/// implements the versionable traits for a rust primitive scalar type (integer, float, bool and
/// char) Since these types won't move between versions, we consider that they are their own
/// versionized types
macro_rules! impl_scalar_versionize {
    ($t:ty) => {
        impl Versionize for $t {
            type Versioned<'vers> = $t;

            fn versionize(&self) -> Self::Versioned<'_> {
                *self
            }
        }

        impl VersionizeOwned for $t {
            type VersionedOwned = $t;
            fn versionize_owned(self) -> Self::VersionedOwned {
                self
            }
        }

        impl Unversionize for $t {
            fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
                Ok(versioned)
            }
        }

        impl NotVersioned for $t {}

        impl NotVersioned for Vec<$t> {}
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

impl<T: Versionize> Versionize for Box<T> {
    type Versioned<'vers> = T::Versioned<'vers> where T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.as_ref().versionize()
    }
}

impl<T: VersionizeOwned> VersionizeOwned for Box<T> {
    type VersionedOwned = Box<T::VersionedOwned>;

    fn versionize_owned(self) -> Self::VersionedOwned {
        Box::new(T::versionize_owned(*self))
    }
}

impl<T: Unversionize> Unversionize for Box<T> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(Box::new(T::unversionize(*versioned)?))
    }
}

impl<T: VersionizeSlice> Versionize for Vec<T> {
    type Versioned<'vers> = T::VersionedSlice<'vers> where T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        T::versionize_slice(self)
    }
}

impl<T: VersionizeVec> VersionizeOwned for Vec<T> {
    type VersionedOwned = T::VersionedVec;

    fn versionize_owned(self) -> Self::VersionedOwned {
        T::versionize_vec(self)
    }
}

impl<T: VersionizeSlice + Clone> Versionize for [T] {
    type Versioned<'vers> = T::VersionedSlice<'vers> where T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        T::versionize_slice(self)
    }
}

impl<T: VersionizeVec + Clone> VersionizeOwned for &[T] {
    type VersionedOwned = T::VersionedVec;

    fn versionize_owned(self) -> Self::VersionedOwned {
        T::versionize_vec(self.to_vec())
    }
}

impl<T: UnversionizeVec> Unversionize for Vec<T> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        T::unversionize_vec(versioned)
    }
}

impl Versionize for String {
    type Versioned<'vers> = &'vers str;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.as_ref()
    }
}

impl VersionizeOwned for String {
    type VersionedOwned = Self;

    fn versionize_owned(self) -> Self::VersionedOwned {
        self
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
}

impl VersionizeOwned for &str {
    type VersionedOwned = String;

    fn versionize_owned(self) -> Self::VersionedOwned {
        self.to_string()
    }
}

impl NotVersioned for str {}

impl<T: Versionize> Versionize for Option<T> {
    type Versioned<'vers> = Option<T::Versioned<'vers>> where T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.as_ref().map(|val| val.versionize())
    }
}

impl<T: VersionizeOwned> VersionizeOwned for Option<T> {
    type VersionedOwned = Option<T::VersionedOwned>;

    fn versionize_owned(self) -> Self::VersionedOwned {
        self.map(|val| val.versionize_owned())
    }
}

impl<T: Unversionize> Unversionize for Option<T> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        versioned.map(|val| T::unversionize(val)).transpose()
    }
}

impl<T: NotVersioned> NotVersioned for Option<T> {}

impl<T> Versionize for PhantomData<T> {
    type Versioned<'vers> = Self
    where
        Self: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        *self
    }
}

impl<T> VersionizeOwned for PhantomData<T> {
    type VersionedOwned = Self;

    fn versionize_owned(self) -> Self::VersionedOwned {
        self
    }
}

impl<T> Unversionize for PhantomData<T> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(versioned)
    }
}

impl<T> NotVersioned for PhantomData<T> {}

impl<T: Versionize> Versionize for Complex<T> {
    type Versioned<'vers> = Complex<T::Versioned<'vers>> where T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        Complex {
            re: self.re.versionize(),
            im: self.im.versionize(),
        }
    }
}

impl<T: VersionizeOwned> VersionizeOwned for Complex<T> {
    type VersionedOwned = Complex<T::VersionedOwned>;

    fn versionize_owned(self) -> Self::VersionedOwned {
        Complex {
            re: self.re.versionize_owned(),
            im: self.im.versionize_owned(),
        }
    }
}

impl<T: Unversionize> Unversionize for Complex<T> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(Complex {
            re: T::unversionize(versioned.re)?,
            im: T::unversionize(versioned.im)?,
        })
    }
}

impl<T: NotVersioned> NotVersioned for Complex<T> {}

impl<T: Versionize> Versionize for ABox<T> {
    type Versioned<'vers> = T::Versioned<'vers> where T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.as_ref().versionize()
    }
}

impl<T: VersionizeOwned + Copy> VersionizeOwned for ABox<T> {
    // Alignment doesn't matter for versioned types
    type VersionedOwned = Box<T::VersionedOwned>;

    fn versionize_owned(self) -> Self::VersionedOwned {
        Box::new(T::versionize_owned(*self))
    }
}

impl<T: Unversionize + Copy> Unversionize for ABox<T>
where
    T::VersionedOwned: Clone,
{
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(ABox::new(0, T::unversionize((*versioned).to_owned())?))
    }
}

impl<T: VersionizeSlice> Versionize for AVec<T> {
    type Versioned<'vers> = T::VersionedSlice<'vers> where T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        T::versionize_slice(self)
    }
}

// Alignment doesn't matter for versioned types
impl<T: VersionizeVec + Clone> VersionizeOwned for AVec<T> {
    type VersionedOwned = T::VersionedVec;

    fn versionize_owned(self) -> Self::VersionedOwned {
        T::versionize_vec(self.to_vec())
    }
}

impl<T: UnversionizeVec + Clone> Unversionize for AVec<T> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        T::unversionize_vec(versioned).map(|unver| AVec::from_iter(0, unver))
    }
}

impl<T: NotVersioned + Clone + Serialize + DeserializeOwned> NotVersioned for AVec<T> {}

impl<T: Versionize, U: Versionize> Versionize for (T, U) {
    type Versioned<'vers> = (T::Versioned<'vers>, U::Versioned<'vers>) where T: 'vers, U: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        (self.0.versionize(), self.1.versionize())
    }
}

impl<T: VersionizeOwned, U: VersionizeOwned> VersionizeOwned for (T, U) {
    type VersionedOwned = (T::VersionedOwned, U::VersionedOwned);

    fn versionize_owned(self) -> Self::VersionedOwned {
        (self.0.versionize_owned(), self.1.versionize_owned())
    }
}

impl<T: Unversionize, U: Unversionize> Unversionize for (T, U) {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok((T::unversionize(versioned.0)?, U::unversionize(versioned.1)?))
    }
}

impl<T: NotVersioned, U: NotVersioned> NotVersioned for (T, U) {}
