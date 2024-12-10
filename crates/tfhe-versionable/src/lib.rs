//! Provides a way to add versioning informations/backward compatibility on rust types used for
//! serialization.
//!
//! This crates provides a set of traits [`Versionize`] and [`Unversionize`] that perform a
//! conversion between a type and its `Versioned` counterpart. The versioned type is an enum
//! that has a variant for each version of the type.
//! These traits can be generated using the [`tfhe_versionable_derive::Versionize`] proc macro.

pub mod deprecation;
pub mod derived_traits;
pub mod upgrade;

use aligned_vec::{ABox, AVec};
use deprecation::DeprecatedVersionError;
use num_complex::Complex;
use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::error::Error;
use std::fmt::Display;
use std::marker::PhantomData;
use std::num::Wrapping;
use std::sync::Arc;

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

/// This trait is used as a proxy to be more flexible when deriving Versionize for `Vec<T>`.
///
/// This way, we can chose to skip versioning `Vec<T>` if T is a native types but still versionize
/// in a loop if T is a custom type.
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
        source: Box<dyn Error + Send + Sync>,
    },

    /// An error has been returned in the conversion method provided by the `try_from` parameter
    /// attribute
    Conversion {
        from_type: String,
        source: Box<dyn Error + Send + Sync>,
    },

    /// The length of a statically sized array is wrong
    ArrayLength {
        expected_size: usize,
        found_size: usize,
    },

    /// A deprecated version has been found
    DeprecatedVersion(DeprecatedVersionError),
}

impl Display for UnversionizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upgrade {
                from_vers,
                into_vers,
                source,
            } => write!(
                f,
                "Failed to upgrade from {from_vers} into {into_vers}: {source}"
            ),
            Self::Conversion { from_type, source } => {
                write!(f, "Failed to convert from {from_type}: {source}")
            }
            Self::ArrayLength {
                expected_size,
                found_size,
            } => {
                write!(
                    f,
                    "Expected array of size {expected_size}, found array of size {found_size}"
                )
            }
            Self::DeprecatedVersion(deprecation_error) => deprecation_error.fmt(f),
        }
    }
}

impl Error for UnversionizeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            UnversionizeError::Upgrade { source, .. } => Some(source.as_ref()),
            UnversionizeError::Conversion { source, .. } => Some(source.as_ref()),
            UnversionizeError::ArrayLength { .. } => None,
            UnversionizeError::DeprecatedVersion(_) => None,
        }
    }
}

impl UnversionizeError {
    pub fn upgrade<E: Error + 'static + Send + Sync>(
        from_vers: &str,
        into_vers: &str,
        source: E,
    ) -> Self {
        Self::Upgrade {
            from_vers: from_vers.to_string(),
            into_vers: into_vers.to_string(),
            source: Box::new(source),
        }
    }

    pub fn conversion<E: Error + 'static + Send + Sync>(from_type: &str, source: E) -> Self {
        Self::Conversion {
            from_type: from_type.to_string(),
            source: Box::new(source),
        }
    }
}

impl From<Infallible> for UnversionizeError {
    fn from(_value: Infallible) -> Self {
        panic!("Infallible error type should never be reached")
    }
}

/// This trait means that we can convert from a versioned enum into the target type.
///
/// This trait can only be implemented on Owned/static types, whereas `Versionize` can also be
/// implemented on reference types.
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
    type VersionedSlice<'vers>
        = &'vers [T]
    where
        T: 'vers;

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

impl<T: Versionize> Versionize for Wrapping<T> {
    type Versioned<'vers>
        = Wrapping<T::Versioned<'vers>>
    where
        T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        Wrapping(self.0.versionize())
    }
}

impl<T: VersionizeOwned> VersionizeOwned for Wrapping<T> {
    type VersionedOwned = Wrapping<T::VersionedOwned>;

    fn versionize_owned(self) -> Self::VersionedOwned {
        Wrapping(T::versionize_owned(self.0))
    }
}

impl<T: Unversionize> Unversionize for Wrapping<T> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(Wrapping(T::unversionize(versioned.0)?))
    }
}

impl<T: NotVersioned> NotVersioned for Wrapping<T> {}

impl<T: Versionize> Versionize for Box<T> {
    type Versioned<'vers>
        = T::Versioned<'vers>
    where
        T: 'vers;

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

impl<T: VersionizeSlice + Clone> Versionize for Box<[T]> {
    type Versioned<'vers>
        = T::VersionedSlice<'vers>
    where
        T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        T::versionize_slice(self)
    }
}

impl<T: VersionizeVec + Clone> VersionizeOwned for Box<[T]> {
    type VersionedOwned = T::VersionedVec;

    fn versionize_owned(self) -> Self::VersionedOwned {
        T::versionize_vec(self.to_vec())
    }
}

impl<T: UnversionizeVec + Clone> Unversionize for Box<[T]> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        T::unversionize_vec(versioned).map(|unver| unver.into_boxed_slice())
    }
}

impl<T: VersionizeVec + Clone> VersionizeVec for Box<[T]> {
    type VersionedVec = Vec<T::VersionedVec>;

    fn versionize_vec(vec: Vec<Self>) -> Self::VersionedVec {
        vec.into_iter()
            .map(|inner| inner.versionize_owned())
            .collect()
    }
}

impl<T: VersionizeSlice> VersionizeSlice for Box<[T]> {
    type VersionedSlice<'vers>
        = Vec<T::VersionedSlice<'vers>>
    where
        T: 'vers;

    fn versionize_slice(slice: &[Self]) -> Self::VersionedSlice<'_> {
        slice
            .iter()
            .map(|inner| T::versionize_slice(inner))
            .collect()
    }
}

impl<T: UnversionizeVec + Clone> UnversionizeVec for Box<[T]> {
    fn unversionize_vec(versioned: Self::VersionedVec) -> Result<Vec<Self>, UnversionizeError> {
        versioned
            .into_iter()
            .map(Box::<[T]>::unversionize)
            .collect()
    }
}

impl<T: VersionizeSlice> Versionize for Vec<T> {
    type Versioned<'vers>
        = T::VersionedSlice<'vers>
    where
        T: 'vers;

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

impl<T: UnversionizeVec> Unversionize for Vec<T> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        T::unversionize_vec(versioned)
    }
}

impl<T: VersionizeVec> VersionizeVec for Vec<T> {
    type VersionedVec = Vec<T::VersionedVec>;

    fn versionize_vec(vec: Vec<Self>) -> Self::VersionedVec {
        vec.into_iter()
            .map(|inner| T::versionize_vec(inner))
            .collect()
    }
}

impl<T: VersionizeSlice> VersionizeSlice for Vec<T> {
    type VersionedSlice<'vers>
        = Vec<T::VersionedSlice<'vers>>
    where
        T: 'vers;

    fn versionize_slice(slice: &[Self]) -> Self::VersionedSlice<'_> {
        slice
            .iter()
            .map(|inner| T::versionize_slice(inner))
            .collect()
    }
}

impl<T: UnversionizeVec> UnversionizeVec for Vec<T> {
    fn unversionize_vec(versioned: Self::VersionedVec) -> Result<Vec<Self>, UnversionizeError> {
        versioned
            .into_iter()
            .map(|inner| T::unversionize_vec(inner))
            .collect()
    }
}

impl<T: VersionizeSlice + Clone> Versionize for [T] {
    type Versioned<'vers>
        = T::VersionedSlice<'vers>
    where
        T: 'vers;

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

impl<T: VersionizeVec + Clone> VersionizeVec for &[T] {
    type VersionedVec = Vec<T::VersionedVec>;

    fn versionize_vec(vec: Vec<Self>) -> Self::VersionedVec {
        vec.into_iter()
            .map(|inner| T::versionize_vec(inner.to_vec()))
            .collect()
    }
}

impl<'a, T: VersionizeSlice> VersionizeSlice for &'a [T] {
    type VersionedSlice<'vers>
        = Vec<T::VersionedSlice<'vers>>
    where
        T: 'vers,
        'a: 'vers;

    fn versionize_slice(slice: &[Self]) -> Self::VersionedSlice<'_> {
        slice
            .iter()
            .map(|inner| T::versionize_slice(inner))
            .collect()
    }
}

// Since serde doesn't support arbitrary length arrays with const generics, the array
// is converted to a slice/vec.
impl<const N: usize, T: VersionizeSlice> Versionize for [T; N] {
    type Versioned<'vers>
        = T::VersionedSlice<'vers>
    where
        T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        T::versionize_slice(self)
    }
}

impl<const N: usize, T: VersionizeVec + Clone> VersionizeOwned for [T; N] {
    type VersionedOwned = T::VersionedVec;

    fn versionize_owned(self) -> Self::VersionedOwned {
        T::versionize_vec(self.to_vec())
    }
}

impl<const N: usize, T: UnversionizeVec + Clone> Unversionize for [T; N] {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        let v = T::unversionize_vec(versioned)?;
        let boxed_slice = v.into_boxed_slice();
        TryInto::<Box<[T; N]>>::try_into(boxed_slice)
            .map(|array| *array)
            .map_err(|slice| UnversionizeError::ArrayLength {
                expected_size: N,
                found_size: slice.len(),
            })
    }
}

impl<const N: usize, T: VersionizeVec + Clone> VersionizeVec for [T; N] {
    type VersionedVec = Vec<T::VersionedVec>;

    fn versionize_vec(vec: Vec<Self>) -> Self::VersionedVec {
        vec.into_iter()
            .map(|inner| inner.versionize_owned())
            .collect()
    }
}

impl<const N: usize, T: VersionizeSlice> VersionizeSlice for [T; N] {
    type VersionedSlice<'vers>
        = Vec<T::VersionedSlice<'vers>>
    where
        T: 'vers;

    fn versionize_slice(slice: &[Self]) -> Self::VersionedSlice<'_> {
        slice
            .iter()
            .map(|inner| T::versionize_slice(inner))
            .collect()
    }
}

impl<const N: usize, T: UnversionizeVec + Clone> UnversionizeVec for [T; N] {
    fn unversionize_vec(versioned: Self::VersionedVec) -> Result<Vec<Self>, UnversionizeError> {
        versioned.into_iter().map(<[T; N]>::unversionize).collect()
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
    type Versioned<'vers>
        = Option<T::Versioned<'vers>>
    where
        T: 'vers;

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
    type Versioned<'vers>
        = Self
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

impl<T: Versionize> Versionize for Arc<T> {
    type Versioned<'vers>
        = T::Versioned<'vers>
    where
        T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.as_ref().versionize()
    }
}

impl<T: VersionizeOwned + Clone> VersionizeOwned for Arc<T> {
    type VersionedOwned = T::VersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        Arc::unwrap_or_clone(self).versionize_owned()
    }
}

impl<T: Unversionize + Clone> Unversionize for Arc<T> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(Arc::new(T::unversionize(versioned)?))
    }
}

impl<T: NotVersioned> NotVersioned for Arc<T> {}

impl<T: Versionize> Versionize for Complex<T> {
    type Versioned<'vers>
        = Complex<T::Versioned<'vers>>
    where
        T: 'vers;

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
    type Versioned<'vers>
        = T::Versioned<'vers>
    where
        T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.as_ref().versionize()
    }
}

impl<T: VersionizeOwned + Clone> VersionizeOwned for ABox<T> {
    // Alignment doesn't matter for versioned types
    type VersionedOwned = Box<T::VersionedOwned>;

    fn versionize_owned(self) -> Self::VersionedOwned {
        Box::new(T::versionize_owned(T::clone(&self)))
    }
}

impl<T: Unversionize + Clone> Unversionize for ABox<T>
where
    T::VersionedOwned: Clone,
{
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(ABox::new(0, T::unversionize((*versioned).to_owned())?))
    }
}

impl<T: VersionizeSlice + Clone> Versionize for ABox<[T]> {
    type Versioned<'vers>
        = T::VersionedSlice<'vers>
    where
        T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        T::versionize_slice(self)
    }
}

impl<T: VersionizeVec + Clone> VersionizeOwned for ABox<[T]> {
    type VersionedOwned = T::VersionedVec;

    fn versionize_owned(self) -> Self::VersionedOwned {
        T::versionize_vec(self.iter().cloned().collect())
    }
}

impl<T: UnversionizeVec + Clone> Unversionize for ABox<[T]> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        T::unversionize_vec(versioned).map(|unver| AVec::from_iter(0, unver).into_boxed_slice())
    }
}

impl<T: NotVersioned + Clone + Serialize + DeserializeOwned> NotVersioned for ABox<[T]> {}

impl<T: VersionizeSlice> Versionize for AVec<T> {
    type Versioned<'vers>
        = T::VersionedSlice<'vers>
    where
        T: 'vers;

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

impl Versionize for () {
    type Versioned<'vers> = ();

    fn versionize(&self) -> Self::Versioned<'_> {}
}

impl VersionizeOwned for () {
    type VersionedOwned = ();

    fn versionize_owned(self) -> Self::VersionedOwned {}
}

impl Unversionize for () {
    fn unversionize(_versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(())
    }
}

impl NotVersioned for () {}

// TODO: use a macro for more tuple sizes
impl<T: Versionize, U: Versionize> Versionize for (T, U) {
    type Versioned<'vers>
        = (T::Versioned<'vers>, U::Versioned<'vers>)
    where
        T: 'vers,
        U: 'vers;

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

impl<T: Versionize, U: Versionize> VersionizeSlice for (T, U) {
    type VersionedSlice<'vers>
        = Vec<(T::Versioned<'vers>, U::Versioned<'vers>)>
    where
        T: 'vers,
        U: 'vers;

    fn versionize_slice(slice: &[Self]) -> Self::VersionedSlice<'_> {
        slice
            .iter()
            .map(|(t, u)| (t.versionize(), u.versionize()))
            .collect()
    }
}

impl<T: VersionizeOwned, U: VersionizeOwned> VersionizeVec for (T, U) {
    type VersionedVec = Vec<(T::VersionedOwned, U::VersionedOwned)>;

    fn versionize_vec(vec: Vec<Self>) -> Self::VersionedVec {
        vec.into_iter()
            .map(|(t, u)| (t.versionize_owned(), u.versionize_owned()))
            .collect()
    }
}

impl<T: Unversionize, U: Unversionize> UnversionizeVec for (T, U) {
    fn unversionize_vec(versioned: Self::VersionedVec) -> Result<Vec<Self>, UnversionizeError> {
        versioned
            .into_iter()
            .map(|(t, u)| Ok((T::unversionize(t)?, U::unversionize(u)?)))
            .collect()
    }
}

impl<T: Versionize, U: Versionize, V: Versionize> Versionize for (T, U, V) {
    type Versioned<'vers>
        = (
        T::Versioned<'vers>,
        U::Versioned<'vers>,
        V::Versioned<'vers>,
    )
    where
        T: 'vers,
        U: 'vers,
        V: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        (
            self.0.versionize(),
            self.1.versionize(),
            self.2.versionize(),
        )
    }
}

impl<T: VersionizeOwned, U: VersionizeOwned, V: VersionizeOwned> VersionizeOwned for (T, U, V) {
    type VersionedOwned = (T::VersionedOwned, U::VersionedOwned, V::VersionedOwned);

    fn versionize_owned(self) -> Self::VersionedOwned {
        (
            self.0.versionize_owned(),
            self.1.versionize_owned(),
            self.2.versionize_owned(),
        )
    }
}

impl<T: Unversionize, U: Unversionize, V: Unversionize> Unversionize for (T, U, V) {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok((
            T::unversionize(versioned.0)?,
            U::unversionize(versioned.1)?,
            V::unversionize(versioned.2)?,
        ))
    }
}

impl<T: Versionize, U: Versionize, V: Versionize> VersionizeSlice for (T, U, V) {
    type VersionedSlice<'vers>
        = Vec<(
        T::Versioned<'vers>,
        U::Versioned<'vers>,
        V::Versioned<'vers>,
    )>
    where
        T: 'vers,
        U: 'vers,
        V: 'vers;

    fn versionize_slice(slice: &[Self]) -> Self::VersionedSlice<'_> {
        slice
            .iter()
            .map(|(t, u, v)| (t.versionize(), u.versionize(), v.versionize()))
            .collect()
    }
}

impl<T: VersionizeOwned, U: VersionizeOwned, V: VersionizeOwned> VersionizeVec for (T, U, V) {
    type VersionedVec = Vec<(T::VersionedOwned, U::VersionedOwned, V::VersionedOwned)>;

    fn versionize_vec(vec: Vec<Self>) -> Self::VersionedVec {
        vec.into_iter()
            .map(|(t, u, v)| {
                (
                    t.versionize_owned(),
                    u.versionize_owned(),
                    v.versionize_owned(),
                )
            })
            .collect()
    }
}

impl<T: Unversionize, U: Unversionize, V: Unversionize> UnversionizeVec for (T, U, V) {
    fn unversionize_vec(versioned: Self::VersionedVec) -> Result<Vec<Self>, UnversionizeError> {
        versioned
            .into_iter()
            .map(|(t, u, v)| {
                Ok((
                    T::unversionize(t)?,
                    U::unversionize(u)?,
                    V::unversionize(v)?,
                ))
            })
            .collect()
    }
}

// converts to `Vec<T::Versioned>` for the versioned type, so we don't have to derive
// Eq/Hash on it.
impl<T: Versionize> Versionize for HashSet<T> {
    type Versioned<'vers>
        = Vec<T::Versioned<'vers>>
    where
        T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.iter().map(|val| val.versionize()).collect()
    }
}

impl<T: VersionizeOwned> VersionizeOwned for HashSet<T> {
    type VersionedOwned = Vec<T::VersionedOwned>;

    fn versionize_owned(self) -> Self::VersionedOwned {
        self.into_iter().map(|val| val.versionize_owned()).collect()
    }
}

impl<T: Unversionize + std::hash::Hash + Eq> Unversionize for HashSet<T> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        versioned
            .into_iter()
            .map(|val| T::unversionize(val))
            .collect()
    }
}

// converts to `Vec<(K::Versioned, V::Versioned)>` for the versioned type, so we don't have to
// derive Eq/Hash on it.
impl<K: Versionize, V: Versionize> Versionize for HashMap<K, V> {
    type Versioned<'vers>
        = Vec<(K::Versioned<'vers>, V::Versioned<'vers>)>
    where
        K: 'vers,
        V: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.iter()
            .map(|(key, val)| (key.versionize(), val.versionize()))
            .collect()
    }
}

impl<K: VersionizeOwned, V: VersionizeOwned> VersionizeOwned for HashMap<K, V> {
    type VersionedOwned = Vec<(K::VersionedOwned, V::VersionedOwned)>;

    fn versionize_owned(self) -> Self::VersionedOwned {
        self.into_iter()
            .map(|(key, val)| (key.versionize_owned(), val.versionize_owned()))
            .collect()
    }
}

impl<K: Unversionize + std::hash::Hash + Eq, V: Unversionize> Unversionize for HashMap<K, V> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        versioned
            .into_iter()
            .map(|(key, val)| Ok((K::unversionize(key)?, V::unversionize(val)?)))
            .collect()
    }
}
