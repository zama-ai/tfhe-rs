//! This example shows how to use the `bound` attribute to add a specific bound that is needed to be
//! able to derive `Versionize`

use serde::de::DeserializeOwned;
use serde::Serialize;
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionsDispatch};

// Example of a simple struct with a manual Versionize impl that requires a specific bound
struct MyStruct<T> {
    val: T,
}

impl<T: Serialize + DeserializeOwned + ToOwned<Owned = T>> Versionize for MyStruct<T> {
    type Versioned<'vers> = &'vers T where T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        &self.val
    }

    type VersionedOwned = T;

    fn versionize_owned(&self) -> Self::VersionedOwned {
        self.val.to_owned()
    }
}

impl<T: Serialize + DeserializeOwned + ToOwned<Owned = T>> Unversionize for MyStruct<T> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(MyStruct { val: versioned })
    }
}

// The additional bound can be specified on the parent struct using this attribute. This is similar
// to what serde does. You can also use #[versionize(OuterVersions, bound(unversionize = "T:
// ToOwned<Owned = T>"))] if the bound is only needed for the Unversionize impl.
#[derive(Versionize)]
#[versionize(OuterVersions, bound = "T: ToOwned<Owned = T>")]
struct Outer<T> {
    inner: MyStruct<T>,
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum OuterVersions<T: ToOwned<Owned = T>> {
    V0(Outer<T>),
}

fn main() {}
