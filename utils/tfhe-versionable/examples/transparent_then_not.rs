//! This example is similar to the "transparent" one, except that the wrapper type is transparent at
//! a point in time, then converted into its own type that is not transparent.
//!
//! Here we have a type, `MyStructWrapper`, that was a transparent wrapper for `MyStruct` in the v0
//! and v1 of the application. `MyStruct` has been upgraded between v0 and v1. In v2,
//! `MyStructWrapper` was transformed into an enum. Since it was transparent before, it has no
//! history (dispatch enum) before v2.
//!
//! To make this work, we consider that the inner and the wrapper type share the same history up to
//! the version where the transparent attribute has been removed.

use std::convert::Infallible;

use tfhe_versionable::{Unversionize, Upgrade, Version, Versionize, VersionsDispatch};

// This type was transparent before, but it has now been transformed to a full type, for example by
// adding a new kind of metadata.
#[derive(Versionize)]
#[versionize(MyStructWrapperVersions)]
struct MyStructWrapper<T> {
    inner: MyStruct<T>,
    count: u64,
}

// We need to create a dispatch enum that follows the version numbers of the inner type, until the
// point where the wrapper is not transparent anymore.
#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyStructWrapperVersions<T> {
    V0(MyStructWrapperV0),
    V1(MyStructWrapperV1<T>),
    V2(MyStructWrapper<T>),
}

// We copy the upgrade path of the internal struct for the wrapper for the first 2 versions. To do
// that, we recreate the "transparent" `MyStructWrapper` from v0 and v1 and upgrade them by calling
// the upgrade method of the inner type.
#[derive(Version)]
#[repr(transparent)]
struct MyStructWrapperV0(MyStructV0);

impl<T: Default> Upgrade<MyStructWrapperV1<T>> for MyStructWrapperV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<MyStructWrapperV1<T>, Self::Error> {
        Ok(MyStructWrapperV1(self.0.upgrade()?))
    }
}

// Then we define the upgrade from the last transparent version to the first "full" version
#[derive(Version)]
#[repr(transparent)]
struct MyStructWrapperV1<T>(MyStruct<T>);

impl<T> Upgrade<MyStructWrapper<T>> for MyStructWrapperV1<T> {
    type Error = Infallible;

    fn upgrade(self) -> Result<MyStructWrapper<T>, Self::Error> {
        Ok(MyStructWrapper {
            inner: self.0,
            count: 0,
        })
    }
}

#[derive(Versionize)]
#[versionize(MyStructVersions)]
struct MyStruct<T> {
    attr: T,
    builtin: u32,
}

#[derive(Version)]
struct MyStructV0 {
    builtin: u32,
}

impl<T: Default> Upgrade<MyStruct<T>> for MyStructV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<MyStruct<T>, Self::Error> {
        Ok(MyStruct {
            attr: T::default(),
            builtin: self.builtin,
        })
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyStructVersions<T> {
    V0(MyStructV0),
    V1(MyStruct<T>),
}

// v0 of the app defined the type as a transparent wrapper
mod v0 {
    use tfhe_versionable::{Versionize, VersionsDispatch};

    #[derive(Versionize)]
    #[versionize(transparent)]
    pub(super) struct MyStructWrapper(pub(super) MyStruct);

    #[derive(Versionize)]
    #[versionize(MyStructVersions)]
    pub(super) struct MyStruct {
        pub(super) builtin: u32,
    }

    #[derive(VersionsDispatch)]
    #[allow(unused)]
    pub(super) enum MyStructVersions {
        V0(MyStruct),
    }
}

// In v1, MyStructWrapper is still transparent but MyStruct got an upgrade compared to v0.
mod v1 {
    use std::convert::Infallible;

    use tfhe_versionable::{Upgrade, Version, Versionize, VersionsDispatch};

    #[derive(Versionize)]
    #[repr(transparent)]
    struct MyStructWrapper<T>(MyStruct<T>);

    #[derive(Versionize)]
    #[versionize(MyStructVersions)]
    struct MyStruct<T> {
        attr: T,
        builtin: u32,
    }

    #[derive(Version)]
    struct MyStructV0 {
        builtin: u32,
    }

    impl<T: Default> Upgrade<MyStruct<T>> for MyStructV0 {
        type Error = Infallible;

        fn upgrade(self) -> Result<MyStruct<T>, Self::Error> {
            Ok(MyStruct {
                attr: T::default(),
                builtin: self.builtin,
            })
        }
    }

    #[derive(VersionsDispatch)]
    #[allow(unused)]
    enum MyStructVersions<T> {
        V0(MyStructV0),
        V1(MyStruct<T>),
    }
}

fn main() {
    let value = 1234;
    let ms = v0::MyStructWrapper(v0::MyStruct { builtin: value });

    let serialized = bincode::serialize(&ms.versionize()).unwrap();

    let unserialized =
        MyStructWrapper::<u64>::unversionize(bincode::deserialize(&serialized).unwrap()).unwrap();

    assert_eq!(unserialized.inner.builtin, value)
}

#[test]
fn test() {
    main()
}
