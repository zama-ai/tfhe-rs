//! Example of a version deprecation, to remove support for types up to a chosen point.
//!
//! In this example, we have an application with 3 versions: v0, v1, v2. We know that v0 and v1 are
//! not used in the wild, so we want to remove backward compatibility with them to be able to
//! clean-up some code. We can use this feature to create a v3 version that will be compatible with
//! v2 but remove support for the previous ones.

use tfhe_versionable::{Unversionize, Versionize};

// The newer version of the app, where you want to cut compatibility with versions that are too old
mod v3 {
    use serde::{Deserialize, Serialize};
    use tfhe_versionable::Versionize;

    use backward_compat::MyStructVersions;

    #[derive(Serialize, Deserialize, Versionize)]
    #[versionize(MyStructVersions)]
    pub struct MyStruct<T> {
        pub count: u32,
        pub attr: T,
    }

    mod backward_compat {
        use tfhe_versionable::deprecation::{Deprecable, Deprecated};
        use tfhe_versionable::VersionsDispatch;

        use super::MyStruct;

        // The `Deprecation` trait will be used to give meaningful error messages to you users
        impl<T> Deprecable for MyStruct<T> {
            // The name of the type, as seen by the user
            const TYPE_NAME: &'static str = "MyStruct";

            // The minimum version of the application/library that we still support. You can include
            // the name of your app/library.
            const MIN_SUPPORTED_APP_VERSION: &'static str = "app v2";
        }

        // Replace the deprecation versions with the `Deprecated` type in the dispatch enum
        #[derive(VersionsDispatch)]
        #[allow(unused)]
        pub enum MyStructVersions<T> {
            V0(Deprecated<MyStruct<T>>),
            V1(Deprecated<MyStruct<T>>),
            V2(MyStruct<T>),
        }
    }
}

fn main() {
    // A version that will be deprecated
    let v0 = v0::MyStruct(37);

    let serialized = bincode::serialize(&v0.versionize()).unwrap();

    // We can upgrade it until the last supported version
    let v2 = v2::MyStruct::<u64>::unversionize(bincode::deserialize(&serialized).unwrap()).unwrap();

    assert_eq!(v0.0, v2.count);
    assert_eq!(v2.attr, u64::default());

    // But trying to upgrade it into the newer version with dropped support will fail.
    let v3_deser: Result<v3::MyStruct<u64>, _> = bincode::deserialize(&serialized);

    assert!(v3_deser.is_err());

    // However you can still update from the last supported version
    let _serialized_v2 = bincode::serialize(&v2.versionize()).unwrap();
}

// Older versions of the application

mod v0 {
    use serde::{Deserialize, Serialize};
    use tfhe_versionable::Versionize;

    use backward_compat::MyStructVersions;

    #[derive(Serialize, Deserialize, Versionize)]
    #[versionize(MyStructVersions)]
    pub struct MyStruct(pub u32);

    mod backward_compat {
        use tfhe_versionable::VersionsDispatch;

        use super::MyStruct;

        #[derive(VersionsDispatch)]
        #[allow(unused)]
        pub enum MyStructVersions {
            V0(MyStruct),
        }
    }
}

mod v1 {
    use serde::{Deserialize, Serialize};
    use tfhe_versionable::Versionize;

    use backward_compat::MyStructVersions;

    #[derive(Serialize, Deserialize, Versionize)]
    #[versionize(MyStructVersions)]
    pub struct MyStruct<T>(pub u32, pub T);

    mod backward_compat {
        use std::convert::Infallible;

        use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

        use super::MyStruct;

        #[derive(Version)]
        pub struct MyStructV0(pub u32);

        impl<T: Default> Upgrade<MyStruct<T>> for MyStructV0 {
            type Error = Infallible;

            fn upgrade(self) -> Result<MyStruct<T>, Self::Error> {
                Ok(MyStruct(self.0, T::default()))
            }
        }

        #[derive(VersionsDispatch)]
        #[allow(unused)]
        pub enum MyStructVersions<T> {
            V0(MyStructV0),
            V1(MyStruct<T>),
        }
    }
}

mod v2 {
    use serde::{Deserialize, Serialize};
    use tfhe_versionable::Versionize;

    use backward_compat::MyStructVersions;

    #[derive(Serialize, Deserialize, Versionize)]
    #[versionize(MyStructVersions)]
    pub struct MyStruct<T> {
        pub count: u32,
        pub attr: T,
    }

    mod backward_compat {
        use std::convert::Infallible;

        use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

        use super::MyStruct;

        #[derive(Version)]
        pub struct MyStructV0(pub u32);

        impl<T: Default> Upgrade<MyStructV1<T>> for MyStructV0 {
            type Error = Infallible;

            fn upgrade(self) -> Result<MyStructV1<T>, Self::Error> {
                Ok(MyStructV1(self.0, T::default()))
            }
        }

        #[derive(Version)]
        pub struct MyStructV1<T>(pub u32, pub T);

        impl<T: Default> Upgrade<MyStruct<T>> for MyStructV1<T> {
            type Error = Infallible;

            fn upgrade(self) -> Result<MyStruct<T>, Self::Error> {
                Ok(MyStruct {
                    count: self.0,
                    attr: T::default(),
                })
            }
        }

        #[derive(VersionsDispatch)]
        #[allow(unused)]
        pub enum MyStructVersions<T> {
            V0(MyStructV0),
            V1(MyStructV1<T>),
            V2(MyStruct<T>),
        }
    }
}

#[test]
fn test() {
    main()
}
