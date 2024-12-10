//! A more realistic example of a codebase that evolves in time. Each "mod vN" should be seen as
//! a version of an application. The "backward_compat" mods can be in different files.

use tfhe_versionable::{Unversionize, Versionize};

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

    use backward_compat::{MyEnumVersions, MyStructVersions};

    #[derive(Serialize, Deserialize, Versionize)]
    #[versionize(MyEnumVersions)]
    pub enum MyEnum<T> {
        Variant0,
        Variant1 { count: u64 },
        Variant2(T),
    }

    #[derive(Serialize, Deserialize, Versionize)]
    #[versionize(MyStructVersions)]
    pub struct MyStruct<T> {
        pub count: u32,
        pub attr: T,
    }

    mod backward_compat {
        use std::convert::Infallible;

        use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

        use super::{MyEnum, MyStruct};

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

        #[derive(VersionsDispatch)]
        #[allow(unused)]
        pub enum MyEnumVersions<T> {
            V0(MyEnum<T>),
        }
    }
}

fn main() {
    let v0 = v0::MyStruct(37);

    let serialized = bincode::serialize(&v0.versionize()).unwrap();

    let v1 = v1::MyStruct::<u64>::unversionize(bincode::deserialize(&serialized).unwrap()).unwrap();

    assert_eq!(v0.0, v1.0);
    assert_eq!(v1.1, u64::default());

    let v2 = v2::MyStruct::<u64>::unversionize(bincode::deserialize(&serialized).unwrap()).unwrap();

    assert_eq!(v0.0, v2.count);
    assert_eq!(v2.attr, u64::default());
}

#[test]
fn test() {
    main()
}
