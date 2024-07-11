//! Test that backward compatibility works with various serde compatible formats

use std::io::Cursor;

use serde::{Deserialize, Serialize};
use tfhe_versionable::{NotVersioned, Unversionize, Versionize};

#[derive(Serialize, Deserialize, NotVersioned, Copy, Clone, Eq, PartialEq, Debug)]
struct MyU64(u64);

// Use a better default value for tests that 0
impl Default for MyU64 {
    fn default() -> Self {
        Self(6789)
    }
}

mod v0 {
    use serde::{Deserialize, Serialize};
    use tfhe_versionable::Versionize;

    use backward_compat::MyStructVersions;

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Versionize)]
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

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Versionize)]
    #[versionize(MyStructVersions)]
    pub struct MyStruct<T: Default>(pub u32, pub T);

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
        pub enum MyStructVersions<T: Default> {
            V0(MyStructV0),
            V1(MyStruct<T>),
        }
    }
}

mod v2 {
    use serde::{Deserialize, Serialize};
    use tfhe_versionable::Versionize;

    use backward_compat::MyStructVersions;

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Versionize)]
    #[versionize(MyStructVersions)]
    pub struct MyStruct<T: Default> {
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
        pub enum MyStructVersions<T: Default> {
            V0(MyStructV0),
            V1(MyStructV1<T>),
            V2(MyStruct<T>),
        }
    }
}

#[test]
fn test_bincode() {
    let v0 = v0::MyStruct(37);

    let v0_ser = bincode::serialize(&v0.versionize()).unwrap();

    let v1 = v1::MyStruct::<MyU64>::unversionize(bincode::deserialize(&v0_ser).unwrap()).unwrap();

    assert_eq!(v0.0, v1.0);
    assert_eq!(v1.1, MyU64::default());

    let v1_ser = bincode::serialize(&v1.versionize()).unwrap();

    let v2 = v2::MyStruct::<MyU64>::unversionize(bincode::deserialize(&v0_ser).unwrap()).unwrap();
    let v2_from_v1 =
        v2::MyStruct::<MyU64>::unversionize(bincode::deserialize(&v1_ser).unwrap()).unwrap();

    assert_eq!(v0.0, v2.count);
    assert_eq!(v2.attr, MyU64::default());
    assert_eq!(v2, v2_from_v1);
}

#[test]
fn test_cbor() {
    let v0 = v0::MyStruct(37);

    let mut v0_ser = Vec::new();
    ciborium::ser::into_writer(&v0.versionize(), &mut v0_ser).unwrap();

    let v1 = v1::MyStruct::<MyU64>::unversionize(
        ciborium::de::from_reader(&mut Cursor::new(&v0_ser)).unwrap(),
    )
    .unwrap();

    assert_eq!(v0.0, v1.0);
    assert_eq!(v1.1, MyU64::default());

    let mut v1_ser = Vec::new();
    ciborium::ser::into_writer(&v1.versionize(), &mut v1_ser).unwrap();

    let v2 = v2::MyStruct::<MyU64>::unversionize(
        ciborium::de::from_reader(&mut Cursor::new(&v0_ser)).unwrap(),
    )
    .unwrap();
    let v2_from_v1 = v2::MyStruct::<MyU64>::unversionize(
        ciborium::de::from_reader(&mut Cursor::new(&v1_ser)).unwrap(),
    )
    .unwrap();

    assert_eq!(v0.0, v2.count);
    assert_eq!(v2.attr, MyU64::default());
    assert_eq!(v2, v2_from_v1);
}

#[test]
fn test_messagepack() {
    let v0 = v0::MyStruct(37);

    let v0_ser = rmp_serde::to_vec(&v0.versionize()).unwrap();

    let v1 = v1::MyStruct::<MyU64>::unversionize(rmp_serde::from_slice(&v0_ser).unwrap()).unwrap();

    assert_eq!(v0.0, v1.0);
    assert_eq!(v1.1, MyU64::default());

    let v1_ser = rmp_serde::to_vec(&v1.versionize()).unwrap();

    let v2 = v2::MyStruct::<MyU64>::unversionize(rmp_serde::from_slice(&v0_ser).unwrap()).unwrap();
    let v2_from_v1 =
        v2::MyStruct::<MyU64>::unversionize(rmp_serde::from_slice(&v1_ser).unwrap()).unwrap();

    assert_eq!(v0.0, v2.count);
    assert_eq!(v2.attr, MyU64::default());
    assert_eq!(v2, v2_from_v1);
}

#[test]
fn test_json() {
    let v0 = v0::MyStruct(37);

    let v0_ser = serde_json::to_string(&v0.versionize()).unwrap();

    let v1 = v1::MyStruct::<MyU64>::unversionize(serde_json::from_str(&v0_ser).unwrap()).unwrap();

    assert_eq!(v0.0, v1.0);
    assert_eq!(v1.1, MyU64::default());

    let v1_ser = serde_json::to_string(&v1.versionize()).unwrap();

    let v2 = v2::MyStruct::<MyU64>::unversionize(serde_json::from_str(&v0_ser).unwrap()).unwrap();
    let v2_from_v1 =
        v2::MyStruct::<MyU64>::unversionize(serde_json::from_str(&v1_ser).unwrap()).unwrap();

    assert_eq!(v0.0, v2.count);
    assert_eq!(v2.attr, MyU64::default());
    assert_eq!(v2, v2_from_v1);
}

#[test]
fn test_yaml() {
    let v0 = v0::MyStruct(37);

    let v0_ser = serde_yaml::to_string(&v0.versionize()).unwrap();

    let v1 = v1::MyStruct::<MyU64>::unversionize(serde_yaml::from_str(&v0_ser).unwrap()).unwrap();

    assert_eq!(v0.0, v1.0);
    assert_eq!(v1.1, MyU64::default());

    let v1_ser = serde_yaml::to_string(&v1.versionize()).unwrap();

    let v2 = v2::MyStruct::<MyU64>::unversionize(serde_yaml::from_str(&v0_ser).unwrap()).unwrap();
    let v2_from_v1 =
        v2::MyStruct::<MyU64>::unversionize(serde_yaml::from_str(&v1_ser).unwrap()).unwrap();

    assert_eq!(v0.0, v2.count);
    assert_eq!(v2.attr, MyU64::default());
    assert_eq!(v2, v2_from_v1);
}

#[test]
fn test_toml() {
    let v0 = v0::MyStruct(37);

    let v0_ser = toml::to_string(&v0.versionize()).unwrap();

    let v1 = v1::MyStruct::<MyU64>::unversionize(toml::from_str(&v0_ser).unwrap()).unwrap();

    assert_eq!(v0.0, v1.0);
    assert_eq!(v1.1, MyU64::default());

    let v1_ser = toml::to_string(&v1.versionize()).unwrap();

    let v2 = v2::MyStruct::<MyU64>::unversionize(toml::from_str(&v0_ser).unwrap()).unwrap();
    let v2_from_v1 = v2::MyStruct::<MyU64>::unversionize(toml::from_str(&v1_ser).unwrap()).unwrap();

    assert_eq!(v0.0, v2.count);
    assert_eq!(v2.attr, MyU64::default());
    assert_eq!(v2, v2_from_v1);
}
