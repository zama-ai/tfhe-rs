//! The simple example, with manual implementation of the versionize trait

use std::convert::Infallible;

use serde::{Deserialize, Serialize};
use tfhe_versionable::{Unversionize, UnversionizeError, Upgrade, Versionize, VersionizeOwned};

struct MyStruct<T> {
    attr: T,
    builtin: u32,
}

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize)]
struct MyStructVersion<'vers, T: 'vers + Versionize> {
    attr: T::Versioned<'vers>,
    builtin: u32,
}

#[derive(Serialize, Deserialize)]
struct MyStructVersionOwned<T: VersionizeOwned> {
    attr: T::VersionedOwned,
    builtin: u32,
}

impl<T: Versionize + Serialize> Versionize for MyStruct<T> {
    type Versioned<'vers>
        = MyStructVersionsDispatch<'vers, T>
    where
        Self: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        let ver = MyStructVersion {
            attr: self.attr.versionize(),
            builtin: self.builtin,
        };
        MyStructVersionsDispatch::V1(ver)
    }
}

impl<T: VersionizeOwned + Serialize + for<'de> Deserialize<'de>> VersionizeOwned for MyStruct<T> {
    type VersionedOwned = MyStructVersionsDispatchOwned<T>;

    fn versionize_owned(self) -> Self::VersionedOwned {
        let ver = MyStructVersionOwned {
            attr: self.attr.versionize_owned(),
            builtin: self.builtin,
        };
        MyStructVersionsDispatchOwned::V1(ver)
    }
}

impl<T: Unversionize + Serialize + for<'de> Deserialize<'de> + Default> Unversionize
    for MyStruct<T>
{
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        match versioned {
            MyStructVersionsDispatchOwned::V0(v0) => v0
                .upgrade()
                .map_err(|e| UnversionizeError::upgrade("V0", "V1", e)),
            MyStructVersionsDispatchOwned::V1(v1) => Ok(Self {
                attr: T::unversionize(v1.attr)?,
                builtin: v1.builtin,
            }),
        }
    }
}

// Since MyStructV0 is only composed of built-in types, it does not need recursive versioning and
// can be used as its own "version type".
#[derive(Serialize)]
enum MyStructVersionsDispatch<'vers, T: 'vers + Versionize> {
    #[allow(dead_code)]
    V0(MyStructV0),
    #[allow(dead_code)]
    V1(MyStructVersion<'vers, T>),
}

#[derive(Serialize, Deserialize)]
enum MyStructVersionsDispatchOwned<T: VersionizeOwned> {
    V0(MyStructV0),
    V1(MyStructVersionOwned<T>),
}

mod v0 {
    use serde::{Deserialize, Serialize};
    use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};

    #[derive(Serialize, Deserialize)]
    pub(super) struct MyStruct {
        pub(super) builtin: u32,
    }

    impl Versionize for MyStruct {
        type Versioned<'vers> = MyStructVersionsDispatch;

        fn versionize(&self) -> Self::Versioned<'_> {
            let ver = MyStruct {
                builtin: self.builtin,
            };
            MyStructVersionsDispatch::V0(ver)
        }
    }

    impl VersionizeOwned for MyStruct {
        type VersionedOwned = MyStructVersionsDispatchOwned;

        fn versionize_owned(self) -> Self::VersionedOwned {
            MyStructVersionsDispatchOwned::V0(self)
        }
    }

    impl Unversionize for MyStruct {
        fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
            match versioned {
                MyStructVersionsDispatchOwned::V0(v0) => Ok(v0),
            }
        }
    }

    #[derive(Serialize)]
    #[allow(dead_code)]
    pub(super) enum MyStructVersionsDispatch {
        V0(MyStruct),
    }

    #[derive(Serialize, Deserialize)]
    pub(super) enum MyStructVersionsDispatchOwned {
        V0(MyStruct),
    }
}

fn main() {
    let value = 1234;
    let ms = v0::MyStruct { builtin: value };

    let serialized = bincode::serialize(&ms.versionize()).unwrap();

    let unserialized =
        MyStruct::<u64>::unversionize(bincode::deserialize(&serialized).unwrap()).unwrap();

    assert_eq!(unserialized.builtin, value);
    assert_eq!(unserialized.attr, u64::default());
}

#[test]
fn test() {
    main()
}
