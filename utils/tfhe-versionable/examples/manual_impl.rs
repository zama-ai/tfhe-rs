//! The simple example, with manual implementation of the versionize trait

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tfhe_versionable::{Unversionize, UnversionizeError, Upgrade, Versionize};

struct MyStruct<T: Default> {
    attr: T,
    builtin: u32,
}

#[derive(Serialize, Deserialize)]
struct MyStructV0 {
    builtin: u32,
}

impl<T: Default> Upgrade<MyStruct<T>> for MyStructV0 {
    fn upgrade(self) -> Result<MyStruct<T>, String> {
        Ok(MyStruct {
            attr: T::default(),
            builtin: self.builtin,
        })
    }
}

#[derive(Serialize)]
struct MyStructVersion<'vers, T: 'vers + Default + Versionize> {
    attr: T::Versioned<'vers>,
    builtin: u32,
}

#[derive(Serialize, Deserialize)]
struct MyStructVersionOwned<T: Default + Versionize> {
    attr: T::VersionedOwned,
    builtin: u32,
}

impl<T: Default + Versionize + Serialize + DeserializeOwned> Versionize for MyStruct<T> {
    type Versioned<'vers> = MyStructVersionsDispatch<'vers, T>
    where
        Self: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        let ver = MyStructVersion {
            attr: self.attr.versionize(),
            builtin: self.builtin,
        };
        MyStructVersionsDispatch::V1(ver)
    }

    type VersionedOwned = MyStructVersionsDispatchOwned<T>;

    fn versionize_owned(&self) -> Self::VersionedOwned {
        let ver = MyStructVersionOwned {
            attr: self.attr.versionize_owned(),
            builtin: self.builtin,
        };
        MyStructVersionsDispatchOwned::V1(ver)
    }
}

impl<T: Default + Versionize + Unversionize + Serialize + DeserializeOwned> Unversionize
    for MyStruct<T>
{
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        match versioned {
            MyStructVersionsDispatchOwned::V0(v0) => v0
                .upgrade()
                .map_err(|e| UnversionizeError::upgrade("V0", "V1", &e)),
            MyStructVersionsDispatchOwned::V1(v1) => Ok(Self {
                attr: T::unversionize(v1.attr)?,
                builtin: v1.builtin,
            }),
        }
    }
}

#[derive(Serialize)]
#[allow(dead_code)]
enum MyStructVersionsDispatch<'vers, T: 'vers + Default + Versionize> {
    V0(MyStructV0),
    V1(MyStructVersion<'vers, T>),
}

#[derive(Serialize, Deserialize)]
enum MyStructVersionsDispatchOwned<T: Default + Versionize> {
    V0(MyStructV0),
    V1(MyStructVersionOwned<T>),
}

fn main() {
    let ms = MyStruct {
        attr: 37u64,
        builtin: 1234,
    };

    let serialized = bincode::serialize(&ms.versionize()).unwrap();

    let _unserialized = MyStruct::<u64>::unversionize(bincode::deserialize(&serialized).unwrap());
}
