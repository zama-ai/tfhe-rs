//! Example of a struct that include a field that is not versionable and is skipped during
//! versioning.
//!
//! This is similar to the `#[serde(skip)]` attribute of Serde.
//! With this attribute, the field is not included in the definition of the associated Version type.
//! During unversioning, the field is instantiated using a `Default` impl.

use std::convert::Infallible;
use std::io::Cursor;

use tfhe_versionable::{Unversionize, Upgrade, Version, Versionize, VersionsDispatch};

// This type is not versionable/serializable and should not be stored.
// It should however at least implement Default to be instantiable when the data is loaded.
#[derive(Default)]
struct NotVersionable(u64);

/// The previous version of our application
mod v0 {
    use super::NotVersionable;
    use tfhe_versionable::{Versionize, VersionsDispatch};

    #[derive(Versionize)]
    #[versionize(MyStructVersions)]
    pub(super) struct MyStruct {
        pub(super) val: u32,
        // This attribute is used to skip the versioning of the field
        // Also work with `#[serde(skip)]` if the field derives Serialize
        #[versionize(skip)]
        #[allow(dead_code)]
        pub(super) to_skip: NotVersionable,
    }

    #[derive(VersionsDispatch)]
    #[allow(unused)]
    pub(super) enum MyStructVersions {
        V0(MyStruct),
    }
}

#[derive(Version)]
struct MyStructV0 {
    val: u32,
    #[versionize(skip)]
    to_skip: NotVersionable,
}

#[derive(Versionize)]
#[versionize(MyStructVersions)]
struct MyStruct {
    val: u64,
    #[versionize(skip)]
    to_skip: NotVersionable,
}

impl Upgrade<MyStruct> for MyStructV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<MyStruct, Self::Error> {
        let val = self.val as u64;

        Ok(MyStruct {
            val,
            to_skip: self.to_skip,
        })
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyStructVersions {
    V0(MyStructV0),
    V1(MyStruct),
}

fn main() {
    let val = 64;
    let stru_v0 = v0::MyStruct {
        val,
        to_skip: NotVersionable(42), // The value will be lost during serialization
    };

    let mut ser = Vec::new();
    ciborium::ser::into_writer(&stru_v0.versionize(), &mut ser).unwrap();

    let unvers =
        MyStruct::unversionize(ciborium::de::from_reader(&mut Cursor::new(&ser)).unwrap()).unwrap();

    assert_eq!(unvers.val, val as u64);
    assert_eq!(unvers.to_skip.0, Default::default());
}

#[test]
fn test() {
    main()
}
