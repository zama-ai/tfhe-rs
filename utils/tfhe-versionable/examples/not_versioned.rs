//! This example shows how to create a type that should not be versioned, even if it is
//! included in other versioned types. Of course it means that if this type is modified in the
//! future, the parent struct should be updated.

use serde::{Deserialize, Serialize};
use tfhe_versionable::{NotVersioned, Versionize, VersionsDispatch};

#[derive(Clone, Serialize, Deserialize, NotVersioned)]
struct MyStructNotVersioned<Inner> {
    val: Inner,
}

#[derive(Versionize)]
#[versionize(MyStructVersions)]
struct MyStruct {
    inner: MyStructNotVersioned<u32>,
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyStructVersions {
    V0(MyStruct),
}

fn main() {
    let ms = MyStruct {
        inner: MyStructNotVersioned { val: 1234 },
    };

    let _versioned = ms.versionize();
}

#[test]
fn test() {
    main()
}
