//! This example shows how to create a type that should not be versioned, even if it is
//! included in other versioned types

use serde::{Deserialize, Serialize};
use tfhe_versionable::{NotVersioned, Versionize, VersionsDispatch};

#[derive(Clone, Serialize, Deserialize, NotVersioned)]
struct MyStructNotVersioned {
    val: u32,
}

#[derive(Versionize)]
#[versionize(MyStructVersions)]
struct MyStruct {
    inner: MyStructNotVersioned,
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyStructVersions {
    V0(MyStruct),
}

fn main() {}
