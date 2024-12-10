use static_assertions::assert_impl_all;

use serde::{Deserialize, Serialize};
use tfhe_versionable::{NotVersioned, Version};

// Simple contentless enum
#[derive(Version)]
pub enum MyEnum {
    Variant0,
    Variant1,
}

#[derive(Serialize, Deserialize, Clone, NotVersioned)]
pub struct MyStruct {
    val: u32,
}

#[derive(Version)]
pub enum MyEnum2<T> {
    Variant1(MyStruct),
    Variant2 { val1: u64, val2: u32 },
    Variant3(T),
}

fn main() {
    assert_impl_all!(MyEnum: Version);

    assert_impl_all!(MyEnum2<u64>: Version);
}
