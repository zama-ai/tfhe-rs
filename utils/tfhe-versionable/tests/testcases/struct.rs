use static_assertions::assert_impl_all;

use tfhe_versionable::{Version, Versionize, VersionsDispatch};

// Empty struct
#[derive(Version)]
pub struct MyEmptyStruct();

#[derive(Version)]
pub struct MyEmptyStruct2 {}

// Simple anonymous struct
#[derive(Version)]
pub struct MyAnonStruct(u32);

#[derive(Version)]
pub struct MyAnonStruct2(u32, u64);

#[derive(Version)]
pub struct MyAnonStruct3<T>(u32, T);

#[derive(Versionize)]
#[versionize(MyStructVersions)]
pub struct MyStruct<T> {
    field0: u64,
    field1: T,
}

#[derive(VersionsDispatch)]
pub enum MyStructVersions<T> {
    V0(MyStruct<T>),
}

#[derive(Version)]
pub struct MyStruct2<T, U> {
    field0: MyStruct<T>,
    field1: U,
}

#[derive(Versionize)]
#[versionize(dispatch = MyStruct3Versions)]
pub struct MyStruct3<T> {
    field0: u64,
    field1: T,
}

#[derive(VersionsDispatch)]
pub enum MyStruct3Versions<T> {
    V0(MyStruct3<T>),
}

fn main() {
    assert_impl_all!(MyEmptyStruct: Version);
    assert_impl_all!(MyEmptyStruct2: Version);

    assert_impl_all!(MyAnonStruct: Version);

    assert_impl_all!(MyAnonStruct2: Version);

    assert_impl_all!(MyAnonStruct3<u64>: Version);

    assert_impl_all!(MyStruct<u32>: Versionize);

    assert_impl_all!(MyStruct2<usize, String>: Version);

    assert_impl_all!(MyStruct3<u32>: Versionize);
}
