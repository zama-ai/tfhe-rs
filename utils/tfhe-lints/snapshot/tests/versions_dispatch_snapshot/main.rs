use std::convert::Infallible;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

// --- Named struct versions ---

#[derive(Version)]
struct MyTypeV0 {
    _val: u32,
}

#[derive(Version)]
struct MyType {
    _val: u64,
}

impl Upgrade<MyType> for MyTypeV0 {
    type Error = Infallible;
    fn upgrade(self) -> Result<MyType, Self::Error> {
        Ok(MyType {
            _val: self._val as u64,
        })
    }
}

// The lint is `Allow` level and only collects data — no warnings expected.
#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyTypeVersions {
    V0(MyTypeV0),
    V1(MyType),
}

// --- Tuple struct versions ---
// Tuple structs have synthetic field names (_0, _1, ...) in the compiler.
// This test ensures compute_type_hash handles them correctly and produces
// different hashes when field types change.

#[derive(Version)]
struct TupleTypeV0(u32, u8);

#[derive(Version)]
struct TupleType(u64, u16);

impl Upgrade<TupleType> for TupleTypeV0 {
    type Error = Infallible;
    fn upgrade(self) -> Result<TupleType, Self::Error> {
        Ok(TupleType(self.0 as u64, self.1 as u16))
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum TupleTypeVersions {
    V0(TupleTypeV0),
    V1(TupleType),
}

fn main() {
    let _x = MyTypeVersions::V0(MyTypeV0 { _val: 42 });
    let _y = TupleTypeVersions::V0(TupleTypeV0(42, 1));
}
