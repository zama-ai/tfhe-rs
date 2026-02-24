use std::convert::Infallible;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

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

fn main() {
    let _x = MyTypeVersions::V0(MyTypeV0 { _val: 42 });
}
