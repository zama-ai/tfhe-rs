use std::convert::Infallible;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

#[derive(Version)]
struct V0 {
    _val: u32,
}

#[derive(Version)]
struct V1 {
    _val: u64,
}

#[derive(Version)]
struct V2 {
    _val: u64,
}

impl Upgrade<V1> for V0 {
    type Error = Infallible;
    fn upgrade(self) -> Result<V1, Self::Error> {
        Ok(V1 {
            _val: self._val as u64,
        })
    }
}

impl Upgrade<V0> for V2 {
    type Error = Infallible;
    fn upgrade(self) -> Result<V0, Self::Error> {
        Ok(V0 {
            _val: self._val as u32,
        })
    }
}

// Good: variants are V0, V1 in order — no warning expected
#[derive(VersionsDispatch)]
#[allow(unused)]
enum GoodVersions {
    V0(V0),
    V1(V1),
}

// Bad: variants are not named V0, V1 — warning expected
#[derive(VersionsDispatch)]
#[allow(unused)]
enum BadVersions {
    First(V0),
    Second(V1),
}

// Bad: variants are V0, V1 in wrong order — warning expected
#[derive(VersionsDispatch)]
#[allow(unused)]
enum WrongOrderVersions {
    V2(V2),
    V0(V0),
}

fn main() {
    let _x = GoodVersions::V0(V0 { _val: 42 });
    let _y = BadVersions::First(V0 { _val: 42 });
    let _z = WrongOrderVersions::V2(V2 { _val: 42 });
}
