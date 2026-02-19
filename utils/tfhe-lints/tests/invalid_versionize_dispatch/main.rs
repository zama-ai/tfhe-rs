use std::convert::Infallible;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

#[derive(Version)]
struct GoodV0 {
    _val: u32,
}

#[derive(Version)]
struct Good {
    _val: u64,
}

impl Upgrade<Good> for GoodV0 {
    type Error = Infallible;
    fn upgrade(self) -> Result<Good, Self::Error> {
        Ok(Good {
            _val: self._val as u64,
        })
    }
}

#[derive(Version)]
struct BadVariantV0 {
    _val: u32,
}

#[derive(Version)]
struct BadVariant {
    _val: u64,
}

impl Upgrade<BadVariant> for BadVariantV0 {
    type Error = Infallible;
    fn upgrade(self) -> Result<BadVariant, Self::Error> {
        Ok(BadVariant {
            _val: self._val as u64,
        })
    }
}

#[derive(Version)]
struct WrongOrder<F> {
    _val: F,
}

#[derive(Version)]
struct WrongOrderV0 {
    _val: u64,
}

impl Upgrade<WrongOrder<u32>> for WrongOrderV0 {
    type Error = Infallible;
    fn upgrade(self) -> Result<WrongOrder<u32>, Self::Error> {
        Ok(WrongOrder {
            _val: self._val as u32,
        })
    }
}

impl Upgrade<WrongOrderV0> for WrongOrder<u32> {
    type Error = Infallible;
    fn upgrade(self) -> Result<WrongOrderV0, Self::Error> {
        Ok(WrongOrderV0 {
            _val: self._val as u64,
        })
    }
}

// Good: variants are V0, V1 in order — no warning expected
#[derive(VersionsDispatch)]
#[allow(unused)]
enum GoodVersions {
    V0(GoodV0),
    V1(Good),
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum BadVariantVersions {
    First(BadVariantV0),
    Second(BadVariant),
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum BadInnerVariantNameVersions {
    V0(BadVariantV0),
    V1(BadVariant),
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum GoodVer {
    V0(GoodV0),
    V1(Good),
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum WrongOrderVersions<F> {
    V1(WrongOrderV0),
    V0(WrongOrder<F>),
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum WrongInnerVariantOrderVersions {
    V0(WrongOrder<u32>),
    V1(WrongOrderV0),
}

#[derive(VersionsDispatch)]
#[allow(unused)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(invalid_versionize_dispatch))]
enum WrongInnerVariantOrder {
    V0(WrongOrder<u32>),
    V1(WrongOrderV0),
}

#[allow(unused)]
enum ClassicEnum {
    Foo(Good),
    Bar(Good),
}

fn main() {
    let _a = GoodVersions::V0(GoodV0 { _val: 42 });
    let _b = BadVariantVersions::First(BadVariantV0 { _val: 42 });
    let _c = WrongOrderVersions::<u32>::V1(WrongOrderV0 { _val: 42 });
    let _d = BadInnerVariantNameVersions::V0(BadVariantV0 { _val: 42 });
    let _e = GoodVer::V0(GoodV0 { _val: 42 });
    let _f = WrongInnerVariantOrderVersions::V0(WrongOrder { _val: 42 });
    let _g = WrongInnerVariantOrder::V0(WrongOrder { _val: 42 });
}
