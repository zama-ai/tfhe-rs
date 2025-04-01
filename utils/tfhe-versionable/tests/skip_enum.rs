//! Test the skip attribute in an enum. This attribute in a struct is already tested in
//! `examples/skip.rs`

use std::convert::Infallible;
use std::io::Cursor;

use tfhe_versionable::{Unversionize, Upgrade, Version, Versionize, VersionsDispatch};

#[allow(dead_code)]
struct NotVersionable(u64);

mod v0 {
    use super::NotVersionable;
    use tfhe_versionable::{Versionize, VersionsDispatch};

    #[derive(Versionize)]
    #[versionize(MyEnumVersions)]
    pub(super) enum MyEnum {
        Var0(u32),
        #[versionize(skip)]
        #[allow(dead_code)]
        Var1(NotVersionable),
    }

    #[derive(VersionsDispatch)]
    #[allow(unused)]
    pub(super) enum MyEnumVersions {
        V0(MyEnum),
    }
}

#[derive(Version)]
enum MyEnumV0 {
    Var0(u32),
    #[versionize(skip)]
    #[allow(dead_code)]
    Var1(NotVersionable),
}

#[derive(Versionize)]
#[versionize(MyEnumVersions)]
enum MyEnum {
    Var0(u64),
    #[versionize(skip)]
    #[allow(dead_code)]
    Var1(NotVersionable),
}

impl Upgrade<MyEnum> for MyEnumV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<MyEnum, Self::Error> {
        match self {
            MyEnumV0::Var0(val) => Ok(MyEnum::Var0(val as u64)),
            MyEnumV0::Var1(val) => Ok(MyEnum::Var1(val)),
        }
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyEnumVersions {
    V0(MyEnumV0),
    V1(MyEnum),
}

#[test]
fn test() {
    // Test the "normal" variant
    let val = 64;
    let enu_v0 = v0::MyEnum::Var0(val);

    let mut ser = Vec::new();
    ciborium::ser::into_writer(&enu_v0.versionize(), &mut ser).unwrap();

    let unvers =
        MyEnum::unversionize(ciborium::de::from_reader(&mut Cursor::new(&ser)).unwrap()).unwrap();

    assert!(matches!(unvers, MyEnum::Var0(unvers_val) if unvers_val == val as u64));

    // Test the skipped variant
    let val = 64;
    let enu_v0 = v0::MyEnum::Var1(NotVersionable(val));

    let mut ser = Vec::new();
    // Serialization of the skipped variant must fail
    assert!(ciborium::ser::into_writer(&enu_v0.versionize(), &mut ser).is_err());
}
