//! Test an enum that derives Default using the `#[default]` attribute

use std::io::Cursor;

use tfhe_versionable::{Unversionize, Versionize, VersionsDispatch};
#[derive(Default, Debug, PartialEq, Eq, Versionize)]
#[versionize(MyEnumVersions)]
pub enum MyEnum {
    Var0,
    #[default]
    Var1,
}

#[derive(VersionsDispatch)]
#[allow(unused)]
pub enum MyEnumVersions {
    V0(MyEnum),
}

#[test]
fn test() {
    let enu = MyEnum::default();

    let mut ser = Vec::new();
    ciborium::ser::into_writer(&enu.versionize(), &mut ser).unwrap();

    let unvers =
        MyEnum::unversionize(ciborium::de::from_reader(&mut Cursor::new(&ser)).unwrap()).unwrap();

    assert_eq!(unvers, enu);
}
