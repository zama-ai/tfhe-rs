use std::convert::Infallible;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

// --- Named struct versions ---

#[derive(Version)]
struct MyTypeV0 {
    _val: u32,
    _other_val: u8,
}

#[derive(Version)]
struct MyType {
    _val: u64,
    _other_val: u16,
}

impl Upgrade<MyType> for MyTypeV0 {
    type Error = Infallible;
    fn upgrade(self) -> Result<MyType, Self::Error> {
        Ok(MyType {
            _val: self._val as u64,
            _other_val: self._other_val as u16,
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

// --- Renamed struct (same fields as MyType, different name) ---
// This tests that renaming a struct does not change its hash,
// since the hash should depend only on field names and types.

#[derive(Version)]
struct RenamedV0 {
    _val: u32,
    _other_val: u8,
}

#[derive(Version)]
struct Renamed {
    _val: u64,
    _other_val: u16,
}

impl Upgrade<Renamed> for RenamedV0 {
    type Error = Infallible;
    fn upgrade(self) -> Result<Renamed, Self::Error> {
        Ok(Renamed {
            _val: self._val as u64,
            _other_val: self._other_val as u16,
        })
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum RenamedVersions {
    V0(RenamedV0),
    V1(Renamed),
}

// --- Renamed field (same types, different field name) ---
// This tests that renaming a field changes the hash.

#[derive(Version)]
struct RenamedFieldV0 {
    _value: u32, // was _val in MyTypeV0
    _other_val: u8,
}

#[derive(Version)]
struct RenamedField {
    _value: u64,
    _other_val: u16,
}

impl Upgrade<RenamedField> for RenamedFieldV0 {
    type Error = Infallible;
    fn upgrade(self) -> Result<RenamedField, Self::Error> {
        Ok(RenamedField {
            _value: self._value as u64,
            _other_val: self._other_val as u16,
        })
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum RenamedFieldVersions {
    V0(RenamedFieldV0),
    V1(RenamedField),
}

// --- Renamed enum variant ---
// This tests that renaming a variant in an enum changes the hash.
// The enum itself has a variant with a different name but same inner type.

#[derive(Version)]
enum MyEnumV0 {
    Alpha(u32),
    Beta(u64),
}

#[derive(Version)]
enum MyEnum {
    Alpha(u32),
    Beta(u64),
}

impl Upgrade<MyEnum> for MyEnumV0 {
    type Error = Infallible;
    fn upgrade(self) -> Result<MyEnum, Self::Error> {
        match self {
            MyEnumV0::Alpha(v) => Ok(MyEnum::Alpha(v)),
            MyEnumV0::Beta(v) => Ok(MyEnum::Beta(v)),
        }
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyEnumVersions {
    V0(MyEnumV0),
    V1(MyEnum),
}

// Same enum but with a renamed variant
#[derive(Version)]
enum RenamedVariantEnumV0 {
    Gamma(u32), // was Alpha
    Beta(u64),
}

#[derive(Version)]
enum RenamedVariantEnum {
    Gamma(u32),
    Beta(u64),
}

impl Upgrade<RenamedVariantEnum> for RenamedVariantEnumV0 {
    type Error = Infallible;
    fn upgrade(self) -> Result<RenamedVariantEnum, Self::Error> {
        match self {
            RenamedVariantEnumV0::Gamma(v) => Ok(RenamedVariantEnum::Gamma(v)),
            RenamedVariantEnumV0::Beta(v) => Ok(RenamedVariantEnum::Beta(v)),
        }
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum RenamedVariantEnumVersions {
    V0(RenamedVariantEnumV0),
    V1(RenamedVariantEnum),
}

// --- Same struct in a different module ---
// This tests that the module path does not affect the hash.
mod other_module {
    use std::convert::Infallible;
    use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

    #[derive(Version)]
    pub struct OtherTypeV0 {
        _val: u32,
        _other_val: u8,
    }

    #[derive(Version)]
    pub struct OtherType {
        _val: u64,
        _other_val: u16,
    }

    impl Upgrade<OtherType> for OtherTypeV0 {
        type Error = Infallible;
        fn upgrade(self) -> Result<OtherType, Self::Error> {
            Ok(OtherType {
                _val: self._val as u64,
                _other_val: self._other_val as u16,
            })
        }
    }

    #[derive(VersionsDispatch)]
    #[allow(unused)]
    pub enum OtherTypeVersions {
        V0(OtherTypeV0),
        V1(OtherType),
    }

    pub fn new_v0() -> OtherTypeVersions {
        OtherTypeVersions::V0(OtherTypeV0 {
            _val: 42,
            _other_val: 1,
        })
    }
}

fn main() {
    let _x = MyTypeVersions::V0(MyTypeV0 {
        _val: 42,
        _other_val: 1,
    });
    let _y = TupleTypeVersions::V0(TupleTypeV0(42, 1));
    let _z = RenamedVersions::V0(RenamedV0 {
        _val: 42,
        _other_val: 1,
    });
    let _w = other_module::new_v0();
    let _rf = RenamedFieldVersions::V0(RenamedFieldV0 {
        _value: 42,
        _other_val: 1,
    });
    let _e = MyEnumVersions::V0(MyEnumV0::Alpha(42));
    let _re = RenamedVariantEnumVersions::V0(RenamedVariantEnumV0::Gamma(42));
}
