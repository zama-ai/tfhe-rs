//! Show how to call a conversion method (from/into) before versioning/unversioning

use tfhe_versionable::{Unversionize, Versionize, VersionsDispatch};

#[derive(Clone, Versionize)]
// To mimic serde parameters, this can also be expressed as
// "#[versionize(from = SerializableMyStruct, into = SerializableMyStruct)]"
#[versionize(convert = "SerializableMyStruct<T>")]
struct MyStruct<T> {
    val: u64,
    generics: T,
}

#[derive(Versionize)]
#[versionize(SerializableMyStructVersions)]
struct SerializableMyStruct<T> {
    high: u32,
    low: u32,
    generics: T,
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum SerializableMyStructVersions<T> {
    V0(SerializableMyStruct<T>),
}

impl<T> From<MyStruct<T>> for SerializableMyStruct<T> {
    fn from(value: MyStruct<T>) -> Self {
        Self {
            high: (value.val >> 32) as u32,
            low: (value.val & 0xffffffff) as u32,
            generics: value.generics,
        }
    }
}

impl<T> From<SerializableMyStruct<T>> for MyStruct<T> {
    fn from(value: SerializableMyStruct<T>) -> Self {
        Self {
            val: ((value.high as u64) << 32) | (value.low as u64),
            generics: value.generics,
        }
    }
}

fn main() {
    let stru = MyStruct {
        val: 37,
        generics: 90,
    };

    let serialized = bincode::serialize(&stru.versionize()).unwrap();

    let stru_decoded: MyStruct<i32> =
        MyStruct::unversionize(bincode::deserialize(&serialized).unwrap()).unwrap();

    assert_eq!(stru.val, stru_decoded.val)
}

#[test]
fn test() {
    main()
}
