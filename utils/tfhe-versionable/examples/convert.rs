//! Show how to call a conversion method (from/into) before versioning/unversioning

use tfhe_versionable::{Unversionize, Versionize, VersionsDispatch};

#[derive(Clone, Versionize)]
#[versionize(SerializableMyStructVersions, from = SerializableMyStruct, into = SerializableMyStruct)]
struct MyStruct {
    val: u64,
}

#[derive(Versionize)]
#[versionize(SerializableMyStructVersions)]
struct SerializableMyStruct {
    high: u32,
    low: u32,
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum SerializableMyStructVersions {
    V0(SerializableMyStruct),
}

impl From<MyStruct> for SerializableMyStruct {
    fn from(value: MyStruct) -> Self {
        println!("{}", value.val);
        Self {
            high: (value.val >> 32) as u32,
            low: (value.val & 0xffffffff) as u32,
        }
    }
}

impl From<SerializableMyStruct> for MyStruct {
    fn from(value: SerializableMyStruct) -> Self {
        Self {
            val: ((value.high as u64) << 32) | (value.low as u64),
        }
    }
}

fn main() {
    let stru = MyStruct { val: 37 };

    let serialized = bincode::serialize(&stru.versionize()).unwrap();

    let stru_decoded = MyStruct::unversionize(bincode::deserialize(&serialized).unwrap()).unwrap();

    assert_eq!(stru.val, stru_decoded.val)
}
