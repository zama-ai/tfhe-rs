//! Checks compatibility between the "convert" feature and bounds on the From/Into trait

use tfhe_versionable::{Unversionize, Versionize, VersionsDispatch};

#[derive(Clone, Versionize)]
#[versionize(try_convert = "SerializableMyStruct")]
struct MyStruct<T> {
    generics: T,
}

#[derive(Versionize)]
#[versionize(SerializableMyStructVersions)]
struct SerializableMyStruct {
    concrete: u64,
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum SerializableMyStructVersions {
    V0(SerializableMyStruct),
}

impl<T: Into<u64>> From<MyStruct<T>> for SerializableMyStruct {
    fn from(value: MyStruct<T>) -> Self {
        Self {
            concrete: value.generics.into(),
        }
    }
}

impl<T: TryFrom<u64>> TryFrom<SerializableMyStruct> for MyStruct<T> {
    fn try_from(value: SerializableMyStruct) -> Result<Self, Self::Error> {
        Ok(Self {
            generics: value.concrete.try_into()?,
        })
    }

    type Error = T::Error;
}

#[test]
fn test() {
    let stru = MyStruct { generics: 90u32 };

    let serialized = bincode::serialize(&stru.versionize()).unwrap();

    let stru_decoded: MyStruct<u32> =
        MyStruct::unversionize(bincode::deserialize(&serialized).unwrap()).unwrap();

    assert_eq!(stru.generics, stru_decoded.generics)
}
