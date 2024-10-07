use std::convert::Infallible;

use tfhe_versionable::{Unversionize, Upgrade, Version, Versionize, VersionsDispatch};

#[derive(Versionize)]
#[versionize(MyStructVersions)]
struct MyStruct<T: ?Sized> {
    builtin: u32,
    attr: T,
}

#[derive(Version)]
struct MyStructV0 {
    builtin: u32,
}

impl<T: Default> Upgrade<MyStruct<T>> for MyStructV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<MyStruct<T>, Self::Error> {
        Ok(MyStruct {
            attr: T::default(),
            builtin: self.builtin,
        })
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyStructVersions<T> {
    V0(MyStructV0),
    V1(MyStruct<T>),
}

mod v0 {
    use tfhe_versionable::{Versionize, VersionsDispatch};

    #[derive(Versionize)]
    #[versionize(MyStructVersions)]
    pub(super) struct MyStruct {
        pub(super) builtin: u32,
    }

    #[derive(VersionsDispatch)]
    #[allow(unused)]
    pub(super) enum MyStructVersions {
        V0(MyStruct),
    }
}

fn main() {
    let value = 1234;
    let ms = v0::MyStruct { builtin: value };

    let serialized = bincode::serialize(&ms.versionize()).unwrap();

    let unserialized =
        MyStruct::<u64>::unversionize(bincode::deserialize(&serialized).unwrap()).unwrap();

    assert_eq!(unserialized.builtin, value);
}

#[test]
fn test() {
    main()
}
