//! Shows a basic usage of this crate

use std::convert::Infallible;

use tfhe_versionable::{Unversionize, Upgrade, Version, Versionize, VersionsDispatch};

// The structure that should be versioned, as defined in your code
#[derive(Versionize)]
// We have to link to the enum type that will holds all the versions of this
// type. This can also be written `#[versionize(dispatch = MyStructVersions)]`.
#[versionize(MyStructVersions)]
struct MyStruct<T> {
    attr: T,
    builtin: u32,
}

// To avoid polluting your code, the old versions can be defined in another module/file, along with
// the dispatch enum
#[derive(Version)] // Used to mark an old version of the type
struct MyStructV0 {
    builtin: u32,
}

// The Upgrade trait tells how to go from the first version to the last. During unversioning, the
// upgrade method will be called on the deserialized value enough times to go to the last variant.
impl<T: Default> Upgrade<MyStruct<T>> for MyStructV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<MyStruct<T>, Self::Error> {
        Ok(MyStruct {
            attr: T::default(),
            builtin: self.builtin,
        })
    }
}

// This is the dispatch enum, that holds one variant for each version of your type.
#[derive(VersionsDispatch)]
// This enum is not directly used but serves as a template to generate a new enum that will be
// serialized. This allows recursive versioning.
#[allow(unused)]
enum MyStructVersions<T> {
    V0(MyStructV0),
    V1(MyStruct<T>),
}

mod v0 {
    // This module simulates an older version of our app where we initiated the versioning process.
    // In real life code this would likely be only present in your git history.
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
    // In the past we saved a value
    let value = 1234;
    let ms = v0::MyStruct { builtin: value };

    let serialized = bincode::serialize(&ms.versionize()).unwrap();

    // This can be called in future versions of your application, when more variants have been added
    let unserialized =
        MyStruct::<u64>::unversionize(bincode::deserialize(&serialized).unwrap()).unwrap();

    assert_eq!(unserialized.builtin, value);
}

#[test]
fn test() {
    main()
}
