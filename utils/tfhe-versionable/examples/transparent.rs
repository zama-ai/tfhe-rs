//! In this example, we use the `transparent` attribute so that the versioning of the outer struct
//! will simply defer to the inner type. This is useful for wrapper types that shouldn't be
//! represented in serialized data. This only works for "newtype" struct or structs with only one
//! field.

use std::convert::Infallible;

use tfhe_versionable::{Unversionize, Upgrade, Version, Versionize, VersionsDispatch};

// The Wrapper that should be skipped. Also work with a single field regular struct:
//
// struct MyStructWrapper<T> { inner: MyStruct<T> };
#[derive(Versionize)]
#[versionize(transparent)] // Also works with `#[repr(transparent)]`
struct MyStructWrapper<T>(MyStruct<T>);

// The inner struct that is versioned.
#[derive(Versionize)]
#[versionize(MyStructVersions)]
struct MyStruct<T> {
    attr: T,
    builtin: u32,
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

    // If you ever change the layout of this struct to make it "not transparent", you should create
    // a MyStructWrapperVersions enum where the first versions are the same than the ones of
    // MyStructVersions. See `transparent_then_not.rs` for a full example.
    #[derive(Versionize)]
    #[versionize(transparent)]
    pub(super) struct MyStructWrapper(pub(super) MyStruct);

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
    let ms = v0::MyStructWrapper(v0::MyStruct { builtin: value });

    let serialized = bincode::serialize(&ms.versionize()).unwrap();

    let unserialized =
        MyStructWrapper::<u64>::unversionize(bincode::deserialize(&serialized).unwrap()).unwrap();

    assert_eq!(unserialized.0.builtin, value);
}

#[test]
fn test() {
    main()
}
