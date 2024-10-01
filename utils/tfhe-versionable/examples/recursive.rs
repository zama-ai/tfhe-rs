//! An example of recursive versioning

use std::convert::Infallible;

use tfhe_versionable::{Unversionize, Upgrade, Version, Versionize, VersionsDispatch};

// The inner struct is independently versioned
#[derive(Versionize)]
#[versionize(MyStructInnerVersions)]
struct MyStructInner<T> {
    attr: T,
    builtin: u32,
}

#[derive(Version)]
struct MyStructInnerV0 {
    builtin: u32,
}

impl<T: Default> Upgrade<MyStructInner<T>> for MyStructInnerV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<MyStructInner<T>, Self::Error> {
        Ok(MyStructInner {
            attr: T::default(),
            builtin: self.builtin,
        })
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyStructInnerVersions<T> {
    V0(MyStructInnerV0),
    V1(MyStructInner<T>),
}

// An upgrade of the inner struct does not require an upgrade of the outer struct
#[derive(Versionize)]
#[versionize(MyStructVersions)]
struct MyStruct<T> {
    inner: MyStructInner<T>,
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyStructVersions<T> {
    V0(MyStruct<T>),
}

mod v0 {
    use tfhe_versionable::{Versionize, VersionsDispatch};

    #[derive(Versionize)]
    #[versionize(MyStructInnerVersions)]
    pub(super) struct MyStructInner {
        pub(super) builtin: u32,
    }

    #[derive(VersionsDispatch)]
    #[allow(unused)]
    pub(super) enum MyStructInnerVersions {
        V0(MyStructInner),
    }

    #[derive(Versionize)]
    #[versionize(MyStructVersions)]
    pub(super) struct MyStruct {
        pub(super) inner: MyStructInner,
    }

    #[derive(VersionsDispatch)]
    #[allow(unused)]
    pub(super) enum MyStructVersions {
        V0(MyStruct),
    }
}

fn main() {
    let builtin = 654;
    let inner = v0::MyStructInner { builtin: 654 };
    let ms = v0::MyStruct { inner };

    let serialized = bincode::serialize(&ms.versionize()).unwrap();

    // This can be called in future versions of your application, when more variants have been added
    let unserialized =
        MyStruct::<u64>::unversionize(bincode::deserialize(&serialized).unwrap()).unwrap();

    assert_eq!(unserialized.inner.builtin, builtin);
}

#[test]
fn test() {
    main()
}
