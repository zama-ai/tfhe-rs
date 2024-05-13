//! An example of recursive versioning

use tfhe_versionable::{Upgrade, Version, Versionize, VersionsDispatch};

#[derive(Versionize)]
#[versionize(MyStructInnerVersions)]
struct MyStructInner<T: Default> {
    attr: T,
    builtin: u32,
}

#[derive(Version)]
struct MyStructInnerV0 {
    attr: u32,
}

impl<T: Default> Upgrade<MyStructInner<T>> for MyStructInnerV0 {
    fn upgrade(self) -> Result<MyStructInner<T>, String> {
        Ok(MyStructInner {
            attr: T::default(),
            builtin: 0,
        })
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyStructInnerVersions<T: Default> {
    V0(MyStructInnerV0),
    V1(MyStructInner<T>),
}

#[derive(Versionize)]
#[versionize(MyStructVersions)]
struct MyStruct<T: Default> {
    inner: MyStructInner<T>,
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyStructVersions<T: Default> {
    V0(MyStruct<T>),
}

fn main() {}
