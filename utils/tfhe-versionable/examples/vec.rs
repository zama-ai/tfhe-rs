/// The `VersionizeVec` and `UnversionizeVec` traits are also automatically derived
/// So that Vec can be versioned as well
use tfhe_versionable::{Versionize, VersionsDispatch};

#[derive(Versionize)]
#[versionize(MyStructInnerVersions)]
struct MyStructInner<T> {
    val: u64,
    gen: T,
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyStructInnerVersions<T> {
    V0(MyStructInner<T>),
}

#[derive(Versionize)]
#[versionize(MyVecVersions)]
struct MyVec<T> {
    vec: Vec<MyStructInner<T>>,
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyVecVersions<T> {
    V0(MyVec<T>),
}

fn main() {}
