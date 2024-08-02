//! Test the impl of Versionize for various types

use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::marker::PhantomData;
use std::num::Wrapping;
use std::sync::Arc;

use aligned_vec::{ABox, AVec};
use num_complex::Complex;
use tfhe_versionable::{Unversionize, Versionize};

use backward_compat::MyStructVersions;

#[derive(PartialEq, Clone, Debug, Versionize)]
#[versionize(MyStructVersions)]
pub struct MyStruct {
    wrap: Wrapping<bool>,
    base_box: Box<u8>,
    sliced_box: Box<[u16; 50]>,
    base_vec: Vec<u32>,
    s: String,
    opt: Option<u64>,
    phantom: PhantomData<u128>,
    arc: Arc<i8>,
    complex: Complex<i16>,
    aligned_box: ABox<i32>,
    aligned_vec: AVec<i64>,
    never: (),
    tuple: (f32, f64),
    set: HashSet<i128>,
    map: HashMap<char, bool>,
}

mod backward_compat {
    use tfhe_versionable::VersionsDispatch;

    use super::MyStruct;

    #[derive(VersionsDispatch)]
    #[allow(unused)]
    pub enum MyStructVersions {
        V0(MyStruct),
    }
}

#[test]
fn test_types() {
    let stru = MyStruct {
        wrap: Wrapping(false),
        base_box: Box::new(42),
        sliced_box: vec![11; 50].into_boxed_slice().try_into().unwrap(),
        base_vec: vec![1234, 5678],
        s: String::from("test"),
        opt: Some(0xdeadbeef),
        phantom: PhantomData,
        arc: Arc::new(-1),
        complex: Complex::new(-37, -45),
        aligned_box: ABox::new(0, -98765),
        aligned_vec: AVec::from_slice(0, &[1, 2, 3, 4]),
        never: (),
        tuple: (3.14, 2.71),
        set: HashSet::from_iter([1, 2, 3].into_iter()),
        map: HashMap::from_iter([('t', true), ('e', false), ('s', true)].into_iter()),
    };

    let mut ser = Vec::new();
    ciborium::ser::into_writer(&stru.versionize(), &mut ser).unwrap();

    let unser =
        MyStruct::unversionize(ciborium::de::from_reader(&mut Cursor::new(&ser)).unwrap()).unwrap();

    assert_eq!(stru, unser);
}
