use core::slice;

use crate::array::ClearArray;
use crate::prelude::*;
use crate::{generate_keys, set_server_key, ConfigBuilder, CpuFheUint32Array, FheUint32Array};
use rand::prelude::*;
use rand::thread_rng;

#[test]
fn test_cpu_only_bitand() {
    let ck = super::setup_default_cpu();
    super::bitand_test_case::<
        crate::FheUint32Id,
        crate::high_level_api::array::cpu::integers::CpuUintArrayBackend,
        u32,
    >(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitand() {
    let ck = super::setup_default_gpu();
    super::bitand_test_case::<
        crate::FheUint32Id,
        crate::high_level_api::array::gpu::integers::GpuUintArrayBackend,
        u32,
    >(&ck);
}

#[test]
fn test_cpu_dyn_bitand() {
    let ck = super::setup_default_cpu();
    super::bitand_test_case::<
        crate::FheUint32Id,
        crate::high_level_api::array::dynamic::DynUintBackend,
        u32,
    >(&ck);
}

#[test]
fn test_cpu_only_bitor() {
    let ck = super::setup_default_cpu();
    super::bitor_test_case::<crate::CpuFheUint32Array, u32>(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitor() {
    let ck = super::setup_default_gpu();
    super::bitor_test_case::<crate::array::GpuFheUint32Array, u32>(&ck);
}

#[test]
fn test_cpu_dyn_bitor() {
    let ck = super::setup_default_cpu();
    super::bitor_test_case::<crate::FheUint32Array, u32>(&ck);
}

#[test]
fn test_cpu_only_bitxor() {
    let ck = super::setup_default_cpu();
    super::bitxor_test_case::<crate::CpuFheUint32Array, u32>(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitxor() {
    let ck = super::setup_default_gpu();
    super::bitxor_test_case::<crate::array::GpuFheUint32Array, u32>(&ck);
}

#[test]
fn test_cpu_dyn_bitxor() {
    let ck = super::setup_default_cpu();
    super::bitxor_test_case::<crate::FheUint32Array, u32>(&ck);
}
#[test]
fn test_cpu_only_bitand_scalar_slice() {
    let ck = super::setup_default_cpu();
    super::bitand_scalar_slice_test_case::<crate::CpuFheUint32Array, u32>(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitand_scalar_slice() {
    let ck = super::setup_default_gpu();
    super::bitand_scalar_slice_test_case::<crate::array::GpuFheUint32Array, u32>(&ck);
}

#[test]
fn test_cpu_dyn_bitand_scalar_slice() {
    let ck = super::setup_default_cpu();
    super::bitand_scalar_slice_test_case::<crate::FheUint32Array, u32>(&ck);
}

#[test]
fn test_single_dimension() {
    let config = ConfigBuilder::default().build();
    let (cks, sks) = generate_keys(config);

    set_server_key(sks);

    let mut rng = thread_rng();

    let num_elems = 5;

    let clear_xs = (0..num_elems).map(|_| rng.gen::<u32>()).collect::<Vec<_>>();
    let clear_ys = (0..num_elems).map(|_| rng.gen::<u32>()).collect::<Vec<_>>();

    let xs = FheUint32Array::try_encrypt(clear_xs.as_slice(), &cks).unwrap();
    let ys = FheUint32Array::try_encrypt(clear_ys.as_slice(), &cks).unwrap();

    let range = 1..3;
    let xss = xs.slice(slice::from_ref(&range));
    let yss = ys.slice(slice::from_ref(&range));

    let zs = xss + yss;

    let clear_zs: Vec<u32> = zs.decrypt(&cks);
    for (z, (x, y)) in clear_zs.into_iter().zip(
        clear_xs[range.clone()]
            .iter()
            .copied()
            .zip(clear_ys[range].iter().copied()),
    ) {
        assert_eq!(z, x.wrapping_add(y));
    }
}

#[test]
fn test_2_dimension() {
    let config = ConfigBuilder::default().build();
    let (cks, sks) = generate_keys(config);

    set_server_key(sks);

    let num_elems = 4 * 4;
    let clear_xs = (0..num_elems as u32).collect::<Vec<_>>();
    let clear_ys = vec![1u32; num_elems];

    let mut xs = CpuFheUint32Array::try_encrypt((clear_xs.as_slice(), vec![4, 4]), &cks).unwrap();
    let ys = CpuFheUint32Array::try_encrypt((clear_ys.as_slice(), vec![4, 4]), &cks).unwrap();

    assert_eq!(xs.num_dim(), 2);
    assert_eq!(xs.shape(), &[4, 4]);
    assert_eq!(xs.container().len(), num_elems);
    assert_eq!(ys.num_dim(), 2);
    assert_eq!(ys.shape(), &[4, 4]);
    assert_eq!(ys.container().len(), num_elems);

    let _ = &xs + &ys;

    let xss = xs.slice(&[2..4, 2..4]);
    let yss = ys.slice(&[2..4, 2..4]);

    assert_eq!(xss.num_dim(), 2);
    assert_eq!(xss.shape(), &[2, 2]);
    assert_eq!(xss.container().len(), 6);
    assert_eq!(yss.num_dim(), 2);
    assert_eq!(yss.shape(), &[2, 2]);
    assert_eq!(xss.container().len(), 6);

    let r = xss + &yss;
    assert_eq!(r.num_dim(), 2);
    assert_eq!(r.shape(), &[2, 2]);
    assert_eq!(r.container().len(), 4);

    let result: Vec<u32> = r.decrypt(&cks);
    assert_eq!(result, vec![11, 12, 15, 16]);

    let xss = xs.slice_mut(&[2..4, 2..4]);
    assert_eq!(xss.num_dim(), 2);
    assert_eq!(xss.shape(), &[2, 2]);

    let xss = xs.slice(&[2..4, 2..4]);
    let clear_array = ClearArray::new(vec![10u32, 20u32, 30u32, 40u32], vec![2, 2]);
    let r = xss + &clear_array;
    let r: Vec<u32> = r.decrypt(&cks);
    assert_eq!(r, vec![20, 31, 44, 55]);
}
