#[test]
fn test_cpu_only_bitand() {
    let ck = super::setup_default_cpu();
    super::bitand_test_case::<
        crate::FheInt32Id,
        crate::high_level_api::array::cpu::integers::CpuIntArrayBackend,
        i32,
    >(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitand() {
    let ck = super::setup_default_gpu();
    super::bitand_test_case::<
        crate::FheInt32Id,
        crate::high_level_api::array::gpu::integers::GpuIntArrayBackend,
        i32,
    >(&ck);
}

#[test]
fn test_cpu_dyn_bitand() {
    let ck = super::setup_default_cpu();
    super::bitand_test_case::<
        crate::FheInt32Id,
        crate::high_level_api::array::dynamic::DynIntBackend,
        i32,
    >(&ck);
}

#[test]
fn test_cpu_only_bitor() {
    let ck = super::setup_default_cpu();
    super::bitor_test_case::<crate::CpuFheInt32Array, i32>(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitor() {
    let ck = super::setup_default_gpu();
    super::bitor_test_case::<crate::array::GpuFheInt32Array, i32>(&ck);
}

#[test]
fn test_cpu_dyn_bitor() {
    let ck = super::setup_default_cpu();
    super::bitor_test_case::<crate::FheInt32Array, i32>(&ck);
}

#[test]
fn test_cpu_only_bitxor() {
    let ck = super::setup_default_cpu();
    super::bitxor_test_case::<crate::CpuFheInt32Array, i32>(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitxor() {
    let ck = super::setup_default_gpu();
    super::bitxor_test_case::<crate::array::GpuFheInt32Array, i32>(&ck);
}

#[test]
fn test_cpu_dyn_bitxor() {
    let ck = super::setup_default_cpu();
    super::bitxor_test_case::<crate::FheInt32Array, i32>(&ck);
}

#[test]
fn test_cpu_only_bitand_scalar_slice() {
    let ck = super::setup_default_cpu();
    super::bitand_scalar_slice_test_case::<crate::CpuFheInt32Array, i32>(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitand_scalar_slice() {
    let ck = super::setup_default_gpu();
    super::bitand_scalar_slice_test_case::<crate::array::GpuFheInt32Array, i32>(&ck);
}

#[test]
fn test_cpu_dyn_bitand_scalar_slice() {
    let ck = super::setup_default_cpu();
    super::bitand_scalar_slice_test_case::<crate::FheInt32Array, i32>(&ck);
}
