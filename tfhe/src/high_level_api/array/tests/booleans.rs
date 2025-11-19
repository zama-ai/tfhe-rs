#[cfg(feature = "gpu")]
use crate::high_level_api::integers::unsigned::tests::gpu::{
    setup_classical_gpu, setup_multibit_gpu,
};

#[test]
fn test_cpu_only_bitand() {
    let ck = super::setup_default_cpu();
    super::bitand_test_case::<
        crate::FheBoolId,
        crate::high_level_api::array::cpu::CpuFheBoolArrayBackend,
        bool,
    >(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitand() {
    for i in [0, 1] {
        let ck = if i == 0 {
            setup_classical_gpu()
        } else if i == 1 {
            setup_multibit_gpu()
        } else {
            panic!("Invalid value for i: {i}")
        };
        super::bitand_test_case::<
            crate::FheBoolId,
            crate::high_level_api::array::gpu::GpuFheBoolArrayBackend,
            bool,
        >(&ck);
    }
}

#[test]
fn test_cpu_dyn_bitand() {
    let ck = super::setup_default_cpu();
    super::bitand_test_case::<
        crate::FheBoolId,
        crate::high_level_api::array::dynamic::DynFheBoolArrayBackend,
        bool,
    >(&ck);
}

#[test]
fn test_cpu_only_bitor() {
    let ck = super::setup_default_cpu();
    super::bitor_test_case::<crate::CpuFheBoolArray, bool>(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitor() {
    for i in [0, 1] {
        let ck = if i == 0 {
            setup_classical_gpu()
        } else if i == 1 {
            setup_multibit_gpu()
        } else {
            panic!("Invalid value for i: {i}")
        };
        super::bitor_test_case::<crate::high_level_api::array::gpu::GpuFheBoolArray, bool>(&ck);
    }
}

#[test]
fn test_cpu_dyn_bitor() {
    let ck = super::setup_default_cpu();
    super::bitor_test_case::<crate::FheBoolArray, bool>(&ck);
}

#[test]
fn test_cpu_only_bitxor() {
    let ck = super::setup_default_cpu();
    super::bitxor_test_case::<crate::CpuFheBoolArray, bool>(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitxor() {
    for i in [0, 1] {
        let ck = if i == 0 {
            setup_classical_gpu()
        } else if i == 1 {
            setup_multibit_gpu()
        } else {
            panic!("Invalid value for i: {i}")
        };
        super::bitxor_test_case::<crate::high_level_api::array::gpu::GpuFheBoolArray, bool>(&ck);
    }
}

#[test]
fn test_cpu_dyn_bitxor() {
    let ck = super::setup_default_cpu();
    super::bitxor_test_case::<crate::FheBoolArray, bool>(&ck);
}

#[test]
fn test_cpu_only_bitand_scalar_slice() {
    let ck = super::setup_default_cpu();
    super::bitand_scalar_slice_test_case::<crate::CpuFheBoolArray, bool>(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitand_scalar_slice() {
    for i in [0, 1] {
        let ck = if i == 0 {
            setup_classical_gpu()
        } else if i == 1 {
            setup_multibit_gpu()
        } else {
            panic!("Invalid value for i: {i}")
        };
        super::bitand_scalar_slice_test_case::<
            crate::high_level_api::array::gpu::GpuFheBoolArray,
            bool,
        >(&ck);
    }
}

#[test]
fn test_cpu_dyn_bitand_scalar_slice() {
    let ck = super::setup_default_cpu();
    super::bitand_scalar_slice_test_case::<crate::FheBoolArray, bool>(&ck);
}
