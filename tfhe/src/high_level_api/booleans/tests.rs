// Without this, clippy will complain about equal expressions to `ffalse & ffalse`
// However since we overloaded these operators, we want to test them to see
// if they are correct
#![allow(clippy::eq_op)]
#![allow(clippy::bool_assert_comparison)]

use crate::prelude::*;
use crate::{
    generate_keys, set_server_key, ClientKey, CompactFheBool, CompactFheBoolList, CompactPublicKey,
    CompressedFheBool, CompressedPublicKey, ConfigBuilder, Device, FheBool,
};

#[inline(always)]
#[track_caller]
fn assert_degree_is_ok(fhe_bool: &FheBool) {
    let degree = fhe_bool.ciphertext.on_cpu().0.degree.get();
    assert!(
        degree <= 1,
        "Invalid degree for FheBool, got {degree} it must be <= 1"
    );
}

fn xor_truth_table(ttrue: &FheBool, ffalse: &FheBool, key: &ClientKey) {
    assert_degree_is_ok(ttrue);
    assert_degree_is_ok(ffalse);

    let r = ffalse ^ ffalse;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ffalse ^ ttrue;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = ttrue ^ ffalse;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = ttrue ^ ttrue;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);
}

fn scalar_xor_truth_table(ttrue: &FheBool, ffalse: &FheBool, key: &ClientKey) {
    assert_degree_is_ok(ttrue);
    assert_degree_is_ok(ffalse);

    // Scalar on the right
    let r = ffalse ^ false;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ffalse ^ true;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = ttrue ^ false;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = ttrue ^ true;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    // Scalar on the left
    let r = false ^ ffalse;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = false ^ ttrue;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = true ^ ffalse;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = true ^ ttrue;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);
}

fn and_truth_table(ttrue: &FheBool, ffalse: &FheBool, key: &ClientKey) {
    assert_degree_is_ok(ttrue);
    assert_degree_is_ok(ffalse);

    let r = ffalse & ffalse;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ffalse & ttrue;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ttrue & ffalse;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ttrue & ttrue;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);
}

fn scalar_and_truth_table(ttrue: &FheBool, ffalse: &FheBool, key: &ClientKey) {
    assert_degree_is_ok(ttrue);
    assert_degree_is_ok(ffalse);

    // Scalar on the right
    let r = ffalse & false;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ffalse & true;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ttrue & false;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ttrue & true;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    // Scalar on the left
    let r = false & ffalse;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = false & ttrue;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = true & ffalse;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = true & ttrue;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);
}

fn or_truth_table(ttrue: &FheBool, ffalse: &FheBool, key: &ClientKey) {
    assert_degree_is_ok(ttrue);
    assert_degree_is_ok(ffalse);

    let r = ffalse | ffalse;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ffalse | ttrue;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = ttrue | ffalse;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = ttrue | ttrue;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);
}

fn scalar_or_truth_table(ttrue: &FheBool, ffalse: &FheBool, key: &ClientKey) {
    assert_degree_is_ok(ttrue);
    assert_degree_is_ok(ffalse);

    // Scalar on the right
    let r = ffalse | false;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ffalse | true;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = ttrue | false;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = ttrue | true;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    // Scalar on the left
    let r = false | ffalse;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = false | ttrue;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = true | ffalse;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = true | ttrue;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);
}

fn not_truth_table(ttrue: &FheBool, ffalse: &FheBool, key: &ClientKey) {
    assert_degree_is_ok(ttrue);
    assert_degree_is_ok(ffalse);

    let r = !ffalse;
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = !ttrue;
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);
}

fn eq_truth_table(ttrue: &FheBool, ffalse: &FheBool, key: &ClientKey) {
    assert_degree_is_ok(ttrue);
    assert_degree_is_ok(ffalse);

    let r = ffalse.eq(ttrue);
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ttrue.eq(ffalse);
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ttrue.eq(ttrue);
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = ffalse.eq(ffalse);
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);
}

fn scalar_eq_truth_table(ttrue: &FheBool, ffalse: &FheBool, key: &ClientKey) {
    assert_degree_is_ok(ttrue);
    assert_degree_is_ok(ffalse);

    let r = ffalse.eq(true);
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ttrue.eq(false);
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ttrue.eq(true);
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = ffalse.eq(false);
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);
}

fn ne_truth_table(ttrue: &FheBool, ffalse: &FheBool, key: &ClientKey) {
    assert_degree_is_ok(ttrue);
    assert_degree_is_ok(ffalse);

    let r = ffalse.ne(ttrue);
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = ttrue.ne(ffalse);
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = ttrue.ne(ttrue);
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ffalse.ne(ffalse);
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);
}

fn scalar_ne_truth_table(ttrue: &FheBool, ffalse: &FheBool, key: &ClientKey) {
    assert_degree_is_ok(ttrue);
    assert_degree_is_ok(ffalse);

    let r = ffalse.ne(true);
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = ttrue.ne(false);
    assert_eq!(r.decrypt(key), true);
    assert_degree_is_ok(&r);

    let r = ttrue.ne(true);
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);

    let r = ffalse.ne(false);
    assert_eq!(r.decrypt(key), false);
    assert_degree_is_ok(&r);
}

fn compressed_bool_test_case(setup_fn: impl FnOnce() -> (ClientKey, Device)) {
    let (cks, sks_device) = setup_fn();

    let cttrue = CompressedFheBool::encrypt(true, &cks);
    let cffalse = CompressedFheBool::encrypt(false, &cks);

    let a = FheBool::from(cttrue);
    let b = FheBool::from(cffalse);

    assert_degree_is_ok(&a);
    assert_degree_is_ok(&b);

    assert_eq!(a.current_device(), sks_device);
    assert_eq!(b.current_device(), sks_device);

    assert_eq!(a.decrypt(&cks), true);
    assert_eq!(b.decrypt(&cks), false);
}

fn compact_bool_test_case(setup_fn: impl FnOnce() -> (ClientKey, Device)) {
    let (cks, sks_device) = setup_fn();
    let cpk = CompactPublicKey::new(&cks);

    let cttrue = CompactFheBool::encrypt(true, &cpk);
    let cffalse = CompactFheBool::encrypt(false, &cpk);

    let a = cttrue.expand();
    let b = cffalse.expand();

    assert_degree_is_ok(&a);
    assert_degree_is_ok(&b);

    assert_eq!(a.current_device(), sks_device);
    assert_eq!(b.current_device(), sks_device);

    assert_eq!(a.decrypt(&cks), true);
    assert_eq!(b.decrypt(&cks), false);
}

fn compact_bool_list_test_case(setup_fn: impl FnOnce() -> (ClientKey, Device)) {
    let (cks, sks_device) = setup_fn();
    let cpk = CompactPublicKey::new(&cks);

    let clears = vec![false, true, true, false];
    let compacts = CompactFheBoolList::encrypt(&clears, &cpk);

    let ciphertexts = compacts.expand();

    for (fhe_bool, clear) in ciphertexts.into_iter().zip(clears.into_iter()) {
        assert_degree_is_ok(&fhe_bool);
        assert_eq!(fhe_bool.current_device(), sks_device);
        assert_eq!(fhe_bool.decrypt(&cks), clear);
    }
}

mod cpu {
    use super::*;
    use crate::Device;

    fn setup_default() -> ClientKey {
        let config = ConfigBuilder::default().build();

        let (my_keys, server_keys) = generate_keys(config);

        set_server_key(server_keys);
        my_keys
    }

    #[test]
    fn test_xor_truth_table_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        assert_eq!(ttrue.ciphertext.on_cpu().0.degree.get(), 1);
        assert_eq!(ffalse.ciphertext.on_cpu().0.degree.get(), 1);

        xor_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_xor_truth_table_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        assert_eq!(ttrue.ciphertext.on_cpu().0.degree.get(), 1);
        assert_eq!(ffalse.ciphertext.on_cpu().0.degree.get(), 1);

        scalar_xor_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_xor_truth_table_trivial_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        xor_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_xor_truth_table_trivial_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        scalar_xor_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_and_truth_table_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        and_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_and_truth_table_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        scalar_and_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_and_truth_table_trivial_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        and_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_and_truth_table_trivial_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        scalar_and_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_or_truth_table_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        or_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_or_truth_table_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        scalar_or_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_or_truth_table_trivial_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        or_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_or_truth_table_trivial_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        scalar_or_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_not_truth_table_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        not_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_not_truth_table_trivial_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        not_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_eq_truth_table_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        eq_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_eq_truth_table_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        scalar_eq_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_eq_truth_table_trivial_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        eq_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_eq_truth_table_trivial_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        scalar_eq_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_ne_truth_table_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        ne_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_ne_truth_table_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        scalar_ne_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_ne_truth_table_trivial_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        ne_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_ne_truth_table_trivial_default() {
        let keys = setup_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::Cpu);
        assert_eq!(ffalse.current_device(), Device::Cpu);

        scalar_ne_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_compressed_bool() {
        compressed_bool_test_case(|| (setup_default(), Device::Cpu));
    }

    #[test]
    fn test_compact_bool() {
        compact_bool_test_case(|| (setup_default(), Device::Cpu));
    }

    #[test]
    fn test_compact_bool_list() {
        compact_bool_list_test_case(|| (setup_default(), Device::Cpu));
    }

    #[test]
    fn test_trivial_bool() {
        let keys = setup_default();

        let a = FheBool::encrypt_trivial(true);
        let b = FheBool::encrypt_trivial(false);

        assert_degree_is_ok(&a);
        assert_degree_is_ok(&b);

        assert_eq!(a.decrypt(&keys), true);
        assert_eq!(b.decrypt(&keys), false);
    }

    #[test]
    fn test_compressed_public_key_encrypt() {
        let config = ConfigBuilder::default().build();
        let (client_key, _) = generate_keys(config);

        let public_key = CompressedPublicKey::new(&client_key);

        let a = FheBool::try_encrypt(true, &public_key).unwrap();
        assert_degree_is_ok(&a);

        let clear: bool = a.decrypt(&client_key);
        assert_eq!(clear, true);
    }

    #[test]
    fn test_decompressed_public_key_encrypt() {
        let config = ConfigBuilder::default().build();
        let (client_key, _) = generate_keys(config);

        let compressed_public_key = CompressedPublicKey::new(&client_key);
        let public_key = compressed_public_key.decompress();

        let a = FheBool::try_encrypt(true, &public_key).unwrap();
        assert_degree_is_ok(&a);

        let clear: bool = a.decrypt(&client_key);
        assert_eq!(clear, true);
    }
}

#[cfg(feature = "gpu")]
mod gpu {
    use super::*;

    fn setup_gpu_default() -> ClientKey {
        let config = ConfigBuilder::default().build();
        let cks = crate::ClientKey::generate(config);
        let csks = crate::CompressedServerKey::new(&cks);

        let server_keys = csks.decompress_to_gpu();

        set_server_key(server_keys);
        cks
    }

    #[test]
    fn test_xor_truth_table_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        xor_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_xor_truth_table_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        scalar_xor_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_xor_truth_table_trivial_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        xor_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_xor_truth_table_trivial_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        scalar_xor_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_and_truth_table_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        and_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_and_truth_table_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        scalar_and_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_and_truth_table_trivial_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        and_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_and_truth_table_trivial_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        scalar_and_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_or_truth_table_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        or_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_or_truth_table_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        scalar_or_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_or_truth_table_trivial_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        or_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_or_truth_table_trivial_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        scalar_or_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_not_truth_table_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        not_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_not_truth_table_trivial_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        not_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_eq_truth_table_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        eq_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_eq_truth_table_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        scalar_eq_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_eq_truth_table_trivial_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        eq_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_eq_truth_table_trivial_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        scalar_eq_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_ne_truth_table_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        ne_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_ne_truth_table_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt(true, &keys);
        let ffalse = FheBool::encrypt(false, &keys);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        scalar_ne_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_ne_truth_table_trivial_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        ne_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_scalar_ne_truth_table_trivial_default() {
        let keys = setup_gpu_default();

        let ttrue = FheBool::encrypt_trivial(true);
        let ffalse = FheBool::encrypt_trivial(false);

        assert_eq!(ttrue.current_device(), Device::CudaGpu);
        assert_eq!(ffalse.current_device(), Device::CudaGpu);

        scalar_ne_truth_table(&ttrue, &ffalse, &keys);
    }

    #[test]
    fn test_compressed_bool() {
        compressed_bool_test_case(|| (setup_gpu_default(), Device::CudaGpu));
    }

    #[test]
    fn test_compact_bool() {
        compact_bool_test_case(|| (setup_gpu_default(), Device::CudaGpu));
    }

    #[test]
    fn test_compact_bool_list() {
        compact_bool_list_test_case(|| (setup_gpu_default(), Device::CudaGpu));
    }
}
