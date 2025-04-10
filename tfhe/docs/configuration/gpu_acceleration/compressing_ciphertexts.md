# Compressing ciphertexts

This document explains how to compress ciphertexts using the GPU - even after homomorphic computations - just like on the [CPU](../../fhe-computation/data-handling/compress.md#compression-ciphertexts-after-some-homomorphic-computation).

Compressing ciphertexts after computation using GPU is very similar to how it's done on the CPU. The following example shows how to compress and decompress a list containing 4 messages:

* One 32-bits integer
* One 64-bit integer
* One Boolean
* One 2-bit integer

```rust
use tfhe::prelude::*;
use tfhe::shortint::parameters::{
    COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS, PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS,
};
use tfhe::{
    set_server_key, CompressedCiphertextList, CompressedCiphertextListBuilder, FheBool,
    FheInt64, FheUint16, FheUint2, FheUint32,
};

fn main() {
    let config =
        tfhe::ConfigBuilder::with_custom_parameters(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS)
            .enable_compression(COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS)
            .build();

    let ck = tfhe::ClientKey::generate(config);
    let compressed_server_key = tfhe::CompressedServerKey::new(&ck);
    let gpu_key = compressed_server_key.decompress_to_gpu();

    set_server_key(gpu_key);

    let ct1 = FheUint32::encrypt(17_u32, &ck);

    let ct2 = FheInt64::encrypt(-1i64, &ck);

    let ct3 = FheBool::encrypt(false, &ck);

    let ct4 = FheUint2::encrypt(3u8, &ck);

    let compressed_list = CompressedCiphertextListBuilder::new()
        .push(ct1)
        .push(ct2)
        .push(ct3)
        .push(ct4)
        .build()
        .unwrap();

    let serialized = bincode::serialize(&compressed_list).unwrap();

    println!("Serialized size: {} bytes", serialized.len());

    let compressed_list: CompressedCiphertextList = bincode::deserialize(&serialized).unwrap();

    let a: FheUint32 = compressed_list.get(0).unwrap().unwrap();
    let b: FheInt64 = compressed_list.get(1).unwrap().unwrap();
    let c: FheBool = compressed_list.get(2).unwrap().unwrap();
    let d: FheUint2 = compressed_list.get(3).unwrap().unwrap();

    let a: u32 = a.decrypt(&ck);
    assert_eq!(a, 17);
    let b: i64 = b.decrypt(&ck);
    assert_eq!(b, -1);
    let c = c.decrypt(&ck);
    assert!(!c);
    let d: u8 = d.decrypt(&ck);
    assert_eq!(d, 3);

}
```
