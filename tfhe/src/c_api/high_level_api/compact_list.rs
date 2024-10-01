use crate::c_api::high_level_api::booleans::FheBool;
use crate::c_api::high_level_api::i128::I128;
use crate::c_api::high_level_api::i256::I256;
use crate::c_api::high_level_api::integers::{
    FheInt10, FheInt12, FheInt128, FheInt14, FheInt16, FheInt160, FheInt2, FheInt256, FheInt32,
    FheInt4, FheInt6, FheInt64, FheInt8, FheUint10, FheUint12, FheUint128, FheUint14, FheUint16,
    FheUint160, FheUint2, FheUint256, FheUint32, FheUint4, FheUint6, FheUint64, FheUint8,
};
use crate::c_api::high_level_api::keys::CompactPublicKey;
use crate::c_api::high_level_api::u128::U128;
use crate::c_api::high_level_api::u256::U256;
use crate::c_api::high_level_api::utils::{
    impl_destroy_on_type, impl_serialize_deserialize_on_type, CApiIntegerType,
};
#[cfg(feature = "zk-pok")]
use crate::c_api::high_level_api::zk::{CompactPkeCrs, ZkComputeLoad};
use crate::c_api::utils::{catch_panic, get_mut_checked, get_ref_checked};
use crate::prelude::CiphertextList;
use std::ffi::c_int;

pub struct CompactCiphertextListBuilder(crate::high_level_api::CompactCiphertextListBuilder);
impl_destroy_on_type!(CompactCiphertextListBuilder);

pub struct CompactCiphertextList(crate::high_level_api::CompactCiphertextList);
impl_destroy_on_type!(CompactCiphertextList);
impl_serialize_deserialize_on_type!(CompactCiphertextList);

#[cfg(feature = "zk-pok")]
pub struct ProvenCompactCiphertextList(crate::high_level_api::ProvenCompactCiphertextList);
#[cfg(feature = "zk-pok")]
impl_destroy_on_type!(ProvenCompactCiphertextList);
#[cfg(feature = "zk-pok")]
impl_serialize_deserialize_on_type!(ProvenCompactCiphertextList);

#[no_mangle]
pub unsafe extern "C" fn compact_ciphertext_list_builder_new(
    compact_public_key: *const CompactPublicKey,
    builder: *mut *mut CompactCiphertextListBuilder,
) -> c_int {
    catch_panic(|| {
        let pk = get_ref_checked(compact_public_key).unwrap();

        let inner = crate::high_level_api::CompactCiphertextListBuilder::new(&pk.0);

        *builder = Box::into_raw(Box::new(CompactCiphertextListBuilder(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn compact_ciphertext_list_builder_build(
    builder: *const CompactCiphertextListBuilder,
    list: *mut *mut CompactCiphertextList,
) -> c_int {
    catch_panic(|| {
        let builder = get_ref_checked(builder).unwrap();

        let inner = builder.0.build();

        *list = Box::into_raw(Box::new(CompactCiphertextList(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn compact_ciphertext_list_builder_build_packed(
    builder: *const CompactCiphertextListBuilder,
    list: *mut *mut CompactCiphertextList,
) -> c_int {
    catch_panic(|| {
        let builder = get_ref_checked(builder).unwrap();

        let inner = builder.0.build_packed();

        *list = Box::into_raw(Box::new(CompactCiphertextList(inner)));
    })
}

#[cfg(feature = "zk-pok")]
#[no_mangle]
pub unsafe extern "C" fn compact_ciphertext_list_builder_build_with_proof_packed(
    builder: *const CompactCiphertextListBuilder,
    crs: *const CompactPkeCrs,
    metadata: *const u8,
    metadata_len: usize,
    compute_load: ZkComputeLoad,
    list: *mut *mut ProvenCompactCiphertextList,
) -> c_int {
    catch_panic(|| {
        let builder = get_ref_checked(builder).unwrap();
        let crs = get_ref_checked(crs).unwrap();

        let metadata = if metadata.is_null() {
            &[]
        } else {
            let _metadata_check_ptr = get_ref_checked(metadata).unwrap();
            core::slice::from_raw_parts(metadata, metadata_len)
        };

        let inner = builder
            .0
            .build_with_proof_packed(&crs.0, metadata, compute_load.into())
            .unwrap();

        *list = Box::into_raw(Box::new(ProvenCompactCiphertextList(inner)));
    })
}

/// Pushes a boolean into the list
#[no_mangle]
pub unsafe extern "C" fn compact_ciphertext_list_builder_push_bool(
    builder: *mut CompactCiphertextListBuilder,
    value: bool,
) -> c_int {
    catch_panic(|| {
        let builder = get_mut_checked(builder).unwrap();
        builder.0.push(value);
    })
}

macro_rules! define_compact_ciphertext_list_builder_push_method {
    (
        unsigned: $($num_bits:literal: $rust_ty:ty),* $(,)?
    ) => {
        ::paste::paste!{
            $(
                #[doc = concat!("Pushes an unsigned integer of ", stringify!($num_bits), " bits to the list")]
                #[no_mangle]
                pub unsafe extern "C" fn [<compact_ciphertext_list_builder_push_u $num_bits>](
                    builder: *mut CompactCiphertextListBuilder,
                    value: $rust_ty,
                ) -> c_int {
                    catch_panic(|| {
                        let builder = get_mut_checked(builder).unwrap();
                        builder.0.push_with_num_bits(value.to_rust(), $num_bits).unwrap();
                    })
                }
            )*
        }
    };
    (
        signed: $($num_bits:literal: $rust_ty:ty),* $(,)?
    ) => {
        ::paste::paste!{
            $(
                #[doc = concat!("Pushes a signed integer of ", stringify!($num_bits), " bits to the list")]
                #[no_mangle]
                pub unsafe extern "C" fn [<compact_ciphertext_list_builder_push_i $num_bits>](
                    builder: *mut CompactCiphertextListBuilder,
                    value: $rust_ty,
                ) -> c_int {
                    catch_panic(|| {
                        let builder = get_mut_checked(builder).unwrap();
                        builder.0.push_with_num_bits(value.to_rust(), $num_bits).unwrap();
                    })
                }
            )*
        }
    };
}

define_compact_ciphertext_list_builder_push_method!(
    unsigned: 2: u8, 4: u8, 6: u8, 8: u8, 10: u16, 12: u16, 14: u16, 16: u16, 32: u32, 64: u64, 128: U128, 160: U256, 256: U256
);
define_compact_ciphertext_list_builder_push_method!(
    signed: 2: i8, 4: i8, 6: i8, 8: i8, 10: i16, 12: i16, 14: i16, 16: i16, 32: i32, 64: i64, 128: I128, 160: I256, 256: I256
);

#[no_mangle]
pub unsafe extern "C" fn compact_ciphertext_list_expand(
    compact_list: *const CompactCiphertextList,
    expander: *mut *mut CompactCiphertextListExpander,
) -> c_int {
    catch_panic(|| {
        let list = get_ref_checked(compact_list).unwrap();

        let inner = list.0.expand().unwrap();

        *expander = Box::into_raw(Box::new(CompactCiphertextListExpander(inner)));
    })
}

#[cfg(feature = "zk-pok")]
#[no_mangle]
pub unsafe extern "C" fn proven_compact_ciphertext_list_verify_and_expand(
    compact_list: *const ProvenCompactCiphertextList,
    crs: *const CompactPkeCrs,
    public_key: *const CompactPublicKey,
    metadata: *const u8,
    metadata_len: usize,
    expander: *mut *mut CompactCiphertextListExpander,
) -> c_int {
    catch_panic(|| {
        let list = get_ref_checked(compact_list).unwrap();
        let crs = get_ref_checked(crs).unwrap();
        let public_key = get_ref_checked(public_key).unwrap();

        let metadata = if metadata.is_null() {
            &[]
        } else {
            let _metadata_check_ptr = get_ref_checked(metadata).unwrap();
            core::slice::from_raw_parts(metadata, metadata_len)
        };

        let inner = list
            .0
            .verify_and_expand(&crs.0, &public_key.0, metadata)
            .unwrap();

        *expander = Box::into_raw(Box::new(CompactCiphertextListExpander(inner)));
    })
}

#[cfg(feature = "zk-pok")]
#[no_mangle]
pub unsafe extern "C" fn proven_compact_ciphertext_list_expand_without_verification(
    compact_list: *const ProvenCompactCiphertextList,
    expander: *mut *mut CompactCiphertextListExpander,
) -> c_int {
    catch_panic(|| {
        let list = get_ref_checked(compact_list).unwrap();

        let inner = list.0.expand_without_verification().unwrap();

        *expander = Box::into_raw(Box::new(CompactCiphertextListExpander(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn compact_ciphertext_list_expander_len(
    expander: *mut CompactCiphertextListExpander,
    out: *mut usize,
) -> c_int {
    catch_panic(|| {
        let expander = get_ref_checked(expander).unwrap();
        *out = expander.0.len();
    })
}

#[no_mangle]
pub unsafe extern "C" fn compact_ciphertext_list_expander_get_kind_of(
    expander: *mut CompactCiphertextListExpander,
    index: usize,
    out: *mut super::FheTypes,
) -> c_int {
    let mut result = None;
    catch_panic(|| {
        let expander = get_ref_checked(expander).unwrap();
        result = expander.0.get_kind_of(index);
    });
    result.map_or(1, |r| {
        *out = r.into();
        0
    })
}

macro_rules! define_compact_ciphertext_list_expander_get {
    (
        unsigned: $($num_bits:literal),*
        $(,)?
    ) => {
        ::paste::paste!(
            $(
                #[no_mangle]
                pub unsafe extern "C" fn [<compact_ciphertext_list_expander_get_fhe_uint $num_bits>](
                    expander: *mut CompactCiphertextListExpander,
                    index: usize,
                    out: *mut *mut [<FheUint $num_bits>],
                ) -> c_int {
                    catch_panic(|| {
                        let expander = get_mut_checked(expander).unwrap();

                        let inner = expander.0.get(index).unwrap().unwrap();

                        *out = Box::into_raw(Box::new([<FheUint $num_bits>](inner)));
                    })
                }
            )*
        );
    };
    (
        signed: $($num_bits:literal),*
        $(,)?
    ) => {
        ::paste::paste!(
            $(
                #[no_mangle]
                pub unsafe extern "C" fn [<compact_ciphertext_list_expander_get_fhe_int $num_bits>](
                    expander: *mut CompactCiphertextListExpander,
                    index: usize,
                    out: *mut *mut [<FheInt $num_bits>],
                ) -> c_int {
                    catch_panic(|| {
                        let expander = get_mut_checked(expander).unwrap();

                        let inner = expander.0.get(index).unwrap().unwrap();

                        *out = Box::into_raw(Box::new([<FheInt $num_bits>](inner)));
                    })
                }
            )*
        );
    }
}

pub struct CompactCiphertextListExpander(crate::high_level_api::CompactCiphertextListExpander);
impl_destroy_on_type!(CompactCiphertextListExpander);

define_compact_ciphertext_list_expander_get!(unsigned: 2, 4, 6, 8, 10, 12, 14, 16, 32, 64, 128, 160, 256);
define_compact_ciphertext_list_expander_get!(signed: 2, 4, 6, 8, 10, 12, 14, 16, 32, 64, 128, 160, 256);

#[no_mangle]
pub unsafe extern "C" fn compact_ciphertext_list_expander_get_fhe_bool(
    expander: *mut CompactCiphertextListExpander,
    index: usize,
    out: *mut *mut FheBool,
) -> c_int {
    catch_panic(|| {
        let expander = get_mut_checked(expander).unwrap();

        let inner = expander.0.get(index).unwrap().unwrap();

        *out = Box::into_raw(Box::new(FheBool(inner)));
    })
}
