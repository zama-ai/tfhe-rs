use crate::c_api::buffer::*;
use crate::c_api::utils::*;
use std::os::raw::c_int;

use crate::shortint;

#[derive(serde::Serialize, serde::Deserialize)]
pub(in crate::c_api) enum ShortintCiphertextInner {
    Big(shortint::ciphertext::CiphertextBig),
    Small(shortint::ciphertext::CiphertextSmall),
}

impl From<shortint::ciphertext::CiphertextBig> for ShortintCiphertextInner {
    fn from(value: shortint::ciphertext::CiphertextBig) -> Self {
        ShortintCiphertextInner::Big(value)
    }
}

impl From<shortint::ciphertext::CiphertextSmall> for ShortintCiphertextInner {
    fn from(value: shortint::ciphertext::CiphertextSmall) -> Self {
        ShortintCiphertextInner::Small(value)
    }
}

pub struct ShortintCiphertext(pub(in crate::c_api) ShortintCiphertextInner);

#[derive(serde::Serialize, serde::Deserialize)]
pub(in crate::c_api) enum ShortintCompressedCiphertextInner {
    Big(shortint::ciphertext::CompressedCiphertextBig),
    Small(shortint::ciphertext::CompressedCiphertextSmall),
}

impl From<shortint::ciphertext::CompressedCiphertextBig> for ShortintCompressedCiphertextInner {
    fn from(value: shortint::ciphertext::CompressedCiphertextBig) -> Self {
        ShortintCompressedCiphertextInner::Big(value)
    }
}

impl From<shortint::ciphertext::CompressedCiphertextSmall> for ShortintCompressedCiphertextInner {
    fn from(value: shortint::ciphertext::CompressedCiphertextSmall) -> Self {
        ShortintCompressedCiphertextInner::Small(value)
    }
}
pub struct ShortintCompressedCiphertext(pub(in crate::c_api) ShortintCompressedCiphertextInner);

#[repr(C)]
pub enum ShortintCiphertextKind {
    ShortintCiphertextBig,
    ShortintCiphertextSmall,
}

#[no_mangle]
pub unsafe extern "C" fn shortint_ciphertext_set_degree(
    ciphertext: *mut ShortintCiphertext,
    degree: usize,
) -> c_int {
    catch_panic(|| {
        let ciphertext = get_mut_checked(ciphertext).unwrap();

        let inner = &mut ciphertext.0;

        match inner {
            ShortintCiphertextInner::Big(inner_ct) => inner_ct.degree.0 = degree,
            ShortintCiphertextInner::Small(inner_ct) => inner_ct.degree.0 = degree,
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_ciphertext_get_degree(
    ciphertext: *const ShortintCiphertext,
    result: *mut usize,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let ciphertext = get_ref_checked(ciphertext).unwrap();

        let inner = &ciphertext.0;

        *result = match inner {
            ShortintCiphertextInner::Big(inner_ct) => inner_ct.degree.0,
            ShortintCiphertextInner::Small(inner_ct) => inner_ct.degree.0,
        };
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_serialize_ciphertext(
    ciphertext: *const ShortintCiphertext,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let ciphertext = get_ref_checked(ciphertext).unwrap();

        let buffer: Buffer = bincode::serialize(&ciphertext.0).unwrap().into();

        *result = buffer;
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_deserialize_ciphertext(
    buffer_view: BufferView,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let ciphertext = bincode::deserialize(buffer_view.into()).unwrap();

        let heap_allocated_ciphertext = Box::new(ShortintCiphertext(ciphertext));

        *result = Box::into_raw(heap_allocated_ciphertext);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_decompress_ciphertext(
    compressed_ciphertext: *const ShortintCompressedCiphertext,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let compressed_ciphertext = get_ref_checked(compressed_ciphertext).unwrap();

        let ciphertext = match &compressed_ciphertext.0 {
            ShortintCompressedCiphertextInner::Big(inner) => {
                ShortintCiphertextInner::Big(inner.clone().into())
            }
            ShortintCompressedCiphertextInner::Small(inner) => {
                ShortintCiphertextInner::Small(inner.clone().into())
            }
        };

        let heap_allocated_ciphertext = Box::new(ShortintCiphertext(ciphertext));

        *result = Box::into_raw(heap_allocated_ciphertext);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_serialize_compressed_ciphertext(
    ciphertext: *const ShortintCompressedCiphertext,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let ciphertext = get_ref_checked(ciphertext).unwrap();

        let buffer: Buffer = bincode::serialize(&ciphertext.0).unwrap().into();

        *result = buffer;
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_deserialize_compressed_ciphertext(
    buffer_view: BufferView,
    result: *mut *mut ShortintCompressedCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let ciphertext: ShortintCompressedCiphertextInner =
            bincode::deserialize(buffer_view.into()).unwrap();

        let heap_allocated_ciphertext = Box::new(ShortintCompressedCiphertext(ciphertext));

        *result = Box::into_raw(heap_allocated_ciphertext);
    })
}
