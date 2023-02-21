use std::os::raw::c_int;

pub fn catch_panic<F>(closure: F) -> c_int
where
    F: FnOnce(),
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(closure)) {
        Ok(_) => 0,
        _ => 1,
    }
}

pub fn check_ptr_is_non_null_and_aligned<T>(ptr: *const T) -> Result<(), String> {
    if ptr.is_null() {
        return Err(format!("pointer is null, got: {ptr:p}"));
    }
    let expected_alignment = std::mem::align_of::<T>();
    if ptr as usize % expected_alignment != 0 {
        return Err(format!(
            "pointer is misaligned, expected {expected_alignment} bytes alignement, got pointer: \
            {ptr:p}. You May have mixed some pointers in your function call. If that's not the \
            case check tfhe.h for alignment constants for plain data types allocation.",
        ));
    }
    Ok(())
}

pub fn get_mut_checked<'a, T>(ptr: *mut T) -> Result<&'a mut T, String> {
    match check_ptr_is_non_null_and_aligned(ptr) {
        Ok(()) => unsafe {
            ptr.as_mut()
                .ok_or_else(|| "Error while converting to mut reference".into())
        },
        Err(e) => Err(e),
    }
}

pub fn get_ref_checked<'a, T>(ptr: *const T) -> Result<&'a T, String> {
    match check_ptr_is_non_null_and_aligned(ptr) {
        Ok(()) => unsafe {
            ptr.as_ref()
                .ok_or_else(|| "Error while converting to reference".into())
        },
        Err(e) => Err(e),
    }
}

macro_rules! dispatch_binary_server_key_call {
    ($server_key:ident, $method:tt, &mut $ct_left:ident, &mut $ct_right:ident) => {
        match (&mut $ct_left.0, &mut $ct_right.0) {
            (
                ShortintCiphertextInner::Big(inner_left),
                ShortintCiphertextInner::Big(inner_right),
            ) => ShortintCiphertextInner::Big($server_key.0.$method(inner_left, inner_right)),
            (
                ShortintCiphertextInner::Small(inner_left),
                ShortintCiphertextInner::Small(inner_right),
            ) => ShortintCiphertextInner::Small($server_key.0.$method(inner_left, inner_right)),
            _ => Err(
                "Got mixed Big and Small ciphertexts, this is not supported, \
            did you mistakenly use a Small ciphertext with a Big ciphertext?",
            )
            .unwrap(),
        }
    };
    ($server_key:ident, $method:tt, &mut $ct_left:ident, &$ct_right:ident) => {
        match (&mut $ct_left.0, &$ct_right.0) {
            (
                ShortintCiphertextInner::Big(inner_left),
                ShortintCiphertextInner::Big(inner_right),
            ) => ShortintCiphertextInner::Big($server_key.0.$method(inner_left, inner_right)),
            (
                ShortintCiphertextInner::Small(inner_left),
                ShortintCiphertextInner::Small(inner_right),
            ) => ShortintCiphertextInner::Small($server_key.0.$method(inner_left, inner_right)),
            _ => Err(
                "Got mixed Big and Small ciphertexts, this is not supported, \
            did you mistakenly use a Small ciphertext with a Big ciphertext?",
            )
            .unwrap(),
        }
    };
    ($server_key:ident, $method:tt, &$ct_left:ident, &$ct_right:ident) => {
        match (&$ct_left.0, &$ct_right.0) {
            (
                ShortintCiphertextInner::Big(inner_left),
                ShortintCiphertextInner::Big(inner_right),
            ) => ShortintCiphertextInner::Big($server_key.0.$method(inner_left, inner_right)),
            (
                ShortintCiphertextInner::Small(inner_left),
                ShortintCiphertextInner::Small(inner_right),
            ) => ShortintCiphertextInner::Small($server_key.0.$method(inner_left, inner_right)),
            _ => Err(
                "Got mixed Big and Small ciphertexts, this is not supported, \
            did you mistakenly use a Small ciphertext with a Big ciphertext?",
            )
            .unwrap(),
        }
    };
    ($server_key:ident, $method:tt, &mut $ct_left:ident, $scalar_right:ident) => {
        match &mut $ct_left.0 {
            ShortintCiphertextInner::Big(inner_left) => {
                ShortintCiphertextInner::Big($server_key.0.$method(inner_left, $scalar_right))
            }
            ShortintCiphertextInner::Small(inner_left) => {
                ShortintCiphertextInner::Small($server_key.0.$method(inner_left, $scalar_right))
            }
        }
    };
    ($server_key:ident, $method:tt, &$ct_left:ident, $scalar_right:ident) => {
        match &$ct_left.0 {
            ShortintCiphertextInner::Big(inner_left) => {
                ShortintCiphertextInner::Big($server_key.0.$method(inner_left, $scalar_right))
            }
            ShortintCiphertextInner::Small(inner_left) => {
                ShortintCiphertextInner::Small($server_key.0.$method(inner_left, $scalar_right))
            }
        }
    };
}

pub(in crate::c_api) use dispatch_binary_server_key_call;

macro_rules! dispatch_binary_assign_server_key_call {
    ($server_key:ident, $method:tt, &mut $ct_left_and_result:ident, &mut $ct_right:ident) => {
        match (&mut $ct_left_and_result.0, &mut $ct_right.0) {
            (
                ShortintCiphertextInner::Big(inner_left),
                ShortintCiphertextInner::Big(inner_right),
            ) => $server_key.0.$method(inner_left, inner_right),
            (
                ShortintCiphertextInner::Small(inner_left),
                ShortintCiphertextInner::Small(inner_right),
            ) => $server_key.0.$method(inner_left, inner_right),
            _ => Err(
                "Got mixed Big and Small ciphertexts, this is not supported, \
            did you mistakenly use a Small ciphertext with a Big ciphertext?",
            )
            .unwrap(),
        }
    };
    ($server_key:ident, $method:tt, &mut $ct_left_and_result:ident, &$ct_right:ident) => {
        match (&mut $ct_left_and_result.0, &$ct_right.0) {
            (
                ShortintCiphertextInner::Big(inner_left),
                ShortintCiphertextInner::Big(inner_right),
            ) => $server_key.0.$method(inner_left, inner_right),
            (
                ShortintCiphertextInner::Small(inner_left),
                ShortintCiphertextInner::Small(inner_right),
            ) => $server_key.0.$method(inner_left, inner_right),
            _ => Err(
                "Got mixed Big and Small ciphertexts, this is not supported, \
            did you mistakenly use a Small ciphertext with a Big ciphertext?",
            )
            .unwrap(),
        }
    };
    ($server_key:ident, $method:tt, &mut $ct_left_and_result:ident, $scalar_right:ident) => {
        match (&mut $ct_left_and_result.0) {
            ShortintCiphertextInner::Big(inner_left) => {
                $server_key.0.$method(inner_left, $scalar_right)
            }
            ShortintCiphertextInner::Small(inner_left) => {
                $server_key.0.$method(inner_left, $scalar_right)
            }
        }
    };
}

pub(in crate::c_api) use dispatch_binary_assign_server_key_call;

macro_rules! dispatch_unary_server_key_call {
    ($server_key:ident, $method:tt, &mut $ct_left:ident) => {
        match (&mut $ct_left.0) {
            ShortintCiphertextInner::Big(inner_left) => {
                ShortintCiphertextInner::Big($server_key.0.$method(inner_left))
            }
            ShortintCiphertextInner::Small(inner_left) => {
                ShortintCiphertextInner::Small($server_key.0.$method(inner_left))
            }
        }
    };
    ($server_key:ident, $method:tt, & $ct_left:ident) => {
        match (&$ct_left.0) {
            ShortintCiphertextInner::Big(inner_left) => {
                ShortintCiphertextInner::Big($server_key.0.$method(inner_left))
            }
            ShortintCiphertextInner::Small(inner_left) => {
                ShortintCiphertextInner::Small($server_key.0.$method(inner_left))
            }
        }
    };
}

pub(in crate::c_api) use dispatch_unary_server_key_call;

macro_rules! dispatch_unary_assign_server_key_call {
    ($server_key:ident, $method:tt, &mut $ct_left_and_result:ident) => {
        match (&mut $ct_left_and_result.0) {
            ShortintCiphertextInner::Big(inner_left) => $server_key.0.$method(inner_left),
            ShortintCiphertextInner::Small(inner_left) => $server_key.0.$method(inner_left),
        }
    };
}

pub(in crate::c_api) use dispatch_unary_assign_server_key_call;
