/// The C Standard only define integers from u8 to u64.
/// So to support u128 and u256 we had to create our own C friendly
/// data types.
///
/// This trait exists to be able to easily write wrapper function
/// by allowing to generically go from a C API scalar type to a rust one
pub(in crate::c_api::high_level_api) trait CApiIntegerType:
    From<Self::RustEquivalent>
{
    type RustEquivalent: From<Self>;

    fn to_rust(self) -> Self::RustEquivalent {
        Self::RustEquivalent::from(self)
    }
}

macro_rules! impl_c_api_integer_type(
    // For when the C Integer type is _not_ the same as the Rust Integer type
    ($c_type:ty => $rust_type:ty) => {
        impl CApiIntegerType for $c_type {
            type RustEquivalent = $rust_type;
        }
    };
    // For when the C Integer type is the same as Rust Integer type
    ($type:ty) => {
        impl CApiIntegerType for $type {
            type RustEquivalent = $type;
        }
    };
);

impl_c_api_integer_type!(bool);
impl_c_api_integer_type!(u8);
impl_c_api_integer_type!(u16);
impl_c_api_integer_type!(u32);
impl_c_api_integer_type!(u64);
impl_c_api_integer_type!(i8);
impl_c_api_integer_type!(i16);
impl_c_api_integer_type!(i32);
impl_c_api_integer_type!(i64);
impl_c_api_integer_type!(crate::c_api::high_level_api::u128::U128 => u128);
impl_c_api_integer_type!(crate::c_api::high_level_api::i128::I128 => i128);
impl_c_api_integer_type!(crate::c_api::high_level_api::u256::U256 => crate::integer::U256);
impl_c_api_integer_type!(crate::c_api::high_level_api::i256::I256 => crate::integer::I256);

macro_rules! impl_destroy_on_type {
    ($wrapper_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            #[doc = "ptr can be null (no-op in that case)"]
            pub unsafe extern "C" fn [<$wrapper_type:snake _destroy>](
                ptr: *mut $wrapper_type,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    if (!ptr.is_null()) {
                        $crate::c_api::utils::check_ptr_is_non_null_and_aligned(ptr).unwrap();
                        drop(Box::from_raw(ptr));
                    }
                })
            }
        }
    };
}

macro_rules! impl_try_encrypt_with_client_key_on_type {
    ($wrapper_type:ty{$wrapped_type:ty}, $input_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn  [<$wrapper_type:snake _try_encrypt_with_client_key_ $input_type:snake>](
                value: $input_type,
                client_key: *const $crate::c_api::high_level_api::keys::ClientKey,
                result: *mut *mut $wrapper_type,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    let value = <$input_type as $crate::c_api::high_level_api::utils::CApiIntegerType>::to_rust(value);
                    let client_key = $crate::c_api::utils::get_ref_checked(client_key).unwrap();

                    let inner = <$wrapped_type>::try_encrypt(value, &client_key.0).unwrap();

                    *result = Box::into_raw(Box::new($wrapper_type(inner)));
                })
            }
        }
    };
}

macro_rules! impl_try_encrypt_with_public_key_on_type {
    ($wrapper_type:ty{$wrapped_type:ty}, $input_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn  [<$wrapper_type:snake _try_encrypt_with_public_key_ $input_type:snake>](
                value: $input_type,
                public_key: *const $crate::c_api::high_level_api::keys::PublicKey,
                result: *mut *mut $wrapper_type,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    let value = <$input_type as $crate::c_api::high_level_api::utils::CApiIntegerType>::to_rust(value);

                    let public_key = $crate::c_api::utils::get_ref_checked(public_key).unwrap();

                    let inner = <$wrapped_type>::try_encrypt(value, &public_key.0).unwrap();

                    *result = Box::into_raw(Box::new($wrapper_type(inner)));
                })
            }
        }
    };
}

macro_rules! impl_try_encrypt_with_compact_public_key_on_type {
    ($wrapper_type:ty{$wrapped_type:ty}, $input_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn  [<$wrapper_type:snake _try_encrypt_with_compact_public_key_ $input_type:snake>](
                value: $input_type,
                public_key: *const $crate::c_api::high_level_api::keys::CompactPublicKey,
                result: *mut *mut $wrapper_type,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    let value = <$input_type as $crate::c_api::high_level_api::utils::CApiIntegerType>::to_rust(value);

                    let public_key = $crate::c_api::utils::get_ref_checked(public_key).unwrap();

                    let inner = <$wrapped_type>::try_encrypt(value, &public_key.0).unwrap();

                    *result = Box::into_raw(Box::new($wrapper_type(inner)));
                })
            }
        }
    };
}

macro_rules! impl_try_encrypt_list_with_compact_public_key_on_type {
    ($wrapper_type:ty{$wrapped_type:ty}, $input_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn  [<$wrapper_type:snake _try_encrypt_with_compact_public_key_ $input_type:snake>](
                input: *const $input_type,
                input_len: usize,
                public_key: *const $crate::c_api::high_level_api::keys::CompactPublicKey,
                result: *mut *mut $wrapper_type,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    let public_key = $crate::c_api::utils::get_ref_checked(public_key).unwrap();
                    let slc = ::std::slice::from_raw_parts(input, input_len);
                    let inner = <$wrapped_type>::try_encrypt(slc, &public_key.0).unwrap();

                    *result = Box::into_raw(Box::new($wrapper_type(inner)));
                })
            }
        }
    };
}

macro_rules! impl_try_encrypt_trivial_on_type {
    ($wrapper_type:ty{$wrapped_type:ty}, $input_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn  [<$wrapper_type:snake _try_encrypt_trivial_ $input_type:snake>](
                value: $input_type,
                result: *mut *mut $wrapper_type,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    let value = <$input_type as $crate::c_api::high_level_api::utils::CApiIntegerType>::to_rust(value);

                    let inner = <$wrapped_type>::try_encrypt_trivial(value).unwrap();

                    *result = Box::into_raw(Box::new($wrapper_type(inner)));
                })
            }
        }
    };
}
macro_rules! impl_decrypt_on_type {
    ($wrapper_type:ty, $output_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn  [<$wrapper_type:snake _decrypt>](
                encrypted_value: *const $wrapper_type,
                client_key: *const $crate::c_api::high_level_api::keys::ClientKey,
                result: *mut $output_type,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    let client_key = $crate::c_api::utils::get_ref_checked(client_key).unwrap();
                    let encrypted_value = $crate::c_api::utils::get_ref_checked(encrypted_value).unwrap();

                    type RustScalarType_ = <$output_type as $crate::c_api::high_level_api::utils::CApiIntegerType>::RustEquivalent;

                    let rust_clear: RustScalarType_ = encrypted_value.0.decrypt(&client_key.0);

                    *result = <$output_type>::from(rust_clear);
                })
            }
        }
    };
}

macro_rules! impl_clone_on_type {
    ($wrapper_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<$wrapper_type:snake _clone>](
                sself: *const $wrapper_type,
                result: *mut *mut $wrapper_type,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    $crate::c_api::utils::check_ptr_is_non_null_and_aligned(result).unwrap();

                    let wrapper = $crate::c_api::utils::get_ref_checked(sself).unwrap();

                    let heap_allocated_object = Box::new($wrapper_type(wrapper.0.clone()));

                    *result = Box::into_raw(heap_allocated_object);
                })
            }
        }
    };
}

macro_rules! impl_serialize_deserialize_on_type {
    ($wrapper_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<$wrapper_type:snake _serialize>](
                sself: *const $wrapper_type,
                result: *mut $crate::c_api::buffer::Buffer,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    $crate::c_api::utils::check_ptr_is_non_null_and_aligned(result).unwrap();

                    let wrapper = $crate::c_api::utils::get_ref_checked(sself).unwrap();

                    let buffer: $crate::c_api::buffer::Buffer = bincode::serialize(&wrapper.0)
                        .unwrap()
                        .into();

                    *result = buffer;
                })
            }

            #[no_mangle]
            pub unsafe extern "C" fn [<$wrapper_type:snake _deserialize>](
                buffer_view: $crate::c_api::buffer::BufferView,
                result: *mut *mut $wrapper_type,
                ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    $crate::c_api::utils::check_ptr_is_non_null_and_aligned(result).unwrap();

                    // First fill the result with a null ptr so that if we fail and the return code is not
                    // checked, then any access to the result pointer will segfault (mimics malloc on failure)
                    *result = std::ptr::null_mut();

                    let object = bincode::deserialize(buffer_view.into()).unwrap();

                    let heap_allocated_object = Box::new($wrapper_type(object));

                    *result = Box::into_raw(heap_allocated_object);
                })
            }
        }
    };
}

macro_rules! impl_safe_serialize_on_type {
    ($wrapper_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<$wrapper_type:snake _safe_serialize>](
                sself: *const $wrapper_type,
                result: *mut crate::c_api::buffer::Buffer,
                serialized_size_limit: u64,
            ) -> ::std::os::raw::c_int {
                crate::c_api::utils::catch_panic(|| {
                    crate::c_api::utils::check_ptr_is_non_null_and_aligned(result).unwrap();

                    let mut buffer = vec![];

                    let sself = crate::c_api::utils::get_ref_checked(sself).unwrap();

                    crate::high_level_api::safe_serialize(&sself.0, &mut buffer, serialized_size_limit)
                        .unwrap();

                    *result = buffer.into();
                })
            }
        }
    };
}

macro_rules! impl_safe_deserialize_conformant_integer {
    ($wrapper_type:ty, $function_name:path) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<$wrapper_type:snake _safe_deserialize_conformant>](
                buffer_view: crate::c_api::buffer::BufferView,
                serialized_size_limit: u64,
                server_key: *const crate::c_api::high_level_api::keys::ServerKey,
                result: *mut *mut $wrapper_type,
            ) -> ::std::os::raw::c_int {
                crate::c_api::utils::catch_panic(|| {
                    crate::c_api::utils::check_ptr_is_non_null_and_aligned(result).unwrap();

                    let sk = crate::c_api::utils::get_ref_checked(server_key).unwrap();

                    let buffer_view: &[u8] = buffer_view.into();

                    // First fill the result with a null ptr so that if we fail and the return code is not
                    // checked, then any access to the result pointer will segfault (mimics malloc on failure)
                    *result = std::ptr::null_mut();

                    let object: $wrapper_type = $wrapper_type(
                        $function_name(
                            buffer_view,
                            serialized_size_limit,
                            &sk.0,
                        )
                        .unwrap(),
                    );

                    let heap_allocated_object = Box::new(object);

                    *result = Box::into_raw(heap_allocated_object);
                })
            }
        }
    };
}

macro_rules! impl_binary_fn_on_type {
    // More general binary fn case,
    // where the type of the left-hand side can be different
    // than the type of the right-hand side.
    //
    // The result type is the one of the left-hand side.
    //
    // In practice, this is used for shifts on signed type,
    // where lhs is a signed type and rhs is an unsigned type
     (
        lhs_type: $lhs_type:ty,
        rhs_type: $rhs_type:ty,
        binary_fn_names: $($binary_fn_name:ident),*
        $(,)?
    ) => {
         $( // unroll binary_fn_names
           ::paste::paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<$lhs_type:snake _ $binary_fn_name>](
                    lhs: *const $lhs_type,
                    rhs: *const $rhs_type,
                    result: *mut *mut $lhs_type,
                ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let lhs = $crate::c_api::utils::get_ref_checked(lhs).unwrap();
                        let rhs = $crate::c_api::utils::get_ref_checked(rhs).unwrap();

                        let inner = (&lhs.0).$binary_fn_name(&rhs.0);

                        *result = Box::into_raw(Box::new($lhs_type(inner)));
                    })
                }
            }
         )*

    };

    // Usual binary fn case, where lhs, rhs and result are all of the same type
    ($wrapper_type:ty => $($binary_fn_name:ident),* $(,)?) => {
        impl_binary_fn_on_type!(
            lhs_type: $wrapper_type,
            rhs_type: $wrapper_type,
            binary_fn_names: $($binary_fn_name),*
        );
    };
}

// Comparisons returns FheBool so we use a specialized
// macro for them
macro_rules! impl_comparison_fn_on_type {
     (
        lhs_type: $lhs_type:ty,
        rhs_type: $rhs_type:ty,
        comparison_fn_names: $($comparison_fn_name:ident),*
        $(,)?
    ) => {
         $( // unroll comparison_fn_names
           ::paste::paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<$lhs_type:snake _ $comparison_fn_name>](
                    lhs: *const $lhs_type,
                    rhs: *const $rhs_type,
                    result: *mut *mut $crate::c_api::high_level_api::booleans::FheBool,
                ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let lhs = $crate::c_api::utils::get_ref_checked(lhs).unwrap();
                        let rhs = $crate::c_api::utils::get_ref_checked(rhs).unwrap();

                        let inner = (&lhs.0).$comparison_fn_name(&rhs.0);

                        let inner = $crate::c_api::high_level_api::booleans::FheBool(inner);
                        *result = Box::into_raw(Box::new(inner));
                    })
                }
            }
         )*
    };
}

macro_rules! impl_scalar_comparison_fn_on_type {
     (
        lhs_type: $lhs_type:ty,
        clear_type: $scalar_type:ty,
        comparison_fn_names: $($comparison_fn_name:ident),*
        $(,)?
    ) => {
         $( // unroll comparison_fn_names
           ::paste::paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<$lhs_type:snake _scalar_ $comparison_fn_name>](
                    lhs: *const $lhs_type,
                    rhs: $scalar_type,
                    result: *mut *mut $crate::c_api::high_level_api::booleans::FheBool,
                ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let lhs = $crate::c_api::utils::get_ref_checked(lhs).unwrap();
                        let rhs = <$scalar_type as $crate::c_api::high_level_api::utils::CApiIntegerType>::to_rust(rhs);


                        let inner = (&lhs.0).$comparison_fn_name(rhs);

                        let inner = $crate::c_api::high_level_api::booleans::FheBool(inner);
                        *result = Box::into_raw(Box::new(inner));
                    })
                }
            }
         )*
    };
}

macro_rules! impl_unary_fn_on_type {
    ($wrapper_type:ty => $($unary_fn_name:ident),* $(,)?) => {
        $(
           ::paste::paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<$wrapper_type:snake _ $unary_fn_name>](
                    lhs: *const $wrapper_type,
                    result: *mut *mut $wrapper_type,
                ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let lhs = $crate::c_api::utils::get_ref_checked(lhs).unwrap();

                        let inner = (&lhs.0).$unary_fn_name();

                        *result = Box::into_raw(Box::new($wrapper_type(inner)));
                    })
                }
            }
        )*
    };
}

#[cfg(feature = "integer")]
macro_rules! impl_binary_assign_fn_on_type {
    // More general binary fn case,
    // where the type of the left-hand side can be different
    // than the type of the right-hand side.
    //
    // In practice, this is used for shifts on signed type,
    // where lhs is a signed type and rhs is an unsigned type
    (
        lhs_type: $lhs_type:ty,
        rhs_type: $rhs_type:ty,
        binary_fn_names: $($binary_assign_fn_name:ident),*
        $(,)?
    ) => {
        $(
           ::paste::paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<$lhs_type:snake _ $binary_assign_fn_name>](
                    lhs: *mut $lhs_type,
                    rhs: *const $rhs_type,
                ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let lhs = $crate::c_api::utils::get_mut_checked(lhs).unwrap();
                        let rhs = $crate::c_api::utils::get_ref_checked(rhs).unwrap();

                        lhs.0.$binary_assign_fn_name(&rhs.0);
                    })
                }
            }
        )*
    };
    ($wrapper_type:ty => $($binary_assign_fn_name:ident),* $(,)?) => {
         impl_binary_assign_fn_on_type!(
            lhs_type: $wrapper_type,
            rhs_type: $wrapper_type,
            binary_fn_names: $($binary_assign_fn_name),*
        );
    };
}

#[cfg(feature = "integer")]
macro_rules! impl_scalar_binary_fn_on_type {
    ($wrapper_type:ty, $scalar_type:ty => $($binary_fn_name:ident),* $(,)?) => {
        $(
           ::paste::paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<$wrapper_type:snake _scalar_ $binary_fn_name>](
                    lhs: *const $wrapper_type,
                    rhs: $scalar_type,
                    result: *mut *mut $wrapper_type,
                ) -> c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let lhs = $crate::c_api::utils::get_ref_checked(lhs).unwrap();
                        let rhs = <$scalar_type as $crate::c_api::high_level_api::utils::CApiIntegerType>::to_rust(rhs);

                        let inner = (&lhs.0).$binary_fn_name(rhs);

                        *result = Box::into_raw(Box::new($wrapper_type(inner)));
                    })
                }
            }
        )*
    };
}

#[cfg(feature = "integer")]
macro_rules! impl_scalar_binary_assign_fn_on_type {
    ($wrapper_type:ty, $scalar_type:ty => $($binary_assign_fn_name:ident),* $(,)?) => {
        $(
           ::paste::paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<$wrapper_type:snake _scalar_ $binary_assign_fn_name>](
                    lhs: *mut $wrapper_type,
                    rhs: $scalar_type,
                ) -> c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let lhs = $crate::c_api::utils::get_mut_checked(lhs).unwrap();
                        let rhs = <$scalar_type as $crate::c_api::high_level_api::utils::CApiIntegerType
                            >::to_rust(rhs);

                        lhs.0.$binary_assign_fn_name(rhs);
                    })
                }
            }
        )*
    };
}
