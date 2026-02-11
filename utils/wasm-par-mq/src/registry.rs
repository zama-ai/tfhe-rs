/// Global registry of functions that can be called as worker tasks.
///
/// Since workers communicate with message passing, all the data needs to be serializable.
/// This means that the function to be run in a task cannot simply be given as an argument. To
/// circumvent this, we register a list of functions that can be called in this global
/// registry, along with their names. This registration happens in the main wasm thread and in
/// the workers, and only depends on compile time information, such that they will all end up
/// with the exact same registry.
/// The main thread will thus only have to send the name of the function to call, and the
/// workers will be able to call them through their local registry.
///
/// # Example
/// ```ignore
/// use wasm_par_mq::{ParallelIterator, ParallelSlice, par_fn, register_fn};
/// fn double(x: i32) -> i32 { x * 2 }
/// register_fn!(double, i32, i32);
///
/// #[wasm_bindgen]
/// pub async fn double_all(data: Vec<i32>) -> Vec<i32> {
///     data.par_iter().map(par_fn!(double)).collect_vec().await
/// }
/// ```
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::Hash;
use std::marker::PhantomData;

/// A unique id for a function, used as a key in the registry
///
/// Even if this type is Serialize, it should not be shared between different compiled binaries
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct FunctionId(Cow<'static, str>);

impl FunctionId {
    pub(crate) const fn from_name(name: &'static str) -> Self {
        Self(Cow::Borrowed(name))
    }
}

/// Type-erased function that operates on a serialized chunk and returns serialized results.
/// The function processes each item in the chunk and returns a Vec of results.
type ErasedChunkFn = Box<dyn Fn(&[u8]) -> Result<Vec<u8>, String>>;

/// A function entry that will be inserted in the registry.
// Needs to be const constructible because the registry is populated with `inventory`
pub struct NewFnEntry {
    // In theory, there are a few solutions to create a new ID:
    // - the `stringify!` macro, but it is not unique
    // - TypeId, but it is opaque (worse for debug) and not serializable
    // - type_name, which is unique and user friendly.
    // However type_name is not const as of rust 1.93, so instead of the name we store a function
    // pointer that can be called later at runtime.
    name_fn: fn() -> &'static str,
    handler: fn(&[u8]) -> Result<Vec<u8>, String>,
}

impl NewFnEntry {
    /// Create a new function entry to be inserted in the registry.
    ///
    /// SHOULD NOT be called directly, use the [`register_fn!`] macro
    // Made pub because it will be called in the macro that lives in user code.
    pub const fn new(
        handler: fn(&[u8]) -> Result<Vec<u8>, String>,
        name_fn: fn() -> &'static str,
    ) -> Self {
        Self { name_fn, handler }
    }
}

/// An entry in the Registry. Can be used to send a task function to call to the workers
// A wrapper for the FunctionId, with type information for compile time checks
pub struct FnEntry<F> {
    fn_id: FunctionId,
    _phantom: PhantomData<F>,
}

impl<F: RegisteredFn> FnEntry<F> {
    /// Returns the associated entry for an already registered function.
    ///
    /// SHOULD NOT be called directly, use the [`par_fn!`] macro
    pub fn new() -> Self {
        Self {
            fn_id: FunctionId::from_name(F::name()),
            _phantom: PhantomData,
        }
    }

    pub(crate) fn id(&self) -> &FunctionId {
        &self.fn_id
    }
}

impl<F: RegisteredFn> Default for FnEntry<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F> Clone for FnEntry<F> {
    fn clone(&self) -> Self {
        Self {
            fn_id: self.fn_id.clone(),
            _phantom: PhantomData,
        }
    }
}

/// Marker trait for a function that has been added to the registry.
///
/// This SHOULD NOT be implemented manually, use the [`register_fn!`] macro
// Trait needs to be pub and cannot be sealed because it will be called by the macro from user code
pub trait RegisteredFn {
    type Input;
    type Output;

    fn name() -> &'static str {
        std::any::type_name::<Self>()
    }
}

/// Deserialize as a Vec of items
///
/// SHOULD NOT be called directly, use the [`register_fn!`] macro
// Made pub because it will be called in the macro that lives in user code.
pub fn deserialize_input_chunk<I: DeserializeOwned>(input_chunk: &[u8]) -> Result<Vec<I>, String> {
    postcard::from_bytes(input_chunk).map_err(|e| format!("deserialize chunk error: {e}"))
}

/// Serialize the results
///
/// SHOULD NOT be called directly, use the [`register_fn!`] macro
// Made pub because it will be called in the macro that lives in user code.
pub fn serialize_output_chunk<O: Serialize>(output_chunk: Vec<O>) -> Result<Vec<u8>, String> {
    postcard::to_allocvec(&output_chunk).map_err(|e| format!("serialize results error: {e}"))
}

// Collect all the NewFnEntry objects registered by user code
inventory::collect!(NewFnEntry);

thread_local! {
    /// Global registry for chunk-processing functions (used by workers)
    static REGISTRY: RefCell<HashMap<FunctionId, ErasedChunkFn>> = RefCell::new(HashMap::new());
}

/// Initializes the registry with user defined functions, registered with the `register_fn` macro.
///
/// This should be called once at program startup.
pub(crate) fn init_registry() {
    REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();

        // The inventory doc advises calling `__wasm_call_ctors` before iterating. However, when
        // using wasm-bindgen, ctors are handled automatically, so no manual call is needed. Calling
        // it twice could be dangerous if other dependencies add non-idempotent ctors.
        for entry in inventory::iter::<NewFnEntry> {
            registry.insert(
                FunctionId::from_name((entry.name_fn)()),
                Box::new(entry.handler),
            );
        }
    });
}

/// Execute a registered chunk function by name with serialized input data.
/// The input should be a serialized Vec of items, and the output is a serialized Vec of results.
pub(crate) fn execute(fn_id: FunctionId, data: &[u8]) -> Result<Vec<u8>, String> {
    REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let f = registry
            .get(&fn_id)
            .ok_or_else(|| format!("function {} not found in registry", fn_id.0))?;
        f(data)
    })
}

/// Macro to register a function that processes individual items.
/// The function will be applied to each element in a chunk.
///
/// # Example
/// ```ignore
/// fn double(x: i32) -> i32 { x * 2 }
/// register_fn!(double, i32, i32);
/// ```
#[macro_export]
macro_rules! register_fn {
    ($fn:ident, $input:ty, $output:ty) => {
        $crate::__private::paste! {
            fn [<__handler_ $fn>](data: &[u8]) -> Result<Vec<u8>, String> {
                let inputs: Vec<$input> = $crate::__private::deserialize_input_chunk(data)?;
                let outputs: Vec<$output> = inputs.into_iter().map($fn).collect();
                $crate::__private::serialize_output_chunk(outputs)
            }

            // Create a type with the same name as the function. Since types and values live in
            // different namespaces, it will not clash.
            //
            // This type is used as a marker type that will be used to add a compile time checks
            // that a function called with `par_fn!` has previously been registered.
            // The error message is not really good but at least it will refuse to compile.
            #[doc(hidden)]
            #[allow(non_camel_case_types)]
            pub struct $fn {}
            impl $crate::__private::RegisteredFn for $fn {
                type Input = $input;
                type Output = $output;
            }

            $crate::__private::submit_fn_entry! {
                $crate::__private::NewFnEntry::new([<__handler_ $fn>],
                    <$fn as $crate::__private::RegisteredFn>::name)
            }
        }
    };
}

/// This macro is used to wrap a function that can be called inside a parallel map.
///
/// # Warning
/// The function must have been registered with `register_fn!` before
///
/// # Example
/// ```ignore
/// fn double(x: i32) -> i32 { x * 2 }
/// register_fn!(double, i32, i32);
///
/// #[wasm_bindgen]
/// pub async fn double_all(data: Vec<i32>) -> Vec<i32> {
///     data.par_iter().map(par_fn!(double)).collect_vec().await
/// }
/// ```
#[macro_export]
macro_rules! par_fn {
    ($fn: ident) => {
        $crate::__private::FnEntry::<$fn>::new()
    };
}

/// This macro is used to wrap a sync function that can be called with execute_async,
/// and will call `collect_vec_sync`.
///
/// # Warning
/// The function must have been registered with `register_fn!` before
///
/// # Example
/// ```ignore
/// fn double(x: i32) -> i32 { x * 2 }
/// register_fn!(double, i32, i32);
///
/// fn double_all(data: Vec<i32>) -> Vec<i32> {
///     data.par_iter().map(par_fn!(double)).collect_vec_sync()
/// }
/// register_fn!(double_all, Vec<i32>, Vec<i32>);
///
/// #[wasm_bindgen]
/// pub async fn double_all_sync(data: Vec<i32>) -> Result<Vec<i32>, JsValue> {
///     execute_async(sync_fn!(double_all_impl), &data)
///         .await
///         .map_err(|e| JsValue::from_str(&e))
/// }
/// ```
#[macro_export]
macro_rules! sync_fn {
    ($fn: ident) => {
        $crate::__private::FnEntry::<$fn>::new()
    };
}
