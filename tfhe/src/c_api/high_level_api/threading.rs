use super::super::utils::{catch_panic, get_mut_checked};
use crate::c_api::high_level_api::keys::ServerKey;
use crate::c_api::utils::get_ref_checked;
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::ffi::{c_int, c_void};

/// Used to limit number of threads
///
/// This struct can be used to limit the number of threads
/// operations (ran inside this context) can use.
///
/// A threading context creates and hold the specified number of threads
pub struct TfheThreadingContext {
    pool: ThreadPool,
}

/// Creates a new threading context
///
/// - num_threads: number of threads inside this context 0 means it will have number of CPU threads
#[no_mangle]
pub unsafe extern "C" fn tfhe_threading_context_create(
    num_threads: usize,
    context: *mut *mut TfheThreadingContext,
) -> c_int {
    catch_panic(|| {
        *context = std::ptr::null_mut();

        let pool = ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .unwrap();

        let ctx = TfheThreadingContext { pool };

        *context = Box::into_raw(Box::new(ctx));
    })
}

/// Destroys the threading context
///
/// `context` may be NULL
#[no_mangle]
pub unsafe extern "C" fn tfhe_threading_context_destroy(context: *mut TfheThreadingContext) {
    let _ = catch_panic(|| {
        if context.is_null() {
            return;
        }

        drop(Box::from_raw(context));
    });
}

/// Sets the server key inside of all of the threads the context has
#[no_mangle]
pub unsafe extern "C" fn tfhe_threading_context_set_server_key(
    context: *mut TfheThreadingContext,
    server_key: *const ServerKey,
) -> c_int {
    catch_panic(|| {
        let sks = get_ref_checked(server_key).map(|sks| &sks.0).unwrap();
        let context = get_mut_checked(context).unwrap();

        context
            .pool
            .broadcast(|_| crate::high_level_api::set_server_key(sks.clone()));
    })
}

/// Runs the given function inside the context
///
///
/// Both the `func` and `data` must be thread-safe
/// That is, `data` and `func` must not be used by other
/// threads, unless they do not have data races or have protections
/// to prevent data races.
#[no_mangle]
pub unsafe extern "C" fn tfhe_threading_context_run(
    context: *mut TfheThreadingContext,
    func: extern "C" fn(*mut c_void) -> c_int,
    data: *mut c_void,
) -> c_int {
    // *mut c_void is not Send by default
    // neither extern fn is
    //
    // However rayon/rust require a `Send` closure
    // here we can't prove it, the responsibility is on the user
    // since the function is unsafe its fine (no soundness issue)

    struct TheUserEnsuresDataIsThreadSafe(*mut c_void);
    unsafe impl Send for TheUserEnsuresDataIsThreadSafe {}

    struct TheUserEnsuresTheFuncIsThreadSafe(extern "C" fn(*mut c_void) -> c_int);
    unsafe impl Send for TheUserEnsuresTheFuncIsThreadSafe {}

    #[allow(clippy::needless_pass_by_ref_mut)]
    impl TheUserEnsuresTheFuncIsThreadSafe {
        fn execute(&mut self, data: &TheUserEnsuresDataIsThreadSafe) -> c_int {
            (self.0)(data.0)
        }
    }

    let mut func = TheUserEnsuresTheFuncIsThreadSafe(func);
    let data = TheUserEnsuresDataIsThreadSafe(data);

    let mut result = 0;

    let panic_result = catch_panic(|| {
        let context = get_mut_checked(context).unwrap();

        result = context.pool.install(move || func.execute(&data));
    });

    if panic_result != 0 {
        panic_result
    } else {
        result
    }
}
