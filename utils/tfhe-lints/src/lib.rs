#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_ast;
extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

mod serialize_without_versionize;
mod versionize_dispatch_enum;

mod utils;

dylint_linting::dylint_library!();

#[allow(clippy::no_mangle_with_rust_abi)]
#[no_mangle]
pub fn register_lints(_sess: &rustc_session::Session, lint_store: &mut rustc_lint::LintStore) {
    lint_store.register_lints(&[
        serialize_without_versionize::SERIALIZE_WITHOUT_VERSIONIZE,
        versionize_dispatch_enum::VERSIONIZE_DISPATCH_ENUM,
    ]);
    lint_store.register_late_pass(|_| {
        Box::new(serialize_without_versionize::SerializeWithoutVersionize::default())
    });
    lint_store.register_late_pass(|_| {
        Box::new(versionize_dispatch_enum::VersionizeDispatchEnum::default())
    });
}
