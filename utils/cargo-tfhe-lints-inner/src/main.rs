#![feature(rustc_private)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

mod serialize_without_versionize;
pub mod utils;

// We need to import them like this otherwise it doesn't work.
extern crate rustc_ast;
extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

use rustc_lint::LintStore;
use rustc_tools::with_lints;
use serialize_without_versionize::SerializeWithoutVersionize;

fn main() {
    let tool_args = std::env::args().skip(2).collect::<Vec<_>>();

    let (cargo_args, rustc_args) = if let Some(idx) = tool_args.iter().position(|arg| arg == "--") {
        tool_args.split_at(idx)
    } else {
        (tool_args.as_slice(), &[] as &[String])
    };

    rustc_tools::cargo_integration(&cargo_args, |args| {
        let mut args = args.to_vec();
        args.extend(rustc_args.iter().skip(1).cloned());
        args.extend(
            [
                "--emit=metadata",
                // These params allows to use the syntax
                // `#[cfg_attr(tfhe_lints, allow(tfhe_lints::serialize_without_versionize))]`
                "-Zcrate-attr=feature(register_tool)",
                "-Zcrate-attr=register_tool(tfhe_lints)",
                "--cfg=tfhe_lints",
            ]
            .iter()
            .map(ToString::to_string),
        );
        let serialize_without_versionize = SerializeWithoutVersionize::new();

        with_lints(&args, vec![], move |store: &mut LintStore| {
            let lint = serialize_without_versionize.clone();
            store.register_late_pass(move |_| Box::new(lint.clone()));
        })
        .expect("with_lints failed");
    })
    .expect("cargo_integration failed");
}
