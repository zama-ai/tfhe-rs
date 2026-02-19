use std::sync::{Arc, OnceLock};

use rustc_hir::def_id::DefId;
use rustc_hir::{Impl, Item, ItemKind};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_session::{declare_lint, impl_lint_pass};

use crate::utils::{get_def_id_from_ty, is_allowed_lint, symbols_list_from_str};

#[derive(Default)]
pub struct SerializeWithoutVersionizeInner {
    pub versionize_trait: OnceLock<Option<DefId>>,
}

const VERSIONIZE_TRAIT: [&str; 2] = ["tfhe_versionable", "Versionize"];
const SERIALIZE_TRAIT: [&str; 3] = ["serde_core", "ser", "Serialize"];
// Serialize trait root definition has been moved from the serde crate to serde_core
const SERIALIZE_TRAIT_LEGACY: [&str; 3] = ["serde", "ser", "Serialize"];
const LINT_NAME: &str = "serialize_without_versionize";

impl SerializeWithoutVersionizeInner {
    /// Tries to find the definition of the `Versionize` trait. The value is memoized and is
    /// instantly accessed after the first lookup.
    pub fn versionize_trait(&self, cx: &LateContext<'_>) -> Option<DefId> {
        self.versionize_trait
            .get_or_init(|| {
                let versionize_trait = cx.tcx.all_traits_including_private().find(|def_id| {
                    let path = cx.get_def_path(*def_id);
                    path == symbols_list_from_str(&VERSIONIZE_TRAIT)
                });

                versionize_trait
            })
            .to_owned()
    }
}

#[derive(Default, Clone)]
pub struct SerializeWithoutVersionize(pub Arc<SerializeWithoutVersionizeInner>);

declare_lint! {
    /// ### What it does
    /// For every type that implements `Serialize`, checks that it also implement `Versionize`
    ///
    /// ### Why is this bad?
    /// If a type is serializable but does not implement Versionize, it is likely that the
    /// implementation has been forgotten.
    ///
    /// ### Example
    /// ```rust
    /// #[derive(Serialize)]
    /// pub struct MyStruct {}
    /// ```
    /// Use instead:
    /// ```rust
    /// #[derive(Serialize, Versionize)]
    /// #[versionize(MyStructVersions)]
    /// pub struct MyStruct {}
    /// ```
    pub SERIALIZE_WITHOUT_VERSIONIZE,
    Warn,
    "Detects types that implement Serialize without implementing Versionize"
}

impl_lint_pass!(SerializeWithoutVersionize => [SERIALIZE_WITHOUT_VERSIONIZE]);

impl<'tcx> LateLintPass<'tcx> for SerializeWithoutVersionize {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'_>) {
        // If the currently checked item is a trait impl
        if let ItemKind::Impl(Impl {
            of_trait: Some(trait_ref),
            ..
        }) = item.kind
        {
            // Gets the target type of the implementation
            let ty: rustc_middle::ty::Ty<'tcx> =
                cx.tcx.type_of(item.owner_id).instantiate_identity();

            if let Some(type_def_id) = get_def_id_from_ty(ty) {
                // If the type has been automatically generated, skip it
                if cx.tcx.is_automatically_derived(type_def_id) {
                    return;
                }

                // Skip it if the user explicitly allowed it.
                if is_allowed_lint(cx, type_def_id, LINT_NAME) {
                    return;
                }

                // Check if the implemented trait is `Serialize`
                if let Some(def_id) = trait_ref.trait_ref.trait_def_id() {
                    let path = cx.get_def_path(def_id);
                    if path == symbols_list_from_str(&SERIALIZE_TRAIT)
                        || path == symbols_list_from_str(&SERIALIZE_TRAIT_LEGACY)
                    {
                        // Try to find an implementation of versionize for this type
                        let mut found_impl = false;
                        if let Some(versionize_trait) = self.0.versionize_trait(cx) {
                            cx.tcx
                                .for_each_relevant_impl(versionize_trait, ty, |impl_id| {
                                    if !found_impl {
                                        let trait_ref = cx.tcx.impl_trait_ref(impl_id);

                                        if trait_ref.instantiate_identity().args.type_at(0) == ty {
                                            found_impl = true;
                                        }
                                    }
                                });
                        }

                        if !found_impl {
                            // Emit a warning
                            cx.span_lint(
                                SERIALIZE_WITHOUT_VERSIONIZE,
                                cx.tcx.def_span(type_def_id),
                                |diag| {
                                    diag.primary_message(format!("Type {ty} implements `Serialize` but does not implement `Versionize`"));
                                    diag.note("Add `#[derive(Versionize)]` for this type or silence this warning using \
                                               `#[cfg_attr(dylint_lib = \"tfhe_lints\", allow(serialize_without_versionize))]`");
                                    diag.span_note(item.span, "`Serialize` derived here");
                                },
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "serialize_without_versionize");
}
