use std::sync::{Arc, OnceLock};

use rustc_hir::def_id::DefId;
use rustc_hir::{Impl, Item, ItemKind};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_session::{declare_tool_lint, impl_lint_pass};
use rustc_span::sym;

use crate::utils::{get_def_id_from_ty, is_allowed_lint, symbols_list_from_str};

declare_tool_lint! {
    pub tfhe_lints::SERIALIZE_WITHOUT_VERSIONIZE,
    Warn,
    "warns if `Serialize` is implemented without `Versionize`"
}

#[derive(Default)]
pub struct SerializeWithoutVersionizeInner {
    pub versionize_trait: OnceLock<Option<DefId>>,
}

const VERSIONIZE_TRAIT: [&str; 2] = ["tfhe_versionable", "Versionize"];
const SERIALIZE_TRAIT: [&str; 3] = ["serde", "ser", "Serialize"];
const LINT_NAME: &str = "serialize_without_versionize";

impl SerializeWithoutVersionizeInner {
    /// Tries to find the definition of the `Versionize` trait. The value is memoized and is
    /// instantly accessed after the first lookup.
    pub fn versionize_trait(&self, cx: &LateContext<'_>) -> Option<DefId> {
        self.versionize_trait
            .get_or_init(|| {
                let versionize_trait = cx.tcx.all_traits().find(|def_id| {
                    cx.match_def_path(*def_id, symbols_list_from_str(&VERSIONIZE_TRAIT).as_slice())
                });

                versionize_trait
            })
            .to_owned()
    }
}

#[derive(Default, Clone)]
pub struct SerializeWithoutVersionize(pub Arc<SerializeWithoutVersionizeInner>);

impl SerializeWithoutVersionize {
    pub fn new() -> Self {
        Self::default()
    }
}

impl_lint_pass!(SerializeWithoutVersionize => [SERIALIZE_WITHOUT_VERSIONIZE]);

impl<'tcx> LateLintPass<'tcx> for SerializeWithoutVersionize {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'_>) {
        // If the currently checked item is a trait impl
        if let ItemKind::Impl(Impl {
            of_trait: Some(ref trait_ref),
            ..
        }) = item.kind
        {
            // Gets the target type of the implementation
            let ty: rustc_middle::ty::Ty<'tcx> =
                cx.tcx.type_of(item.owner_id).instantiate_identity();

            if let Some(type_def_id) = get_def_id_from_ty(ty) {
                // If the type has been automatically generated, skip it
                if cx.tcx.has_attr(type_def_id, sym::automatically_derived) {
                    return;
                }

                // Skip it if the user explicitly allowed it.
                if is_allowed_lint(cx, type_def_id, LINT_NAME) {
                    return;
                }

                // Check if the implemented trait is `Serialize`
                if let Some(versionize_trait) = self.0.versionize_trait(cx) {
                    if let Some(def_id) = trait_ref.trait_def_id() {
                        if cx.match_def_path(
                            def_id,
                            symbols_list_from_str(&SERIALIZE_TRAIT).as_slice(),
                        ) {
                            // Try to find an implementation of versionize for this type
                            let mut found_impl = false;
                            cx.tcx
                                .for_each_relevant_impl(versionize_trait, ty, |impl_id| {
                                    if !found_impl {
                                        let trait_ref = cx
                                            .tcx
                                            .impl_trait_ref(impl_id)
                                            .expect("must be a trait implementation");

                                        if trait_ref.instantiate_identity().args.type_at(0) == ty {
                                            found_impl = true;
                                        }
                                    }
                                });

                            if !found_impl {
                                // Emit a warning
                                cx.span_lint(
                                    SERIALIZE_WITHOUT_VERSIONIZE,
                                    cx.tcx.def_span(type_def_id),
                                    format!(
                                        "Type {ty} implements `Serialize` but does not implement `Versionize`"
                                    ),|diag| {
                                        diag.note("Add `#[derive(Versionize)] for this type or silence this warning using \
`#[cfg_attr(tfhe_lints, allow(tfhe_lints::serialize_without_versionize))]``");
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
}
