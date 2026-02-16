use std::sync::{Arc, OnceLock};

use rustc_hir::def_id::DefId;
use rustc_hir::{Item, ItemKind};
use rustc_lint::{LateContext, LateLintPass, LintContext};

use crate::utils::{get_def_id_from_ty, is_allowed_lint, symbols_list_from_str};

#[derive(Default)]
pub struct VersionsVariantsOrderInner {
    pub versions_dispatch_trait: OnceLock<Option<DefId>>,
}

const VERSIONS_DISPATCH_TRAIT: [&str; 2] = ["tfhe_versionable", "VersionsDispatch"];
const LINT_NAME: &str = "versions_variants_order";

impl VersionsVariantsOrderInner {
    /// Tries to find the definition of the `VersionsDispatch` trait. The value is memoized and is
    /// instantly accessed after the first lookup.
    pub fn versions_dispatch_trait(&self, cx: &LateContext<'_>) -> Option<DefId> {
        self.versions_dispatch_trait
            .get_or_init(|| {
                let versionize_trait = cx.tcx.all_traits_including_private().find(|def_id| {
                    let path = cx.get_def_path(*def_id);
                    path == symbols_list_from_str(&VERSIONS_DISPATCH_TRAIT)
                });

                versionize_trait
            })
            .to_owned()
    }
}

#[derive(Default, Clone)]
pub struct VersionsVariantsOrder(pub Arc<VersionsVariantsOrderInner>);

dylint_linting::impl_late_lint! {
    /// ### What it does
    /// For every enum that implements `VersionsDispatch`, checks that its variants are named
    /// V0, V1, ... and are in the correct order
    ///
    /// ### Why is this bad?
    /// Using V0, V1, ... for the variant names of the dispatch enum everywhere makes it easier
    /// to catch versioning mistakes
    ///
    /// ### Example
    /// ```rust
    /// #[derive(VersionsDispatch)]
    /// pub enum MyStructVersions {
    ///  FirstVersion(MyStructV0),
    ///  SecondVersion(MyStruct)
    /// }
    /// ```
    /// Use instead:
    /// ```rust
    /// #[derive(VersionsDispatch)]
    /// pub enum MyStructVersions {
    ///  V0(MyStructV0),
    ///  V1(MyStruct)
    /// }
    /// ```
    pub VERSIONS_VARIANTS_ORDER,
    Warn,
    "Detects if variants in a DispatchEnum are correctly ordered",
    VersionsVariantsOrder::default()
}

impl<'tcx> LateLintPass<'tcx> for VersionsVariantsOrder {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'_>) {
        // If the currently checked item is an enum definition
        if let ItemKind::Enum(_, _, enu) = item.kind {
            // Gets the type name of the enum
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
            }

            // Try to find an implementation of versionize for this type
            let mut found_impl = false;
            if let Some(versionize_trait) = self.0.versions_dispatch_trait(cx) {
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

            if found_impl {
                for (id, variant) in enu.variants.iter().enumerate() {
                    if variant.ident.as_str() != format!("V{}", id) {
                        cx.span_lint(VERSIONS_VARIANTS_ORDER, variant.span, |diag| {
                            diag.primary_message(format!("Invalid variant for dispatch enum {ty}"));
                            diag.note("Variants should be named V0, V1, ... and defined in order");
                        });
                    }
                }
            }
        }
    }
}
