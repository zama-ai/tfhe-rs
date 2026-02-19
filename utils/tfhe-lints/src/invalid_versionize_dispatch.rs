use std::sync::{Arc, OnceLock};

use rustc_errors::Applicability;
use rustc_hir::def::Res;
use rustc_hir::def_id::DefId;
use rustc_hir::{Item, ItemKind, QPath, TyKind, VariantData};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_session::{declare_lint, impl_lint_pass};
use rustc_span::{Ident, Symbol};

use crate::utils::{get_def_id_from_ty, is_allowed_lint, symbols_list_from_str};

#[derive(Default)]
pub struct InvalidVersionizeDispatchInner {
    pub versions_dispatch_trait: OnceLock<Option<DefId>>,
}

const VERSIONS_DISPATCH_TRAIT: [&str; 3] =
    ["tfhe_versionable", "derived_traits", "VersionsDispatch"];
const LINT_NAME: &str = "invalid_versionize_dispatch";
const DEPRECTED_TYPE_PATH: &str = "tfhe_versionable::deprecation::Deprecated";

impl InvalidVersionizeDispatchInner {
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
pub struct InvalidVersionizeDispatch(pub Arc<InvalidVersionizeDispatchInner>);

declare_lint! {
    /// ### What it does
    /// For every enum that derives `VersionsDispatch`, checks that:
    /// 1. The enum name ends with `Versions`.
    /// 2. Variants are named `V0`, `V1`, ... in order.
    /// 3. Inner types follow the naming convention: `{Base}V0`, `{Base}V1`, ... for older
    ///    versions and `{Base}` (without a version suffix) for the last (current) variant,
    ///    where `{Base}` is the enum name without the `Versions` suffix.
    ///
    /// ### Why is this bad?
    /// Consistent naming across all dispatch enums makes it much easier to spot versioning
    /// mistakes during code review. Breaking any of the three rules above can lead to
    /// confusion about which version maps to which type.
    ///
    /// ### Examples
    ///
    /// #### Bad: enum name missing `Versions` suffix
    /// ```rust
    /// #[derive(VersionsDispatch)]
    /// pub enum MyStructVer {
    ///     V0(MyStructV0),
    ///     V1(MyStruct),
    /// }
    /// ```
    ///
    /// #### Bad: variant names not following V0, V1, ... convention
    /// ```rust
    /// #[derive(VersionsDispatch)]
    /// pub enum MyStructVersions {
    ///     First(MyStructV0),
    ///     Second(MyStruct),
    /// }
    /// ```
    ///
    /// #### Bad: inner types not matching the expected naming convention
    /// ```rust
    /// #[derive(VersionsDispatch)]
    /// pub enum MyStructVersions {
    ///     V0(SomethingElseV0),
    ///     V1(SomethingElse),
    /// }
    /// ```
    ///
    /// #### Good
    /// ```rust
    /// #[derive(VersionsDispatch)]
    /// pub enum MyStructVersions {
    ///     V0(MyStructV0),
    ///     V1(MyStruct),
    /// }
    /// ```
    pub INVALID_VERSIONIZE_DISPATCH,
    Warn,
    "Detects invalid naming or ordering in VersionsDispatch enums"
}

impl_lint_pass!(InvalidVersionizeDispatch => [INVALID_VERSIONIZE_DISPATCH]);

impl<'tcx> LateLintPass<'tcx> for InvalidVersionizeDispatch {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'_>) {
        // If the currently checked item is an enum definition
        if let ItemKind::Enum(enu_id, _, enu) = item.kind {
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

                // Try to find an implementation of versions dispatch for this type
                let mut found_impl = false;
                if let Some(versions_dispatch_trait) = self.0.versions_dispatch_trait(cx) {
                    cx.tcx
                        .for_each_relevant_impl(versions_dispatch_trait, ty, |impl_id| {
                            if !found_impl {
                                let trait_ref = cx.tcx.impl_trait_ref(impl_id);

                                if trait_ref.instantiate_identity().args.type_at(0) == ty {
                                    found_impl = true;
                                }
                            }
                        });
                }

                if !found_impl {
                    return;
                }

                let enum_name = cx.tcx.item_name(type_def_id);
                let mut suggested_type_name = enum_name.as_str();
                const TARGET_SUFFIX: &str = "Versions";
                for i in (1..TARGET_SUFFIX.len() + 1).rev() {
                    let partial_suffix = &TARGET_SUFFIX[..i];
                    if let Some(stripped) = suggested_type_name.strip_suffix(partial_suffix) {
                        suggested_type_name = stripped;
                        break;
                    }
                }

                if !enum_name.to_string().ends_with(TARGET_SUFFIX) {
                    cx.span_lint(INVALID_VERSIONIZE_DISPATCH, enu_id.span, |diag| {
                        diag.primary_message(format!(
                            "Enum {ty} should end with '{TARGET_SUFFIX}'"
                        ));
                        diag.span_suggestion(
                            enu_id.span,
                            "Consider renaming it to",
                            format!("{}{TARGET_SUFFIX}", suggested_type_name),
                            Applicability::MaybeIncorrect,
                        );
                        diag.note("This is a convention to easily identify dispatch enums");
                        diag.note("If you want to ignore this rule, you can add `#[cfg_attr(dylint_lib = \"tfhe_lints\", allow(invalid_dispatch_enum))]` to the enum definition");
                    });
                }

                let enu_variants_iterator = enu.variants.iter().enumerate();
                let enu_variants_length = enu.variants.len();
                for (id, variant) in enu_variants_iterator {
                    if let Some((name, variant_def_id, ident)) =
                        dispatch_variant_inner_type_name(cx, variant)
                    {
                        if cx.tcx.def_path_str(variant_def_id) == DEPRECTED_TYPE_PATH {
                            continue;
                        } else if id == enu_variants_length - 1
                            && name.as_str() != suggested_type_name
                        {
                            cx.span_lint(INVALID_VERSIONIZE_DISPATCH, ident.span, |diag| {
                                        diag.primary_message(format!("Invalid variant for dispatch enum {ty}"));
                                        diag.span_suggestion(
                                            ident.span,
                                            "Consider renaming it to",
                                            suggested_type_name,
                                            Applicability::MaybeIncorrect,
                                        );
                                        diag.note(format!("The inner type of the last variant should be named like the enum without the 'Versions' suffix, i.e. {suggested_type_name}"));
                                        diag.note("If you want to ignore this rule, you can add `#[cfg_attr(dylint_lib = \"tfhe_lints\", allow(invalid_dispatch_enum))]` to the enum definition");
                                    });
                        } else if id < enu_variants_length - 1
                            && name.as_str() != format!("{}V{id}", suggested_type_name)
                        {
                            cx.span_lint(INVALID_VERSIONIZE_DISPATCH, ident.span, |diag| {
                                        diag.primary_message(format!("Invalid variant for dispatch enum {ty}"));
                                        diag.span_suggestion(
                                            ident.span,
                                            "Consider renaming it to",
                                            format!("{}V{id}",suggested_type_name),
                                            Applicability::MaybeIncorrect,
                                        );
                                        diag.note(format!("The inner type of all variants except the last should be named like the enum without the 'Versions' suffix followed by a version suffix, i.e. {}V{id}", suggested_type_name));
                                        diag.note("If you want to ignore this rule, you can add `#[cfg_attr(dylint_lib = \"tfhe_lints\", allow(invalid_dispatch_enum))]` to the enum definition");
                                });
                        }
                    } else {
                        cx.span_lint(INVALID_VERSIONIZE_DISPATCH, variant.span, |diag| {
                            diag.primary_message(format!("Invalid variant for dispatch enum {ty}"));
                            diag.note("Do not inline fields; variants must wrap a struct type.");
                            diag.note("If you want to ignore this rule, you can add `#[cfg_attr(dylint_lib = \"tfhe_lints\", allow(invalid_dispatch_enum))]` to the enum definition");
                        });
                    }
                    if variant.ident.as_str() != format!("V{}", id) {
                        cx.span_lint(INVALID_VERSIONIZE_DISPATCH, variant.ident.span, |diag| {
                            diag.primary_message(format!("Invalid variant for dispatch enum {ty}"));
                            diag.span_suggestion(
                                variant.ident.span,
                                "Consider renaming it to",
                                format!("V{id}"),
                                Applicability::MaybeIncorrect,
                            );
                            diag.note("Variants should be named V0, V1, ... and defined in order");
                            diag.note("If you want to ignore this rule, you can add `#[cfg_attr(dylint_lib = \"tfhe_lints\", allow(invalid_dispatch_enum))]` to the enum definition");
                        });
                    }
                }
            }
        }
    }
}

fn dispatch_variant_inner_type_name<'tcx>(
    cx: &LateContext<'tcx>,
    variant: &'tcx rustc_hir::Variant<'tcx>,
) -> Option<(Symbol, DefId, Ident)> {
    let fields = match &variant.data {
        VariantData::Tuple(fields, ..) if fields.len() == 1 => fields,
        _ => return None,
    };

    let field = fields.first()?;

    let TyKind::Path(QPath::Resolved(_, path)) = &field.ty.kind else {
        return None;
    };

    let Res::Def(_, def_id) = path.res else {
        return None;
    };

    let segment = path.segments.last()?;

    Some((cx.tcx.item_name(def_id), def_id, segment.ident))
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "invalid_versionize_dispatch");
}
