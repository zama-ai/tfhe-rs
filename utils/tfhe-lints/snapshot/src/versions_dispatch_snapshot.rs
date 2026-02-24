use std::sync::{Arc, Mutex, OnceLock};

use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{Impl, Item, ItemKind};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty::{self, TyKind};
use rustc_session::{declare_lint, impl_lint_pass};
use serde::Serialize;
use sha2::{Digest, Sha256};

use tfhe_lints_common::{get_def_id_from_ty, symbols_list_from_str};

const VERSIONS_DISPATCH_TRAIT: [&str; 3] =
    ["tfhe_versionable", "derived_traits", "VersionsDispatch"];
const UPGRADE_TRAIT: [&str; 3] = ["tfhe_versionable", "upgrade", "Upgrade"];
const UPGRADE_STR: &str = "upgrade";

#[derive(Serialize, Clone)]
pub struct VariantMeta {
    pub index: usize,
    pub inner_type_def_path: String,
    pub inner_type_display: String,
    pub struct_hash: String,
}

#[derive(Serialize, Clone)]
pub struct UpgradeMeta {
    pub source_def_path: String,
    pub target_def_path: String,
    pub body_hash: String,
}

#[derive(Serialize, Clone)]
pub struct EnumSnapshot {
    pub enum_name: String,
    pub variants: Vec<VariantMeta>,
    pub upgrades: Vec<UpgradeMeta>,
}

pub struct VersionsDispatchSnapshotInner {
    // Trait collection
    pub versions_dispatch_trait: OnceLock<Option<DefId>>,
    pub upgrade_trait: OnceLock<Option<DefId>>,
    // Collected metadata
    pub collected_enums: Mutex<Vec<EnumSnapshot>>,
    pub collected_upgrades: Mutex<Vec<UpgradeMeta>>,
}

impl Default for VersionsDispatchSnapshotInner {
    fn default() -> Self {
        Self {
            versions_dispatch_trait: OnceLock::new(),
            upgrade_trait: OnceLock::new(),
            collected_enums: Mutex::new(Vec::new()),
            collected_upgrades: Mutex::new(Vec::new()),
        }
    }
}

impl VersionsDispatchSnapshotInner {
    /// Tries to find the definition of the `VersionsDispatch` trait. The value is memoized and is
    /// instantly accessed after the first lookup.
    pub fn versions_dispatch_trait(&self, cx: &LateContext<'_>) -> Option<DefId> {
        self.versions_dispatch_trait
            .get_or_init(|| {
                cx.tcx.all_traits_including_private().find(|def_id| {
                    let path = cx.get_def_path(*def_id);
                    path == symbols_list_from_str(&VERSIONS_DISPATCH_TRAIT)
                })
            })
            .to_owned()
    }

    pub fn upgrade_trait(&self, cx: &LateContext<'_>) -> Option<DefId> {
        self.upgrade_trait
            .get_or_init(|| {
                cx.tcx.all_traits_including_private().find(|def_id| {
                    let path = cx.get_def_path(*def_id);
                    path == symbols_list_from_str(&UPGRADE_TRAIT)
                })
            })
            .to_owned()
    }
}

declare_lint! {
    /// ### What it does
    /// Collects metadata about enums implementing `VersionsDispatch`, recording each variant's
    /// fully-resolved inner type path and a hash of its fields. The collected data is written to
    /// a JSON file for use by the backward-compatibility checker.
    ///
    /// ### Why is this needed?
    /// This lint runs inside the compiler with access to `TyCtxt`, providing
    /// canonical full paths via `tcx.def_path_str()` and full field-level type information for
    /// hashing.
    pub VERSIONS_DISPATCH_SNAPSHOT,
    Warn,
    "Collects VersionsDispatch enum metadata for backward-compatibility checking"
}

#[derive(Default, Clone)]
pub struct VersionsDispatchSnapshot(pub Arc<VersionsDispatchSnapshotInner>);

impl_lint_pass!(VersionsDispatchSnapshot => [VERSIONS_DISPATCH_SNAPSHOT]);

/// Compute a SHA-256 hash of the fields of a type (struct, enum or union).
///
/// Iterates over all variants of the ADT. Structs, tuples, and unions are considered
/// to have a single variant (FIRST_VARIANT), so this handles all ADT kinds uniformly.
/// For tuple structs, field names are synthetic (`_0`, `_1`, ...).
fn compute_type_hash<'tcx>(
    tcx: ty::TyCtxt<'tcx>,
    adt_def: ty::AdtDef<'tcx>,
    args: ty::GenericArgsRef<'tcx>,
) -> String {
    let mut hasher = Sha256::new();

    for variant in adt_def.variants() {
        let name = tcx.def_path_str(variant.def_id);
        let fields_str: Vec<String> = variant
            .fields
            .iter()
            .map(|f| {
                let field_name = f.name.as_str();
                let field_ty = f.ty(tcx, args);
                format!("{field_name}:{field_ty}")
            })
            .collect();
        hasher.update(format!("{}:{};", name, fields_str.join(",")));
    }

    format!("{:x}", hasher.finalize())
}

fn hash_upgrade_body(
    cx: &LateContext<'_>,
    impl_block: &Impl<'_>,
    source_str: &str,
    target_str: &str,
) -> String {
    for item_ref in impl_block.items {
        let impl_item_id = rustc_hir::ImplItemId {
            owner_id: item_ref.owner_id,
        };
        let impl_item = cx.tcx.hir_impl_item(impl_item_id);

        if impl_item.ident.as_str() != UPGRADE_STR {
            continue;
        }

        let source_map = cx.tcx.sess.source_map();
        if let Ok(body_source) = source_map.span_to_snippet(impl_item.span) {
            let normalized = body_source
                .replace(target_str, "__TARGET__")
                .replace(source_str, "__SOURCE__");

            let mut hasher = Sha256::new();
            hasher.update(&normalized);
            return format!("{:x}", hasher.finalize());
        }
    }

    String::new()
}

impl<'tcx> LateLintPass<'tcx> for VersionsDispatchSnapshot {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'_>) {
        match &item.kind {
            ItemKind::Enum(_, _, enu) => {
                self.handle_enum(cx, item, enu);
            }
            ItemKind::Impl(impl_block) => {
                self.handle_impl(cx, item, impl_block);
            }
            _ => {}
        }
    }

    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        let enums = self.0.collected_enums.lock().unwrap();
        let upgrades = self.0.collected_upgrades.lock().unwrap();

        if enums.is_empty() {
            return;
        }

        let crate_name = cx.tcx.crate_name(LOCAL_CRATE).to_string();

        // Match upgrades to their enums
        let mut final_enums: Vec<EnumSnapshot> = enums.clone();
        for upgrade in upgrades.iter() {
            for e in &mut final_enums {
                let has_source = e
                    .variants
                    .iter()
                    .any(|v| v.inner_type_def_path == upgrade.source_def_path);
                let has_target = e
                    .variants
                    .iter()
                    .any(|v| v.inner_type_def_path == upgrade.target_def_path);
                if has_source && has_target {
                    e.upgrades.push(upgrade.clone());
                    break;
                }
            }
        }

        let data_dir =
            std::env::var("TFHE_BACKWARD_COMPAT_DATA_DIR").unwrap_or_else(|_| ".".to_string());
        let path = std::path::Path::new(&data_dir)
            .join(format!("lint_enum_snapshots_{}.json", crate_name));

        if let Ok(json) = serde_json::to_string_pretty(&final_enums) {
            let _ = std::fs::create_dir_all(&data_dir);
            let _ = std::fs::write(&path, json);
            eprintln!(
                "Written {} enum snapshots ({} upgrades) to {}",
                final_enums.len(),
                upgrades.len(),
                path.display()
            );
        }
    }
}

impl VersionsDispatchSnapshot {
    fn handle_enum<'tcx>(
        &self,
        cx: &LateContext<'tcx>,
        item: &'tcx Item<'_>,
        enu: &'tcx rustc_hir::EnumDef<'tcx>,
    ) {
        let ty = cx.tcx.type_of(item.owner_id).instantiate_identity();
        if get_def_id_from_ty(ty).is_none() {
            return;
        }

        // Check if this enum implements VersionsDispatch
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

        if !found_impl {
            return;
        }

        let enum_name = cx.tcx.def_path_str(item.owner_id.to_def_id());

        let mut variants = Vec::new();
        for (index, variant) in enu.variants.iter().enumerate() {
            let field = match variant.data.fields().first() {
                Some(f) => f,
                None => continue,
            };

            let field_def_id = field.def_id;
            let field_ty = cx.tcx.type_of(field_def_id).instantiate_identity();

            let (inner_type_def_path, inner_type_display, struct_hash) = match field_ty.kind() {
                TyKind::Adt(adt_def, args) => {
                    let def_path = cx.tcx.def_path_str(adt_def.did());
                    // This one is to have the information regarding the generic
                    let display = format!("{field_ty}");
                    let hash = compute_type_hash(cx.tcx, *adt_def, args);
                    (def_path, display, hash)
                }
                _ => {
                    let display = format!("{field_ty}");
                    (display.clone(), display, String::new())
                }
            };

            variants.push(VariantMeta {
                index,
                inner_type_def_path,
                inner_type_display,
                struct_hash,
            });
        }

        self.0.collected_enums.lock().unwrap().push(EnumSnapshot {
            enum_name,
            variants,
            upgrades: vec![],
        });
    }

    fn handle_impl<'tcx>(
        &self,
        cx: &LateContext<'tcx>,
        item: &'tcx Item<'_>,
        impl_block: &'tcx Impl<'_>,
    ) {
        let Some(trait_ref) = impl_block.of_trait else {
            return;
        };
        let Some(upgrade_trait_def_id) = self.0.upgrade_trait(cx) else {
            return;
        };
        let trait_def_id = match trait_ref.trait_ref.path.res {
            rustc_hir::def::Res::Def(_, def_id) => def_id,
            _ => return,
        };
        if trait_def_id != upgrade_trait_def_id {
            return;
        }

        // Source type = Self type of the impl
        let source_ty = cx.tcx.type_of(item.owner_id).instantiate_identity();
        let source_def_path = match source_ty.kind() {
            TyKind::Adt(adt_def, _) => cx.tcx.def_path_str(adt_def.did()),
            _ => return,
        };

        // Target type = generic arg of Upgrade<Target>
        // Extract from the trait ref generic args
        let trait_ref = cx.tcx.impl_trait_ref(item.owner_id).instantiate_identity();

        // <MyTypeV0 as tfhe_versionable::Upgrade<MyType>>
        // We take 1 for MyType
        let target_ty = trait_ref.args.type_at(1);
        let target_def_path = match target_ty.kind() {
            TyKind::Adt(adt_def, _) => cx.tcx.def_path_str(adt_def.did()),
            _ => format!("{target_ty}"),
        };

        let source_simple = source_def_path
            .rsplit("::")
            .next()
            .unwrap_or(&source_def_path);
        let target_simple = target_def_path
            .rsplit("::")
            .next()
            .unwrap_or(&target_def_path);

        let body_hash = hash_upgrade_body(cx, impl_block, source_simple, target_simple);

        self.0.collected_upgrades.lock().unwrap().push(UpgradeMeta {
            source_def_path,
            target_def_path,
            body_hash,
        });
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "versions_dispatch_snapshot");
}
