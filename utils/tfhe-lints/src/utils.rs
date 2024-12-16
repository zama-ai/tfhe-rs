use rustc_ast::tokenstream::TokenTree;
use rustc_hir::def_id::DefId;
use rustc_lint::LateContext;
use rustc_middle::ty::{Ty, TyKind};
use rustc_span::Symbol;

/// Converts an array of str into a Vec of [`Symbol`]
pub fn symbols_list_from_str(list: &[&str]) -> Vec<Symbol> {
    list.iter().map(|s| Symbol::intern(s)).collect()
}

/// Checks if the lint is allowed for the item represented by [`DefId`].
/// This shouldn't be necessary since the lints are declared with the
/// `declare_tool_lint` macro but for a mysterious reason this does not
/// work automatically.
pub fn is_allowed_lint(cx: &LateContext<'_>, target: DefId, lint_name: &str) -> bool {
    for attr in cx.tcx.get_attrs(target, Symbol::intern("allow")) {
        let tokens = attr.get_normal_item().args.inner_tokens();
        let mut trees = tokens.trees();

        if let Some(TokenTree::Token(tool_token, _)) = trees.next() {
            if tool_token.is_ident_named(Symbol::intern(lint_name)) {
                return true;
            }
        }
    }

    false
}

/// Gets the [`DefId`] of a type
pub fn get_def_id_from_ty(ty: Ty<'_>) -> Option<DefId> {
    match ty.kind() {
        TyKind::Adt(adt_def, _) => Some(adt_def.did()),
        TyKind::Alias(_, alias_ty) => Some(alias_ty.def_id),
        TyKind::Dynamic(predicates, ..) => predicates.principal_def_id(),
        TyKind::FnDef(def_id, _)
        | TyKind::Foreign(def_id)
        | TyKind::Closure(def_id, ..)
        | TyKind::CoroutineClosure(def_id, _)
        | TyKind::Coroutine(def_id, _)
        | TyKind::CoroutineWitness(def_id, _) => Some(*def_id),
        _ => None,
    }
}
