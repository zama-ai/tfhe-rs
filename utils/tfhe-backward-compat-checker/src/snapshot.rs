//! Snapshot data types shared between the dylint lint and the backward-compat checker.
//! These structs are serialized to JSON by the lint and deserialized by the checker.

use serde::{Deserialize, Serialize};

/// A variant inside a versions dispatch enum (e.g. `V0(FooV0)`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantMeta {
    /// Variant index in the enum (e.g. 0 for V0, 1 for V1).
    pub index: usize,
    /// Full def path of the inner type, without generics (e.g. `tfhe::shortint::FooV0`).
    pub inner_type_def_path: String,
    /// Full path of the inner type, with generics (e.g. `tfhe::shortint::FooV0<Scalar>`).
    pub inner_type_display: String,
    /// SHA-256 hash of the inner type's fields. Changes when the layout changes.
    pub type_hash: String,
}

/// An upgrade implementation between two versioned types (e.g. `Upgrade<FooV0, FooV1>`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeMeta {
    /// Full def path of the source type.
    pub source_def_path: String,
    /// Full def path of the target type.
    pub target_def_path: String,
    /// SHA-256 hash of the upgrade function body. Changes when the migration logic changes.
    pub body_hash: String,
}

/// Snapshot of a single versions dispatch enum with its variants and upgrades.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumSnapshot {
    pub enum_name: String,
    pub variants: Vec<VariantMeta>,
    #[serde(default)] // Might be empty if the enum has no upgrade
    pub upgrades: Vec<UpgradeMeta>,
}
