use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantMeta {
    pub index: usize,
    pub inner_type_def_path: String,
    pub inner_type_display: String,
    pub struct_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeMeta {
    pub source_def_path: String,
    pub target_def_path: String,
    pub body_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumSnapshot {
    pub enum_name: String,
    pub variants: Vec<VariantMeta>,
    #[serde(default)] // Might be empty if the enum have no upgrade
    pub upgrades: Vec<UpgradeMeta>,
}
