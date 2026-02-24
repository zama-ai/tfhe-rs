use std::cmp::Ordering;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use crate::snapshot::{EnumSnapshot, UpgradeMeta, VariantMeta};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Ok,
    Warning,
    Error,
}

/// Each variant represents a distinct type of change between two snapshots.
/// The severity is derived from the variant — change the `severity()` match
/// to update the rules in one place.
#[derive(Debug, Clone)]
pub enum DiffEntry {
    EnumAdded {
        name: String,
        variant_count: usize,
    },
    EnumRemoved {
        name: String,
    },
    VariantAdded {
        enum_name: String,
        index: usize,
        type_path: String,
    },
    VariantRemoved {
        enum_name: String,
        index: usize,
        type_path: String,
    },
    StructHashChanged {
        enum_name: String,
        index: usize,
        type_path: String,
        old_hash: String,
        new_hash: String,
    },
    UpgradeAdded {
        enum_name: String,
        source: String,
        target: String,
    },
    UpgradeRemoved {
        enum_name: String,
        source: String,
        target: String,
    },
    UpgradeHashChanged {
        enum_name: String,
        source: String,
        target: String,
        old_hash: String,
        new_hash: String,
    },
}

impl DiffEntry {
    pub fn enum_added(snap: &EnumSnapshot) -> Self {
        Self::EnumAdded {
            name: snap.enum_name.clone(),
            variant_count: snap.variants.len(),
        }
    }

    pub fn enum_removed(snap: &EnumSnapshot) -> Self {
        Self::EnumRemoved {
            name: snap.enum_name.clone(),
        }
    }

    pub fn variant_added(enum_name: &str, v: &VariantMeta) -> Self {
        Self::VariantAdded {
            enum_name: enum_name.to_string(),
            index: v.index,
            type_path: v.inner_type_def_path.clone(),
        }
    }

    pub fn variant_removed(enum_name: &str, v: &VariantMeta) -> Self {
        Self::VariantRemoved {
            enum_name: enum_name.to_string(),
            index: v.index,
            type_path: v.inner_type_def_path.clone(),
        }
    }

    pub fn struct_hash_changed(enum_name: &str, old: &VariantMeta, new: &VariantMeta) -> Self {
        Self::StructHashChanged {
            enum_name: enum_name.to_string(),
            index: old.index,
            type_path: old.inner_type_def_path.clone(),
            old_hash: old.struct_hash.clone(),
            new_hash: new.struct_hash.clone(),
        }
    }

    pub fn upgrade_added(enum_name: &str, u: &UpgradeMeta) -> Self {
        Self::UpgradeAdded {
            enum_name: enum_name.to_string(),
            source: u.source_def_path.clone(),
            target: u.target_def_path.clone(),
        }
    }

    pub fn upgrade_removed(enum_name: &str, u: &UpgradeMeta) -> Self {
        Self::UpgradeRemoved {
            enum_name: enum_name.to_string(),
            source: u.source_def_path.clone(),
            target: u.target_def_path.clone(),
        }
    }

    pub fn upgrade_hash_changed(enum_name: &str, old: &UpgradeMeta, new: &UpgradeMeta) -> Self {
        Self::UpgradeHashChanged {
            enum_name: enum_name.to_string(),
            source: old.source_def_path.clone(),
            target: old.target_def_path.clone(),
            old_hash: old.body_hash.clone(),
            new_hash: new.body_hash.clone(),
        }
    }

    /// Split a slice of entries into (errors, warnings, additions) by severity.
    pub fn split_by_severity(
        entries: &[DiffEntry],
    ) -> (Vec<&DiffEntry>, Vec<&DiffEntry>, Vec<&DiffEntry>) {
        let errors = entries
            .iter()
            .filter(|e| e.severity() == Severity::Error)
            .collect();
        let warnings = entries
            .iter()
            .filter(|e| e.severity() == Severity::Warning)
            .collect();
        let additions = entries
            .iter()
            .filter(|e| e.severity() == Severity::Ok)
            .collect();
        (errors, warnings, additions)
    }

    /// Single source of truth for severity rules.
    pub fn severity(&self) -> Severity {
        match self {
            Self::EnumAdded { .. } | Self::VariantAdded { .. } | Self::UpgradeAdded { .. } => {
                Severity::Ok
            }
            Self::EnumRemoved { .. }
            | Self::StructHashChanged { .. }
            | Self::UpgradeRemoved { .. }
            | Self::UpgradeHashChanged { .. } => Severity::Warning,
            Self::VariantRemoved { .. } => Severity::Error,
        }
    }
}

impl std::fmt::Display for DiffEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnumAdded {
                name,
                variant_count,
            } => {
                write!(f, "New enum `{name}` ({variant_count} variants)")
            }
            Self::EnumRemoved { name } => {
                write!(f, "Enum `{name}` removed")
            }
            Self::VariantAdded {
                enum_name,
                index,
                type_path,
            } => {
                write!(f, "`{enum_name}`: new variant {index} (`{type_path}`)")
            }
            Self::VariantRemoved {
                enum_name,
                index,
                type_path,
            } => {
                write!(f, "`{enum_name}`: variant {index} (`{type_path}`) removed")
            }
            Self::StructHashChanged {
                enum_name,
                index,
                type_path,
                old_hash,
                new_hash,
            } => {
                write!(
                    f,
                    "`{enum_name}` variant {index} (`{type_path}`):\n   \
                     struct hash changed\n   \
                     old: {old_hash}\n   \
                     new: {new_hash}"
                )
            }
            Self::UpgradeAdded {
                enum_name,
                source,
                target,
            } => {
                write!(f, "`{enum_name}`: new upgrade `{source}` → `{target}`")
            }
            Self::UpgradeRemoved {
                enum_name,
                source,
                target,
            } => {
                write!(f, "`{enum_name}`: upgrade `{source}` → `{target}` removed")
            }
            Self::UpgradeHashChanged {
                enum_name,
                source,
                target,
                old_hash,
                new_hash,
            } => {
                write!(
                    f,
                    "`{enum_name}` upgrade `{source}` → `{target}`:\n   \
                     body hash changed\n   \
                     old: {old_hash}\n   \
                     new: {new_hash}"
                )
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Registry(Vec<EnumSnapshot>); // sorted by enum_name

impl Registry {
    pub fn load_registry(dir: &Path) -> Result<Self, ExitCode> {
        let mut snapshots = Vec::new();

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(err) => {
                eprintln!("Cannot read directory {}: {}", dir.display(), err);
                return Err(ExitCode::from(1));
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();

            // Skip subdirectories (e.g. "head" generated by make backward-snapshot-head)
            if path.is_dir() {
                continue;
            }

            let file_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            if !file_name.starts_with("lint_enum_snapshots_") || !file_name.ends_with(".json") {
                eprint!(
                    "We should not have this kind of file in the snapshot directory: {}. ",
                    path.display()
                );
                return Err(ExitCode::from(1));
            }

            let content = match fs::read_to_string(&path) {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("Cannot read {}: {}", path.display(), err);
                    return Err(ExitCode::from(1));
                }
            };

            let file_snapshots: Vec<EnumSnapshot> = match serde_json::from_str(&content) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("Cannot parse {}: {}", path.display(), err);
                    return Err(ExitCode::from(1));
                }
            };

            snapshots.extend(file_snapshots);
        }

        snapshots.sort_by(|a, b| a.enum_name.cmp(&b.enum_name));

        eprintln!("Loaded {} enums from {}", snapshots.len(), dir.display(),);

        Ok(Registry(snapshots))
    }

    pub fn diff(&self, new: &Registry) -> Vec<DiffEntry> {
        let mut entries = Vec::new();

        let mut old_iter = self.0.iter().peekable();
        let mut new_iter = new.0.iter().peekable();

        loop {
            match (old_iter.peek(), new_iter.peek()) {
                // Case where both old and new have an enum to compare
                (Some(old_snap), Some(new_snap)) => {
                    // As everything is sorted by enum_name, we can compare the names to decide
                    // what to do
                    match old_snap.enum_name.cmp(&new_snap.enum_name) {
                        // This case represents a removal, as the old enum does not exist in the
                        // new registry (we have exhausted the new enums with smaller names)
                        // We move the old iterator forward and record the removal, but we keep the
                        // new iterator
                        Ordering::Less => {
                            let old_snap = old_iter.next().unwrap();
                            entries.push(DiffEntry::enum_removed(old_snap));
                        }
                        // This case represents an addition, as the new enum does not exist in the
                        // old registry
                        // We move the new iterator forward and record the addition, but we keep
                        // the old
                        Ordering::Greater => {
                            let new_snap = new_iter.next().unwrap();
                            entries.push(DiffEntry::enum_added(new_snap));
                        }
                        // We have the same enum name in both registries, we need to compare them
                        // for modifications
                        // We move both iterators forward and compare the enums, but we don't
                        // record anything
                        Ordering::Equal => {
                            let old_snap = old_iter.next().unwrap();
                            let new_snap = new_iter.next().unwrap();
                            Self::diff_enum(old_snap, new_snap, &mut entries);
                        }
                    }
                }
                // Case where we have exhausted the new enums but still have old enums left
                // (removals)
                (Some(_), None) => {
                    let old_snap = old_iter.next().unwrap();
                    entries.push(DiffEntry::enum_removed(old_snap));
                }
                // Case where we have exhausted the old enums but still have new enums left
                (None, Some(_)) => {
                    let new_snap = new_iter.next().unwrap();
                    entries.push(DiffEntry::enum_added(new_snap));
                }
                // Both iterators are exhausted, we are done
                (None, None) => break,
            }
        }

        entries
    }

    fn diff_enum(old_enum: &EnumSnapshot, new_enum: &EnumSnapshot, entries: &mut Vec<DiffEntry>) {
        let name = &old_enum.enum_name;

        // Variant additions & modifications
        for nv in &new_enum.variants {
            match old_enum.variants.iter().find(|ov| ov.index == nv.index) {
                None => entries.push(DiffEntry::variant_added(name, nv)),
                Some(ov) if ov.struct_hash != nv.struct_hash => {
                    entries.push(DiffEntry::struct_hash_changed(name, ov, nv));
                }
                _ => {}
            }
        }

        // Variant removals
        for ov in &old_enum.variants {
            if !new_enum.variants.iter().any(|nv| nv.index == ov.index) {
                entries.push(DiffEntry::variant_removed(name, ov));
            }
        }

        // Upgrade additions & modifications
        for nu in &new_enum.upgrades {
            match old_enum.upgrades.iter().find(|ou| {
                ou.source_def_path == nu.source_def_path && ou.target_def_path == nu.target_def_path
            }) {
                None => entries.push(DiffEntry::upgrade_added(name, nu)),
                Some(ou) if ou.body_hash != nu.body_hash => {
                    entries.push(DiffEntry::upgrade_hash_changed(name, ou, nu));
                }
                _ => {}
            }
        }

        // Upgrade removals
        for ou in &old_enum.upgrades {
            if !new_enum.upgrades.iter().any(|nu| {
                nu.source_def_path == ou.source_def_path && nu.target_def_path == ou.target_def_path
            }) {
                entries.push(DiffEntry::upgrade_removed(name, ou));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn variant(index: usize, def_path: &str, hash: &str) -> VariantMeta {
        VariantMeta {
            index,
            inner_type_def_path: def_path.to_string(),
            inner_type_display: def_path.to_string(),
            struct_hash: hash.to_string(),
        }
    }

    fn upgrade(source: &str, target: &str, hash: &str) -> UpgradeMeta {
        UpgradeMeta {
            source_def_path: source.to_string(),
            target_def_path: target.to_string(),
            body_hash: hash.to_string(),
        }
    }

    fn enum_snap(
        name: &str,
        variants: Vec<VariantMeta>,
        upgrades: Vec<UpgradeMeta>,
    ) -> EnumSnapshot {
        EnumSnapshot {
            enum_name: name.to_string(),
            variants,
            upgrades,
        }
    }

    fn registry(mut snaps: Vec<EnumSnapshot>) -> Registry {
        snaps.sort_by(|a, b| a.enum_name.cmp(&b.enum_name));
        Registry(snaps)
    }

    /// Helper: count entries by severity
    fn count_by_severity(entries: &[DiffEntry], severity: Severity) -> usize {
        entries.iter().filter(|e| e.severity() == severity).count()
    }

    // ---- diff: additions ----

    #[test]
    fn additions_new_enum() {
        let old = registry(vec![enum_snap("Old", vec![variant(0, "T", "aaa")], vec![])]);
        let new = registry(vec![
            enum_snap("Old", vec![variant(0, "T", "aaa")], vec![]),
            enum_snap("New", vec![variant(0, "T", "bbb")], vec![]),
        ]);

        let entries = old.diff(&new);
        assert_eq!(count_by_severity(&entries, Severity::Ok), 1);
        assert!(matches!(&entries[0], DiffEntry::EnumAdded { name, .. } if name == "New"));
        assert_eq!(count_by_severity(&entries, Severity::Warning), 0);
        assert_eq!(count_by_severity(&entries, Severity::Error), 0);
    }

    #[test]
    fn additions_new_variant() {
        let old = registry(vec![enum_snap("E", vec![variant(0, "V0", "aaa")], vec![])]);
        let new = registry(vec![enum_snap(
            "E",
            vec![variant(0, "V0", "aaa"), variant(1, "V1", "bbb")],
            vec![],
        )]);

        let entries = old.diff(&new);
        assert_eq!(count_by_severity(&entries, Severity::Ok), 1);
        assert!(matches!(
            &entries[0],
            DiffEntry::VariantAdded { index: 1, .. }
        ));
        assert_eq!(count_by_severity(&entries, Severity::Warning), 0);
        assert_eq!(count_by_severity(&entries, Severity::Error), 0);
    }

    #[test]
    fn additions_new_upgrade() {
        let old = registry(vec![enum_snap(
            "E",
            vec![variant(0, "V0", "aaa"), variant(1, "V1", "bbb")],
            vec![],
        )]);
        let new = registry(vec![enum_snap(
            "E",
            vec![variant(0, "V0", "aaa"), variant(1, "V1", "bbb")],
            vec![upgrade("V0", "V1", "uuu")],
        )]);

        let entries = old.diff(&new);
        assert_eq!(count_by_severity(&entries, Severity::Ok), 1);
        assert!(matches!(&entries[0], DiffEntry::UpgradeAdded { .. }));
        assert_eq!(count_by_severity(&entries, Severity::Warning), 0);
        assert_eq!(count_by_severity(&entries, Severity::Error), 0);
    }

    #[test]
    fn additions_none_when_identical() {
        let old = registry(vec![enum_snap("E", vec![variant(0, "V0", "aaa")], vec![])]);
        let new = old.clone();

        let entries = old.diff(&new);
        assert!(entries.is_empty());
    }

    // ---- diff: warnings (struct hash, upgrade changes, enum removals) ----

    #[test]
    fn warning_variant_hash_changed() {
        let old = registry(vec![enum_snap("E", vec![variant(0, "V0", "aaa")], vec![])]);
        let new = registry(vec![enum_snap(
            "E",
            vec![variant(0, "V0", "CHANGED")],
            vec![],
        )]);

        let entries = old.diff(&new);
        assert_eq!(count_by_severity(&entries, Severity::Warning), 1);
        assert!(matches!(&entries[0], DiffEntry::StructHashChanged { .. }));
        assert_eq!(count_by_severity(&entries, Severity::Ok), 0);
        assert_eq!(count_by_severity(&entries, Severity::Error), 0);
    }

    #[test]
    fn warning_upgrade_hash_changed() {
        let old = registry(vec![enum_snap(
            "E",
            vec![variant(0, "V0", "aaa"), variant(1, "V1", "bbb")],
            vec![upgrade("V0", "V1", "uuu")],
        )]);
        let new = registry(vec![enum_snap(
            "E",
            vec![variant(0, "V0", "aaa"), variant(1, "V1", "bbb")],
            vec![upgrade("V0", "V1", "CHANGED")],
        )]);

        let entries = old.diff(&new);
        assert_eq!(count_by_severity(&entries, Severity::Warning), 1);
        assert!(matches!(&entries[0], DiffEntry::UpgradeHashChanged { .. }));
        assert_eq!(count_by_severity(&entries, Severity::Ok), 0);
        assert_eq!(count_by_severity(&entries, Severity::Error), 0);
    }

    #[test]
    fn warning_upgrade_removed() {
        let old = registry(vec![enum_snap(
            "E",
            vec![variant(0, "V0", "aaa"), variant(1, "V1", "bbb")],
            vec![upgrade("V0", "V1", "uuu")],
        )]);
        let new = registry(vec![enum_snap(
            "E",
            vec![variant(0, "V0", "aaa"), variant(1, "V1", "bbb")],
            vec![],
        )]);

        let entries = old.diff(&new);
        assert_eq!(count_by_severity(&entries, Severity::Warning), 1);
        assert!(matches!(&entries[0], DiffEntry::UpgradeRemoved { .. }));
        assert_eq!(count_by_severity(&entries, Severity::Error), 0);
    }

    #[test]
    fn warning_enum_removed() {
        let old = registry(vec![enum_snap("E", vec![variant(0, "V0", "aaa")], vec![])]);
        let new = registry(vec![]);

        let entries = old.diff(&new);
        assert_eq!(count_by_severity(&entries, Severity::Warning), 1);
        assert!(matches!(&entries[0], DiffEntry::EnumRemoved { .. }));
        assert_eq!(count_by_severity(&entries, Severity::Ok), 0);
        assert_eq!(count_by_severity(&entries, Severity::Error), 0);
    }

    #[test]
    fn warnings_none_when_identical() {
        let old = registry(vec![enum_snap(
            "E",
            vec![variant(0, "V0", "aaa")],
            vec![upgrade("V0", "V1", "uuu")],
        )]);
        let new = old.clone();

        let entries = old.diff(&new);
        assert_eq!(count_by_severity(&entries, Severity::Warning), 0);
    }

    // ---- diff: errors (variant removals) ----

    #[test]
    fn error_variant_removed() {
        let old = registry(vec![enum_snap(
            "E",
            vec![variant(0, "V0", "aaa"), variant(1, "V1", "bbb")],
            vec![],
        )]);
        let new = registry(vec![enum_snap("E", vec![variant(0, "V0", "aaa")], vec![])]);

        let entries = old.diff(&new);
        assert_eq!(count_by_severity(&entries, Severity::Error), 1);
        assert!(matches!(
            &entries[0],
            DiffEntry::VariantRemoved { index: 1, .. }
        ));
        assert_eq!(count_by_severity(&entries, Severity::Warning), 0);
    }

    #[test]
    fn errors_none_when_identical() {
        let old = registry(vec![enum_snap("E", vec![variant(0, "V0", "aaa")], vec![])]);
        let new = old.clone();

        let entries = old.diff(&new);
        assert_eq!(count_by_severity(&entries, Severity::Error), 0);
    }

    #[test]
    fn errors_none_when_enum_removed() {
        let old = registry(vec![enum_snap("E", vec![variant(0, "V0", "aaa")], vec![])]);
        let new = registry(vec![]);

        let entries = old.diff(&new);
        // Enum removal is a warning, not an error
        assert_eq!(count_by_severity(&entries, Severity::Error), 0);
        assert!(count_by_severity(&entries, Severity::Warning) > 0);
    }

    // ---- end-to-end diff flow ----

    #[test]
    fn diff_full_flow_only_additions() {
        let old = registry(vec![enum_snap("E", vec![variant(0, "V0", "aaa")], vec![])]);
        let new = registry(vec![
            enum_snap(
                "E",
                vec![variant(0, "V0", "aaa"), variant(1, "V1", "bbb")],
                vec![upgrade("V0", "V1", "uuu")],
            ),
            enum_snap("New", vec![variant(0, "T", "ccc")], vec![]),
        ]);

        let entries = old.diff(&new);

        assert_eq!(count_by_severity(&entries, Severity::Ok), 3); // new enum + new variant + new upgrade
        assert_eq!(count_by_severity(&entries, Severity::Warning), 0);
        assert_eq!(count_by_severity(&entries, Severity::Error), 0);
    }

    #[test]
    fn diff_full_flow_mixed_changes() {
        let old = registry(vec![
            enum_snap(
                "A",
                vec![variant(0, "V0", "aaa"), variant(1, "V1", "bbb")],
                vec![upgrade("V0", "V1", "uuu")],
            ),
            enum_snap("B", vec![variant(0, "T", "ccc")], vec![]),
        ]);
        let new = registry(vec![enum_snap(
            "A",
            vec![
                variant(0, "V0", "aaa"),
                // V1 removed -> error
                variant(2, "V2", "ddd"),
            ],
            vec![upgrade("V0", "V1", "CHANGED")], // upgrade modified -> warning
        )]);
        // B removed -> warning

        let entries = old.diff(&new);

        assert_eq!(count_by_severity(&entries, Severity::Ok), 1); // new variant V2
        assert_eq!(count_by_severity(&entries, Severity::Warning), 2); // upgrade hash changed + enum B removed
        assert_eq!(count_by_severity(&entries, Severity::Error), 1); // variant V1 removed
    }
}
