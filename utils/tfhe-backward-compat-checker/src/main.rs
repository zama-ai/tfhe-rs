use clap::Parser;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VariantMeta {
    index: usize,
    inner_type_def_path: String,
    inner_type_display: String,
    struct_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpgradeMeta {
    source_def_path: String,
    target_def_path: String,
    body_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnumSnapshot {
    enum_name: String,
    variants: Vec<VariantMeta>,
    #[serde(default)] // Might be empty if the enum have no upgrade
    upgrades: Vec<UpgradeMeta>,
}

#[derive(Debug, Clone)]
struct Registry(Vec<EnumSnapshot>); // sorted by enum_name

#[derive(Parser)]
#[command(name = "backward-compat-checker")]
#[command(about = "Check backward compatibility between two versions of tfhe-rs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Check backward compatibility between base and head snapshots
    Check(CheckArgs),
    /// Generate a markdown diff report between two snapshot directories
    DiffReport(DiffReportArgs),
}

#[derive(clap::Args)]
struct CheckArgs {
    /// Directory containing base (origin) JSON files
    #[arg(long)]
    base_dir: PathBuf,

    /// File suffix for base files (e.g. "origin")
    #[arg(long)]
    base_suffix: String,

    /// Directory containing head (target) JSON files
    #[arg(long)]
    head_dir: PathBuf,

    /// File suffix for head files (e.g. "target")
    #[arg(long)]
    head_suffix: String,

    #[arg(long, default_value_t = false)]
    allow_additional_enums: bool,
}

#[derive(clap::Args)]
struct DiffReportArgs {
    /// Directory containing old snapshot JSON files
    #[arg(long)]
    base_dir: PathBuf,

    /// File suffix for old snapshot files
    #[arg(long)]
    base_suffix: String,

    /// Directory containing new snapshot JSON files
    #[arg(long)]
    head_dir: PathBuf,

    /// File suffix for new snapshot files
    #[arg(long)]
    head_suffix: String,

    /// Output file for the markdown report
    #[arg(long, short)]
    output: PathBuf,
}

impl Registry {
    fn load_registry(dir: &Path, suffix: &str) -> Self {
        let mut snapshots = Vec::new();

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(err) => {
                eprintln!("Cannot read directory {}: {}", dir.display(), err);
                eprintln!("Return empty registry");
                return Registry(snapshots);
            }
        };

        let expected_suffix = format!("_{suffix}.json");

        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            if !file_name.starts_with("lint_enum_snapshots_")
                || !file_name.ends_with(&expected_suffix)
            {
                continue;
            }

            let content = match fs::read_to_string(&path) {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("Cannot read {}: {}", path.display(), err);
                    continue;
                }
            };

            let file_snapshots: Vec<EnumSnapshot> = match serde_json::from_str(&content) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("Cannot parse {}: {}", path.display(), err);
                    continue;
                }
            };

            snapshots.extend(file_snapshots);
        }

        snapshots.sort_by(|a, b| a.enum_name.cmp(&b.enum_name));

        eprintln!(
            "Loaded {} enums from {} ({} files)",
            snapshots.len(),
            dir.display(),
            suffix
        );

        Registry(snapshots)
    }

    fn diff(&self, new: &Registry) -> (Vec<String>, Vec<String>, Vec<String>) {
        let mut additions = Vec::new();
        let mut modifications = Vec::new();
        let mut removals = Vec::new();

        let mut old_iter = self.0.iter().peekable();
        let mut new_iter = new.0.iter().peekable();

        loop {
            match (old_iter.peek(), new_iter.peek()) {
                (Some(old_snap), Some(new_snap)) => {
                    match old_snap.enum_name.cmp(&new_snap.enum_name) {
                        Ordering::Less => {
                            let old_snap = old_iter.next().unwrap();
                            removals.push(format!("Enum `{}` removed", old_snap.enum_name));
                        }
                        Ordering::Greater => {
                            let new_snap = new_iter.next().unwrap();
                            additions.push(format!(
                                "New enum `{}` ({} variants)",
                                new_snap.enum_name,
                                new_snap.variants.len()
                            ));
                        }
                        Ordering::Equal => {
                            let old_snap = old_iter.next().unwrap();
                            let new_snap = new_iter.next().unwrap();
                            Self::diff_enum(
                                &old_snap.enum_name,
                                old_snap,
                                new_snap,
                                &mut additions,
                                &mut modifications,
                                &mut removals,
                            );
                        }
                    }
                }
                (Some(_), None) => {
                    let old_snap = old_iter.next().unwrap();
                    removals.push(format!("Enum `{}` removed", old_snap.enum_name));
                }
                (None, Some(_)) => {
                    let new_snap = new_iter.next().unwrap();
                    additions.push(format!(
                        "New enum `{}` ({} variants)",
                        new_snap.enum_name,
                        new_snap.variants.len()
                    ));
                }
                (None, None) => break,
            }
        }

        (additions, modifications, removals)
    }

    fn diff_enum(
        name: &str,
        old_enum: &EnumSnapshot,
        new_enum: &EnumSnapshot,
        additions: &mut Vec<String>,
        modifications: &mut Vec<String>,
        removals: &mut Vec<String>,
    ) {
        // Variant additions & modifications
        for nv in &new_enum.variants {
            match old_enum.variants.iter().find(|ov| ov.index == nv.index) {
                None => additions.push(format!(
                    "`{}`: new variant {} (`{}`)",
                    name, nv.index, nv.inner_type_def_path
                )),
                Some(ov) if ov.struct_hash != nv.struct_hash => modifications.push(format!(
                    "`{}` variant {} (`{}`):\n   \
                 struct hash changed\n   \
                 old: {}\n   \
                 new: {}",
                    name, ov.index, ov.inner_type_def_path, ov.struct_hash, nv.struct_hash
                )),
                _ => {}
            }
        }

        // Variant removals
        for ov in &old_enum.variants {
            if !new_enum.variants.iter().any(|nv| nv.index == ov.index) {
                removals.push(format!(
                    "`{}`: variant {} (`{}`) removed",
                    name, ov.index, ov.inner_type_def_path
                ));
            }
        }

        // Upgrade additions & modifications
        for nu in &new_enum.upgrades {
            match old_enum.upgrades.iter().find(|ou| {
                ou.source_def_path == nu.source_def_path && ou.target_def_path == nu.target_def_path
            }) {
                None => additions.push(format!(
                    "`{}`: new upgrade `{}` → `{}`",
                    name, nu.source_def_path, nu.target_def_path
                )),
                Some(ou) if ou.body_hash != nu.body_hash => modifications.push(format!(
                    "`{}` upgrade `{}` → `{}`:\n   \
                 body hash changed\n   \
                 old: {}\n   \
                 new: {}",
                    name, ou.source_def_path, ou.target_def_path, ou.body_hash, nu.body_hash
                )),
                _ => {}
            }
        }

        // Upgrade removals
        for ou in &old_enum.upgrades {
            if !new_enum.upgrades.iter().any(|nu| {
                nu.source_def_path == ou.source_def_path && nu.target_def_path == ou.target_def_path
            }) {
                removals.push(format!(
                    "`{}`: upgrade `{}` → `{}` removed",
                    name, ou.source_def_path, ou.target_def_path
                ));
            }
        }
    }
}

fn build_diff_report(
    additions: &[String],
    modifications: &[String],
    removals: &[String],
) -> String {
    if additions.is_empty() && modifications.is_empty() && removals.is_empty() {
        return String::new();
    }

    let mut lines = Vec::new();

    if !modifications.is_empty() || !removals.is_empty() {
        lines.push(
            ":rotating_light: **Backward-compat snapshot base files have suspicious changes**\n"
                .to_string(),
        );
        lines.push(
            "Existing types or upgrades were **modified or removed**. \
             This can hide breaking changes — please review carefully \
             and make sure this is intentional.\n"
                .to_string(),
        );
    } else {
        lines.push(
            ":information_source: **Backward-compat snapshot base files were updated**\n"
                .to_string(),
        );
        lines.push(
            "Only new types/variants/upgrades were added. \
             This is expected when introducing new versioned types.\n"
                .to_string(),
        );
    }

    if !removals.is_empty() {
        lines.push("<details>\n<summary>:x: Removals</summary>\n".to_string());
        for r in removals {
            lines.push(format!("- {r}"));
        }
        lines.push("\n</details>\n".to_string());
    }

    if !modifications.is_empty() {
        lines.push("<details>\n<summary>:warning: Modifications</summary>\n".to_string());
        for m in modifications {
            lines.push(format!("- {m}"));
        }
        lines.push("\n</details>\n".to_string());
    }

    if !additions.is_empty() {
        lines.push("<details>\n<summary>:heavy_plus_sign: Additions</summary>\n".to_string());
        for a in additions {
            lines.push(format!("- {a}"));
        }
        lines.push("\n</details>\n".to_string());
    }

    lines.join("\n")
}

fn run_check(args: CheckArgs) -> ExitCode {
    let base = Registry::load_registry(&args.base_dir, &args.base_suffix);
    let head = Registry::load_registry(&args.head_dir, &args.head_suffix);

    let (additions, modifications, removals) = base.diff(&head);

    // Print summary of additions
    if !additions.is_empty() {
        eprintln!("\nAdditions:");
        for a in &additions {
            eprintln!("   + {a}");
        }
    }

    // Modifications and removals are errors
    let has_errors = !modifications.is_empty() || !removals.is_empty();

    if !removals.is_empty() {
        eprintln!("\nRemovals:");
        for r in &removals {
            eprintln!("   - {r}");
        }
    }

    if !modifications.is_empty() {
        eprintln!("\nModifications:");
        for m in &modifications {
            eprintln!("   ~ {m}");
        }
    }

    if has_errors {
        eprintln!("\nFound {} error(s)", modifications.len() + removals.len());
        return ExitCode::from(1);
    }

    if !&args.allow_additional_enums && !additions.is_empty() {
        eprintln!("\nNew enums/variants/upgrades are not allowed");
        eprintln!("To fix it please regenerate the base snapshot");
        return ExitCode::from(2);
    }

    eprintln!("\nBackward compatibility check passed!");
    println!("OK");
    ExitCode::SUCCESS
}

fn run_diff_report(args: DiffReportArgs) -> ExitCode {
    let old = Registry::load_registry(&args.base_dir, &args.base_suffix);
    let new = Registry::load_registry(&args.head_dir, &args.head_suffix);

    let (additions, modifications, removals) = old.diff(&new);

    let report = build_diff_report(&additions, &modifications, &removals);

    if let Err(err) = fs::write(&args.output, &report) {
        eprintln!("Cannot write report to {}: {}", args.output.display(), err);
        return ExitCode::from(1);
    }

    if report.is_empty() {
        eprintln!("No changes detected");
    } else {
        eprintln!("Report written to {}", args.output.display());
    }

    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Check(args) => run_check(args),
        Command::DiffReport(args) => run_diff_report(args),
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

    // ---- diff: additions ----

    #[test]
    fn additions_new_enum() {
        let old = registry(vec![enum_snap("Old", vec![variant(0, "T", "aaa")], vec![])]);
        let new = registry(vec![
            enum_snap("Old", vec![variant(0, "T", "aaa")], vec![]),
            enum_snap("New", vec![variant(0, "T", "bbb")], vec![]),
        ]);

        let (additions, modifications, removals) = old.diff(&new);
        assert_eq!(additions.len(), 1);
        assert!(additions[0].contains("New enum `New`"));
        assert!(modifications.is_empty());
        assert!(removals.is_empty());
    }

    #[test]
    fn additions_new_variant() {
        let old = registry(vec![enum_snap("E", vec![variant(0, "V0", "aaa")], vec![])]);
        let new = registry(vec![enum_snap(
            "E",
            vec![variant(0, "V0", "aaa"), variant(1, "V1", "bbb")],
            vec![],
        )]);

        let (additions, modifications, removals) = old.diff(&new);
        assert_eq!(additions.len(), 1);
        assert!(additions[0].contains("new variant 1"));
        assert!(modifications.is_empty());
        assert!(removals.is_empty());
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

        let (additions, modifications, removals) = old.diff(&new);
        assert_eq!(additions.len(), 1);
        assert!(additions[0].contains("new upgrade"));
        assert!(modifications.is_empty());
        assert!(removals.is_empty());
    }

    #[test]
    fn additions_none_when_identical() {
        let old = registry(vec![enum_snap("E", vec![variant(0, "V0", "aaa")], vec![])]);
        let new = old.clone();

        let (additions, modifications, removals) = old.diff(&new);
        assert!(additions.is_empty());
        assert!(modifications.is_empty());
        assert!(removals.is_empty());
    }

    // ---- diff: modifications ----

    #[test]
    fn modifications_variant_hash_changed() {
        let old = registry(vec![enum_snap("E", vec![variant(0, "V0", "aaa")], vec![])]);
        let new = registry(vec![enum_snap(
            "E",
            vec![variant(0, "V0", "CHANGED")],
            vec![],
        )]);

        let (additions, modifications, removals) = old.diff(&new);
        assert_eq!(modifications.len(), 1);
        assert!(modifications[0].contains("struct hash changed"));
        assert!(additions.is_empty());
        assert!(removals.is_empty());
    }

    #[test]
    fn modifications_upgrade_hash_changed() {
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

        let (additions, modifications, removals) = old.diff(&new);
        assert_eq!(modifications.len(), 1);
        assert!(modifications[0].contains("body hash changed"));
        assert!(additions.is_empty());
        assert!(removals.is_empty());
    }

    #[test]
    fn modifications_none_when_identical() {
        let old = registry(vec![enum_snap(
            "E",
            vec![variant(0, "V0", "aaa")],
            vec![upgrade("V0", "V1", "uuu")],
        )]);
        let new = old.clone();

        let (_, modifications, _) = old.diff(&new);
        assert!(modifications.is_empty());
    }

    #[test]
    fn modifications_none_when_enum_removed() {
        let old = registry(vec![enum_snap("E", vec![variant(0, "V0", "aaa")], vec![])]);
        let new = registry(vec![]);

        let (_, modifications, _) = old.diff(&new);
        assert!(modifications.is_empty());
    }

    // ---- diff: removals ----

    #[test]
    fn removals_enum_removed() {
        let old = registry(vec![enum_snap("E", vec![variant(0, "V0", "aaa")], vec![])]);
        let new = registry(vec![]);

        let (additions, modifications, removals) = old.diff(&new);
        assert_eq!(removals.len(), 1);
        assert!(removals[0].contains("Enum `E` removed"));
        assert!(additions.is_empty());
        assert!(modifications.is_empty());
    }

    #[test]
    fn removals_variant_removed() {
        let old = registry(vec![enum_snap(
            "E",
            vec![variant(0, "V0", "aaa"), variant(1, "V1", "bbb")],
            vec![],
        )]);
        let new = registry(vec![enum_snap("E", vec![variant(0, "V0", "aaa")], vec![])]);

        let (_, _, removals) = old.diff(&new);
        assert!(
            removals
                .iter()
                .any(|r| r.contains("variant 1") && r.contains("removed"))
        );
    }

    #[test]
    fn removals_upgrade_removed() {
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

        let (_, _, removals) = old.diff(&new);
        assert_eq!(removals.len(), 1);
        assert!(removals[0].contains("upgrade") && removals[0].contains("removed"));
    }

    #[test]
    fn removals_none_when_identical() {
        let old = registry(vec![enum_snap("E", vec![variant(0, "V0", "aaa")], vec![])]);
        let new = old.clone();

        let (_, _, removals) = old.diff(&new);
        assert!(removals.is_empty());
    }

    // ---- build_diff_report ----

    #[test]
    fn report_empty_when_no_changes() {
        assert!(build_diff_report(&[], &[], &[]).is_empty());
    }

    #[test]
    fn report_informational_when_only_additions() {
        let report = build_diff_report(&["new enum".to_string()], &[], &[]);
        assert!(report.contains(":information_source:"));
        assert!(!report.contains(":rotating_light:"));
    }

    #[test]
    fn report_suspicious_when_modifications() {
        let report = build_diff_report(&[], &["hash changed".to_string()], &[]);
        assert!(report.contains(":rotating_light:"));
        assert!(report.contains("suspicious"));
    }

    #[test]
    fn report_suspicious_when_removals() {
        let report = build_diff_report(&[], &[], &["enum removed".to_string()]);
        assert!(report.contains(":rotating_light:"));
        assert!(report.contains(":x: Removals"));
    }

    #[test]
    fn report_suspicious_when_modifications_and_additions() {
        let report = build_diff_report(
            &["new enum".to_string()],
            &["hash changed".to_string()],
            &[],
        );
        assert!(report.contains(":rotating_light:"));
        assert!(report.contains(":heavy_plus_sign: Additions"));
        assert!(report.contains(":warning: Modifications"));
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

        let (additions, modifications, removals) = old.diff(&new);

        assert_eq!(additions.len(), 3); // new enum + new variant + new upgrade
        assert!(modifications.is_empty());
        assert!(removals.is_empty());

        let report = build_diff_report(&additions, &modifications, &removals);
        assert!(report.contains(":information_source:"));
    }

    #[test]
    fn diff_full_flow_suspicious_changes() {
        let old = registry(vec![
            enum_snap(
                "A",
                vec![variant(0, "V0", "aaa"), variant(1, "V1", "bbb")],
                vec![upgrade("V0", "V1", "uuu")],
            ),
            enum_snap("B", vec![variant(0, "T", "ccc")], vec![]),
        ]);
        let new = registry(vec![
            enum_snap(
                "A",
                vec![
                    variant(0, "V0", "aaa"),
                    variant(1, "V1", "bbb"),
                    variant(2, "V2", "ddd"),
                ],
                vec![upgrade("V0", "V1", "CHANGED")],
            ),
            // B removed
        ]);

        let (additions, modifications, removals) = old.diff(&new);

        assert_eq!(additions.len(), 1); // new variant
        assert_eq!(modifications.len(), 1); // upgrade hash changed
        assert_eq!(removals.len(), 1); // enum B removed

        let report = build_diff_report(&additions, &modifications, &removals);
        assert!(report.contains(":rotating_light:"));
        assert!(report.contains(":x: Removals"));
        assert!(report.contains(":warning: Modifications"));
        assert!(report.contains(":heavy_plus_sign: Additions"));
    }
}
