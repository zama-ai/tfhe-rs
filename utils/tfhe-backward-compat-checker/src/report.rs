use crate::diff::DiffEntry;

const LINES: &str = "---\n";

pub fn build_diff_report(entries: &[DiffEntry]) -> String {
    if entries.is_empty() {
        return String::new();
    }

    let (errors, warnings, additions) = DiffEntry::split_by_severity(entries);

    let mut lines = Vec::new();

    if !errors.is_empty() {
        lines.push(":x: **Backward-compat snapshot: breaking changes detected**\n".to_string());
        lines.push(
            "Variant removals were detected. This **will break deserialization** \
             of existing data and must be fixed before merging.\n"
                .to_string(),
        );
    } else if !warnings.is_empty() {
        lines.push(
            ":warning: **Backward-compat snapshot: suspicious changes detected**\n".to_string(),
        );
        lines.push(
            "Upgrades or struct definitions were modified or removed. \
             This may hide breaking changes — please review carefully.\n"
                .to_string(),
        );
    } else {
        lines.push(
            ":information_source: **Backward-compat snapshot: new types added**\n".to_string(),
        );
        lines.push(
            "Only new types/variants/upgrades were added. \
             This is expected when introducing new versioned types.\n"
                .to_string(),
        );
    }

    lines.push(LINES.to_string());

    if !errors.is_empty() {
        lines.push("<details>\n<summary>:x: Errors (variant removals)</summary>\n".to_string());
        for e in &errors {
            lines.push(format!("- {e}"));
        }
        lines.push("\n</details>\n".to_string());
    }

    if !warnings.is_empty() {
        lines.push(
            "<details>\n<summary>:warning: Warnings (upgrade/struct modifications, enum removals)</summary>\n"
                .to_string(),
        );
        for w in &warnings {
            lines.push(format!("- {w}"));
        }
        lines.push("\n</details>\n".to_string());
    }

    if !additions.is_empty() {
        lines.push("<details>\n<summary>:heavy_plus_sign: Additions</summary>\n".to_string());
        for a in &additions {
            lines.push(format!("- {a}"));
        }
        lines.push("\n</details>\n".to_string());
    }

    lines.push(LINES.to_string());

    // Severity reference
    lines.push("<details>\n<summary>Severity reference</summary>\n".to_string());
    lines.push("| Change | Severity |".to_string());
    lines.push("|--------|----------|".to_string());
    lines.push("| New enum/variant/upgrade | :heavy_check_mark: OK |".to_string());
    lines.push("| Modified/removed upgrade | :warning: Warning |".to_string());
    lines.push("| Modified struct hash | :warning: Warning |".to_string());
    lines.push("| Removed enum | :warning: Warning |".to_string());
    lines.push("| Removed variant | :x: Error |".to_string());
    lines.push("\n</details>".to_string());

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_empty_when_no_changes() {
        assert!(build_diff_report(&[]).is_empty());
    }

    #[test]
    fn report_informational_when_only_additions() {
        let entries = vec![DiffEntry::EnumAdded {
            name: "E".to_string(),
            variant_count: 1,
        }];
        let report = build_diff_report(&entries);
        assert!(report.contains(":information_source:"));
        assert!(!report.contains(":x: **"));
        assert!(!report.contains(":warning: **"));
    }

    #[test]
    fn report_warning_when_warnings() {
        let entries = vec![DiffEntry::EnumRemoved {
            name: "E".to_string(),
        }];
        let report = build_diff_report(&entries);
        assert!(report.contains(":warning: **"));
        assert!(report.contains("suspicious"));
    }

    #[test]
    fn report_error_when_variant_removed() {
        let entries = vec![DiffEntry::VariantRemoved {
            enum_name: "E".to_string(),
            index: 0,
            type_path: "V0".to_string(),
        }];
        let report = build_diff_report(&entries);
        assert!(report.contains(":x: **"));
        assert!(report.contains("breaking changes"));
    }

    #[test]
    fn report_error_takes_priority_over_warnings() {
        let entries = vec![
            DiffEntry::EnumAdded {
                name: "N".to_string(),
                variant_count: 1,
            },
            DiffEntry::EnumRemoved {
                name: "O".to_string(),
            },
            DiffEntry::VariantRemoved {
                enum_name: "E".to_string(),
                index: 0,
                type_path: "V0".to_string(),
            },
        ];
        let report = build_diff_report(&entries);
        assert!(report.contains(":x: **"));
        assert!(report.contains(":warning: Warnings"));
        assert!(report.contains(":heavy_plus_sign: Additions"));
    }

    #[test]
    fn report_contains_severity_reference() {
        let entries = vec![DiffEntry::EnumAdded {
            name: "E".to_string(),
            variant_count: 1,
        }];
        let report = build_diff_report(&entries);
        assert!(report.contains("Severity reference"));
        assert!(report.contains("Removed variant"));
    }
}
