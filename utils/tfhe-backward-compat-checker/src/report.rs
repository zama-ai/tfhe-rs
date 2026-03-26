use crate::diff::DiffEntry;

/// Build a markdown report from diff entries, suitable for posting as a PR comment.
/// Returns an empty string if there are no changes.
pub fn build_diff_report(entries: &[DiffEntry]) -> String {
    if entries.is_empty() {
        return ":white_check_mark: **Backward-compat snapshot: everything looks good! No backward-compatibility issues detected.**".to_string();
    }

    let (errors, warnings, neutral) = DiffEntry::split_by_severity(entries);

    let mut lines = Vec::new();

    if !errors.is_empty() {
        lines.push(":x: **Backward-compat snapshot: breaking changes detected**\n".to_string());
        lines.push(
            "Breaking changes were detected that **will break deserialization** \
             of existing data. This **must be fixed before merging**.\n"
                .to_string(),
        );
    } else if !warnings.is_empty() {
        lines.push(
            ":warning: **Backward-compat snapshot: suspicious changes detected**\n".to_string(),
        );
        lines.push(
            "Suspicious changes were detected that may hide breaking changes. \
             Please review the warnings below carefully.\n"
                .to_string(),
        );
    } else {
        lines.push(
            ":information_source: **Backward-compat snapshot: neutral changes**\n".to_string(),
        );
        lines.push(
            "Only neutral changes were detected. \
             This is expected when introducing new versioned types.\n"
                .to_string(),
        );
    }

    lines.push("---\n".to_string());

    if !errors.is_empty() {
        lines.push("<details>\n<summary>:x: Errors</summary>\n".to_string());
        for e in &errors {
            lines.push(format!("- {e}"));
        }
        lines.push("\n</details>\n".to_string());
    }

    if !warnings.is_empty() {
        lines.push("<details>\n<summary>:warning: Warnings</summary>\n".to_string());
        for w in &warnings {
            lines.push(format!("- {w}"));
        }
        lines.push("\n</details>\n".to_string());
    }

    if !neutral.is_empty() {
        lines.push("<details>\n<summary>:heavy_plus_sign: Neutral</summary>\n".to_string());
        for a in &neutral {
            lines.push(format!("- {a}"));
        }
        lines.push("\n</details>\n".to_string());
    }

    lines.push("---\n".to_string());

    lines.push(
        "If you encounter any errors or have doubts, you can verify locally by running:\n\n\
         ```\n\
         make backward_correctness BASE_REF=<base_branch_or_commit>\n\
         ```\n\n\
         Where `BASE_REF` is the reference branch or commit to check against.\n"
            .to_string(),
    );

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
        let entries = vec![DiffEntry::VersionsDispatchEnumAdded {
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
        let entries = vec![DiffEntry::VersionsDispatchEnumRemoved {
            name: "E".to_string(),
        }];
        let report = build_diff_report(&entries);
        assert!(report.contains(":warning: **"));
        assert!(report.contains("suspicious"));
    }

    #[test]
    fn report_error_when_variant_removed() {
        let entries = vec![DiffEntry::VersionsDispatchVariantRemoved {
            enum_name: "E".to_string(),
            index: 0,
            type_path: "V0".to_string(),
        }];
        let report = build_diff_report(&entries);
        assert!(report.contains(":x: **"));
        assert!(report.contains("breaking changes detected"));
    }

    #[test]
    fn report_error_takes_priority_over_warnings() {
        let entries = vec![
            DiffEntry::VersionsDispatchEnumAdded {
                name: "N".to_string(),
                variant_count: 1,
            },
            DiffEntry::VersionsDispatchEnumRemoved {
                name: "O".to_string(),
            },
            DiffEntry::VersionsDispatchVariantRemoved {
                enum_name: "E".to_string(),
                index: 0,
                type_path: "V0".to_string(),
            },
        ];
        let report = build_diff_report(&entries);
        assert!(report.contains(":x: **"));
        assert!(report.contains(":warning: Warnings"));
        assert!(report.contains(":heavy_plus_sign: Neutral"));
    }

    #[test]
    fn report_contains_separator() {
        let entries = vec![DiffEntry::VersionsDispatchEnumAdded {
            name: "E".to_string(),
            variant_count: 1,
        }];
        let report = build_diff_report(&entries);
        assert!(report.contains("---"));
    }
}
