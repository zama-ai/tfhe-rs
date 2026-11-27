//! The report as a terminal shows it. Everything is returned as lines, an empty one separates
//! two blocks.

use super::status::{Report, Status};
use super::workspace::Workspace;
use std::collections::BTreeSet;

const MERMAID_HEADER: &str = "---
config:
  layout: elk
  elk:
    mergeEdges: true
    nodePlacementStrategy: NETWORK_SIMPLEX
---
flowchart TD";

/// One row per crate, columns aligned.
pub fn table(reports: &[Report]) -> Vec<String> {
    let header = [
        "crate",
        "manifest",
        "crates.io",
        "baseline",
        "changes",
        "status",
    ];
    let mut rows = vec![header.map(str::to_owned)];
    for report in reports {
        let or_dash = |value: &Option<String>| value.clone().unwrap_or_else(|| "-".to_owned());
        let changes = match report.baseline_tag {
            Some(_) => report.changed_files.len().to_string(),
            // Nothing to compare the crate to.
            None => "-".to_owned(),
        };
        rows.push([
            report.name.clone(),
            report.version.clone(),
            or_dash(&report.published),
            or_dash(&report.baseline_tag),
            changes,
            report.status.to_string(),
        ]);
    }

    let widths: [usize; 6] = std::array::from_fn(|column| {
        rows.iter()
            .map(|row| row[column].chars().count())
            .max()
            .unwrap_or(0)
    });
    rows.iter()
        .map(|row| {
            let cells: Vec<String> = row
                .iter()
                .zip(widths)
                .map(|(cell, width)| format!("{cell:<width$}"))
                .collect();
            cells.join("  ").trim_end().to_owned()
        })
        .collect()
}

/// What is left to do for the crates of `reports`.
///
/// A gate only answers its own question: `brief` leaves out the steps of a release.
pub fn actions(reports: &[Report], show_files: bool, brief: bool) -> Vec<String> {
    let having = |status: Status| reports.iter().filter(move |report| report.status == status);
    let mut lines = Vec::new();

    for report in having(Status::Mismatch) {
        lines.push(String::new());
        lines.push(format!("!! {}: {}", report.name, report.detail));
    }

    if having(Status::Bump).next().is_some() {
        lines.push(String::new());
        lines.push("Changed without a version bump:".to_owned());
        for report in having(Status::Bump) {
            lines.push(format!(
                "  {}: {} changed file(s) since {}, bump {}",
                report.name,
                report.changed_files.len(),
                report.baseline_tag.as_deref().unwrap_or("-"),
                report.manifest
            ));
            if show_files {
                for path in &report.changed_files {
                    lines.push(format!("      {path}"));
                }
            }
        }
    }

    if brief {
        return lines;
    }

    if having(Status::Tag).next().is_some() {
        lines.push(String::new());
        lines.push("Bumped but not tagged, create the tags in this order:".to_owned());
        for report in having(Status::Tag) {
            let tag = &report.tag;
            lines.push(format!(
                "  git tag -s -a -m \"{} {} release\" {tag} && git push origin tag {tag}",
                report.name, report.version
            ));
        }
    }

    if having(Status::Publish).next().is_some() {
        lines.push(String::new());
        lines.push("Tagged but not on crates.io, release these in this order:".to_owned());
        for report in having(Status::Publish) {
            lines.push(format!("  {} from tag {}", report.name, report.tag));
        }
    }

    let pending: BTreeSet<&str> = having(Status::Tag)
        .chain(having(Status::Publish))
        .map(|report| report.name.as_str())
        .collect();
    for report in having(Status::Tag).chain(having(Status::Publish)) {
        let blockers: Vec<&str> = report
            .dependencies
            .iter()
            .map(String::as_str)
            .filter(|dependency| pending.contains(dependency))
            .collect();
        if !blockers.is_empty() {
            lines.push(String::new());
            lines.push(format!(
                "Note: publish {} before {}; cargo publish fails on a dependency that is not on \
                crates.io yet.",
                blockers.join(", "),
                report.name
            ));
        }
    }

    if reports.iter().all(|report| report.status == Status::Ok) {
        lines.push(String::new());
        lines.push("Nothing to do: every released crate is up to date on crates.io.".to_owned());
    }
    lines
}

/// Why `report` stops a release made from `tag`.
pub fn not_ready(report: &Report, tag: &str) -> String {
    let why = if report.detail.is_empty() {
        report.status.why_not_ready()
    } else {
        &report.detail
    };
    format!("{} is not ready to release from {tag}: {why}", report.name)
}

/// The dependencies between the released crates as a Mermaid flowchart, a crate below the crates
/// it depends on.
pub fn mermaid(workspace: &Workspace) -> Vec<String> {
    let names: Vec<&str> = workspace.names().collect();
    let node = |name: &str| name.replace('-', "_");

    let mut lines = vec![MERMAID_HEADER.to_owned()];
    for name in workspace.publish_order(&names) {
        lines.push(format!("    {}[\"{name}\"]", node(name)));
    }
    let dependencies = workspace.pruned_dependencies(&names);
    for name in &names {
        for dependency in dependencies.get(name).into_iter().flatten() {
            lines.push(format!("    {} --> {}", node(dependency), node(name)));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::super::testing::krate;
    use super::*;

    fn report(name: &str, version: &str, status: Status) -> Report {
        Report {
            name: name.to_owned(),
            version: version.to_owned(),
            published: Some("1.0.0".to_owned()),
            baseline_tag: Some(format!("{name}-1.0.0")),
            tag: format!("{name}-{version}"),
            tag_exists: status == Status::Publish,
            manifest: format!("{name}/Cargo.toml"),
            changed_files: vec![],
            status,
            detail: String::new(),
            dependencies: vec![],
        }
    }

    #[test]
    fn table_aligns_its_columns() {
        let never_released = Report {
            published: None,
            baseline_tag: None,
            ..report("wasm-par-mq", "0.1.0", Status::Tag)
        };
        let changed = Report {
            changed_files: vec!["a".to_owned(), "b".to_owned()],
            ..report("tfhe", "1.0.0", Status::Bump)
        };

        assert_eq!(
            table(&[never_released, changed]),
            [
                "crate        manifest  crates.io  baseline    changes  status",
                "wasm-par-mq  0.1.0     -          -           -        TAG",
                "tfhe         1.0.0     1.0.0      tfhe-1.0.0  2        BUMP",
            ]
        );
    }

    #[test]
    fn table_of_nothing_is_its_header() {
        assert_eq!(
            table(&[]),
            ["crate  manifest  crates.io  baseline  changes  status"]
        );
    }

    #[test]
    fn everything_released_is_said() {
        let reports = [report("tfhe", "1.0.0", Status::Ok)];

        assert_eq!(
            actions(&reports, false, false),
            [
                "",
                "Nothing to do: every released crate is up to date on crates.io."
            ]
        );
        // Not the question a gate asks.
        assert!(actions(&reports, false, true).is_empty());
    }

    #[test]
    fn missing_bumps_are_listed_with_their_files_on_demand() {
        let reports = [Report {
            changed_files: vec!["tfhe/src/lib.rs".to_owned(), "tfhe/build.rs".to_owned()],
            ..report("tfhe", "1.0.0", Status::Bump)
        }];

        assert_eq!(
            actions(&reports, false, true),
            [
                "",
                "Changed without a version bump:",
                "  tfhe: 2 changed file(s) since tfhe-1.0.0, bump tfhe/Cargo.toml",
            ]
        );
        assert_eq!(
            actions(&reports, true, false),
            [
                "",
                "Changed without a version bump:",
                "  tfhe: 2 changed file(s) since tfhe-1.0.0, bump tfhe/Cargo.toml",
                "      tfhe/src/lib.rs",
                "      tfhe/build.rs",
            ]
        );
    }

    #[test]
    fn release_steps_come_in_order_with_what_blocks_them() {
        let reports = [
            report("tfhe-csprng", "1.1.0", Status::Tag),
            report("tfhe-fft", "1.1.0", Status::Publish),
            Report {
                detail: "HEAD declares version 1.0.0, commit the bump before tagging".to_owned(),
                ..report("tfhe-ntt", "1.1.0", Status::Mismatch)
            },
            Report {
                dependencies: vec![
                    "tfhe-csprng".to_owned(),
                    "tfhe-fft".to_owned(),
                    "tfhe-ntt".to_owned(),
                ],
                ..report("tfhe", "1.1.0", Status::Tag)
            },
        ];

        assert_eq!(
            actions(&reports, false, false),
            [
                "",
                "!! tfhe-ntt: HEAD declares version 1.0.0, commit the bump before tagging",
                "",
                "Bumped but not tagged, create the tags in this order:",
                "  git tag -s -a -m \"tfhe-csprng 1.1.0 release\" tfhe-csprng-1.1.0 \
                && git push origin tag tfhe-csprng-1.1.0",
                "  git tag -s -a -m \"tfhe 1.1.0 release\" tfhe-1.1.0 \
                && git push origin tag tfhe-1.1.0",
                "",
                "Tagged but not on crates.io, release these in this order:",
                "  tfhe-fft from tag tfhe-fft-1.1.0",
                "",
                "Note: publish tfhe-csprng, tfhe-fft before tfhe; cargo publish fails on a \
                dependency that is not on crates.io yet.",
            ]
        );
        // A gate is only told what stops it.
        assert_eq!(
            actions(&reports, false, true),
            [
                "",
                "!! tfhe-ntt: HEAD declares version 1.0.0, commit the bump before tagging",
            ]
        );
    }

    #[test]
    fn not_ready_says_why() {
        let tag = "tfhe-rs-1.1.0";
        assert_eq!(
            not_ready(&report("tfhe", "1.1.0", Status::Tag), tag),
            "tfhe is not ready to release from tfhe-rs-1.1.0: no tag names this version"
        );
        assert_eq!(
            not_ready(&report("tfhe", "1.1.0", Status::Ok), tag),
            "tfhe is not ready to release from tfhe-rs-1.1.0: this version is already on crates.io"
        );
        assert_eq!(
            not_ready(&report("tfhe", "1.1.0", Status::Bump), tag),
            "tfhe is not ready to release from tfhe-rs-1.1.0: this version is already on \
            crates.io and the crate changed since"
        );
        let mismatch = Report {
            detail: "manifest version is behind crates.io (1.1.1)".to_owned(),
            ..report("tfhe", "1.1.0", Status::Mismatch)
        };
        assert_eq!(
            not_ready(&mismatch, tag),
            "tfhe is not ready to release from tfhe-rs-1.1.0: manifest version is behind \
            crates.io (1.1.1)"
        );
    }

    #[test]
    fn mermaid_draws_the_pruned_dependencies() {
        let workspace = Workspace::new(
            "/repo",
            [
                krate("tfhe", "1.0.0", &["tfhe-csprng", "tfhe-versionable"]),
                krate("tfhe-csprng", "1.0.0", &["tfhe-versionable"]),
                krate("tfhe-versionable", "1.0.0", &[]),
            ],
        );

        assert_eq!(
            mermaid(&workspace),
            [
                MERMAID_HEADER,
                "    tfhe_versionable[\"tfhe-versionable\"]",
                "    tfhe_csprng[\"tfhe-csprng\"]",
                "    tfhe[\"tfhe\"]",
                "    tfhe_csprng --> tfhe",
                "    tfhe_versionable --> tfhe_csprng",
            ]
        );
    }
}
