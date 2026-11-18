//! What a release from the current commit publishes, and what is in its way.
//!
//! A crate is released when its version is not in the registry yet and its release tag points at
//! the commit being released: the tag is what declares it ready, a crate merely bumped on the
//! way to its next release is left alone.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::json;

use super::registry::{CRATES_IO, Registry};
use super::repo::Repo;
use super::status::{CrateReport, Status, crate_reports, release_crates, workspace_packages};
use super::{Result, print_table};

/// What a release does about a crate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// It is published by this release.
    Publish,
    /// Its version is in the registry already.
    Published,
    /// Its version is not in the registry and no tag releases it.
    Untagged,
    /// Its version is not in the registry and the tag releasing it points at another commit.
    Elsewhere,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            State::Publish => "publish",
            State::Published => "published",
            State::Untagged => "untagged",
            State::Elsewhere => "tagged elsewhere",
        }
    }
}

pub struct Planned {
    pub report: CrateReport,
    pub state: State,
}

impl Planned {
    /// The crate with its version, as written in a message.
    pub fn id(&self) -> String {
        format!("{} {}", self.report.name, self.report.version)
    }

    /// File name of the crate once packaged.
    pub fn file_name(&self) -> String {
        format!("{}-{}.crate", self.report.name, self.report.version)
    }
}

/// Names of `crates`, in the same order.
pub fn names<'p>(crates: &[&'p Planned]) -> Vec<&'p str> {
    let names = crates.iter();
    names.map(|planned| planned.report.name.as_str()).collect()
}

pub struct Plan<'a> {
    pub repo: &'a Repo,
    pub registry: &'a Registry,
    /// Tag the release was asked from, if any.
    tag: Option<String>,
    /// Whether every crate that is not published is selected, tagged or not, to check that they
    /// could all be released from the current commit.
    pub rehearsal: bool,
    /// The commit being released.
    pub head: String,
    target_directory: PathBuf,
    /// Every released crate, in the order they have to be published: dependencies first.
    pub crates: Vec<Planned>,
    /// Why this release cannot go ahead.
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl<'a> Plan<'a> {
    pub fn new(
        repo: &'a Repo,
        registry: &'a Registry,
        tag: Option<&str>,
        rehearsal: bool,
        allow_new_crates: bool,
    ) -> Result<Self> {
        let metadata = repo.metadata()?;
        let packages = workspace_packages(&metadata);
        let release = release_crates(&packages, registry);
        let head = repo.head()?;
        let reports = crate_reports(repo, &release, &packages, &release, registry, None)?;
        let crates = reports
            .into_iter()
            .map(|report| {
                let state = if report.is_published {
                    State::Published
                } else if rehearsal || report.tag_commit.as_deref() == Some(&head) {
                    State::Publish
                } else if report.tag_exists {
                    State::Elsewhere
                } else {
                    State::Untagged
                };
                Planned { report, state }
            })
            .collect();
        let mut plan = Self {
            repo,
            registry,
            tag: tag.map(str::to_owned),
            rehearsal,
            head,
            target_directory: metadata.target_directory.into(),
            crates,
            errors: Vec::new(),
            warnings: Vec::new(),
        };
        plan.errors = plan.tag_errors();
        plan.errors.extend(plan.selection_errors(allow_new_crates));
        plan.warnings = plan.selection_warnings();
        Ok(plan)
    }

    /// Crates to publish, in publish order.
    pub fn selected(&self) -> Vec<&Planned> {
        let selected = |planned: &&Planned| planned.state == State::Publish;
        self.crates.iter().filter(selected).collect()
    }

    /// Whether the release tag of the crate points at the commit being released.
    pub fn tagged_here(&self, planned: &Planned) -> bool {
        planned.report.tag_commit.as_deref() == Some(&self.head)
    }

    /// Crates released from this commit, by this run or by an earlier one.
    pub fn released(&self) -> Vec<&Planned> {
        let released =
            |planned: &&Planned| planned.state == State::Publish || self.tagged_here(planned);
        self.crates.iter().filter(released).collect()
    }

    fn by_name(&self) -> BTreeMap<&str, &Planned> {
        let crates = self.crates.iter();
        crates
            .map(|planned| (planned.report.name.as_str(), planned))
            .collect()
    }

    /// Check the release was asked from a tag releasing a crate from this commit.
    fn tag_errors(&self) -> Vec<String> {
        let Some(tag) = &self.tag else {
            return Vec::new();
        };
        let reports = || self.crates.iter().map(|planned| &planned.report);
        let commit = reports()
            .filter(|report| &report.tag == tag)
            .find_map(|report| report.tag_commit.as_deref());
        match commit {
            None => {
                let expected: Vec<&str> = reports().map(|report| report.tag.as_str()).collect();
                vec![format!(
                    "{tag} is not the release tag of a crate at the version this commit \
                    declares, which would be one of: {}",
                    expected.join(", ")
                )]
            }
            Some(commit) if commit != self.head => vec![format!(
                "{tag} points at commit {commit:.9} but {:.9} is checked out",
                self.head
            )],
            Some(_) => Vec::new(),
        }
    }

    fn selection_errors(&self, allow_new_crates: bool) -> Vec<String> {
        let by_name = self.by_name();
        let registry = &self.registry.label;
        let mut errors = Vec::new();
        for planned in self.selected() {
            let report = &planned.report;
            let id = planned.id();
            if report.status == Status::Mismatch {
                errors.push(format!("{id}: {}", report.detail));
            }
            if report.published.is_none() && !allow_new_crates {
                errors.push(format!(
                    "{id} would be the first version of this crate on {registry}: trusted \
                    publishing cannot create a crate, publish this version with an API token \
                    and register the release workflow as its trusted publisher \
                    (--allow-new-crates to go ahead anyway)"
                ));
            }
            // cargo resolves the dependencies of what it publishes from the registry and from
            // the crates published along: one that is in neither fails the run, possibly after
            // some crates were uploaded.
            for name in &report.dependencies {
                let dependency = &by_name[name.as_str()].report;
                let needed = format!("{id} depends on {name} {}, which is", dependency.version);
                match by_name[name.as_str()].state {
                    State::Untagged => errors.push(format!(
                        "{needed} neither on {registry} nor tagged: tag this commit with {} to \
                        release it as well",
                        dependency.tag
                    )),
                    State::Elsewhere => errors.push(format!(
                        "{needed} not on {registry} and tagged on another commit: release it \
                        from {} ({:.9}) first",
                        dependency.tag,
                        dependency.tag_commit.as_deref().unwrap_or_default()
                    )),
                    State::Publish | State::Published => {}
                }
            }
        }
        errors
    }

    /// The crates published here are built against the dependencies that are in the registry:
    /// tell when those are not what the repository holds.
    fn selection_warnings(&self) -> Vec<String> {
        let by_name = self.by_name();
        let mut users: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut changed: Vec<&str> = Vec::new();
        for planned in self.selected() {
            for name in &planned.report.dependencies {
                if by_name[name.as_str()].report.status == Status::Bump {
                    if !changed.contains(&name.as_str()) {
                        changed.push(name);
                    }
                    users.entry(name).or_default().push(&planned.report.name);
                }
            }
        }
        let warning = |name: &&str| {
            let dependency = &by_name[name].report;
            format!(
                "{name} changed since {} without a version bump ({} changed file(s)): {} will \
                be used with the {name} {} that is on {}, not with these changes",
                dependency.baseline_tag.as_deref().unwrap_or("-"),
                dependency.changed_files.len(),
                users[name].join(", "),
                dependency.version,
                self.registry.label
            )
        };
        changed.iter().map(warning).collect()
    }

    /// Where cargo leaves the crate file it packages.
    pub fn crate_file(&self, planned: &Planned) -> PathBuf {
        let packages = self.target_directory.join("package");
        packages.join(planned.file_name())
    }

    /// Where the crate files of a release are gathered by default.
    pub fn default_output_directory(&self) -> PathBuf {
        self.target_directory.join("release-crates")
    }

    /// The cargo command publishing `crates`.
    pub fn cargo_publish(&self, options: &[&str], crates: &[&Planned]) -> Vec<String> {
        let mut command = vec!["cargo", "publish", "--locked"];
        command.extend(options);
        if self.registry.name != CRATES_IO {
            command.extend(["--registry", &self.registry.name]);
        }
        for planned in crates {
            command.extend(["-p", &planned.report.name]);
        }
        command.into_iter().map(str::to_owned).collect()
    }

    fn title(&self) -> String {
        let mut origin = format!("commit {:.9}", self.head);
        if let Some(tag) = &self.tag {
            origin += &format!(" (tag {tag})");
        }
        let registry = &self.registry.label;
        if self.rehearsal {
            format!(
                "Rehearsal of a release to {registry} from {origin}: every crate that is not \
                published yet is selected, tagged or not"
            )
        } else {
            format!("Release to {registry} from {origin}")
        }
    }

    fn table(&self) -> Vec<Vec<String>> {
        let header = [
            "crate",
            "version",
            &self.registry.label,
            "release tag",
            "state",
        ];
        let mut rows = vec![header.map(str::to_owned).to_vec()];
        for planned in &self.crates {
            let report = &planned.report;
            let dash = || "-".to_owned();
            let commit = report.tag_commit.as_deref().unwrap_or_default();
            rows.push(vec![
                report.name.clone(),
                report.version.to_string(),
                report
                    .published
                    .as_ref()
                    .map_or_else(dash, ToString::to_string),
                if report.tag_exists {
                    report.tag.clone()
                } else {
                    dash()
                },
                match planned.state {
                    State::Elsewhere => format!("tagged on {commit:.9}"),
                    state => state.name().to_owned(),
                },
            ]);
        }
        rows
    }

    /// What the release is going to do, in a few lines.
    fn outcome(&self) -> Vec<String> {
        let registry = &self.registry.label;
        let selected = self.selected();
        if selected.is_empty() {
            let tagged_here = |planned: &Planned| self.tagged_here(planned);
            let reason = if self.rehearsal {
                format!("every crate is on {registry} already")
            } else if !self.crates.iter().any(tagged_here) {
                "no release tag points at this commit (--rehearsal selects the crates that are \
                not published yet)"
                    .to_owned()
            } else {
                format!("the crates tagged on this commit are on {registry} already")
            };
            return vec![format!("Nothing to publish: {reason}.")];
        }
        let mut lines = vec![format!("To publish to {registry}, dependencies first:")];
        lines.extend(selected.iter().map(|planned| format!("  {}", planned.id())));
        lines.push("with:".to_owned());
        lines.push(format!(
            "  {}",
            self.cargo_publish(&[], &selected).join(" ")
        ));
        lines
    }

    /// Print the plan, what the release is going to do being left out when `outcome` is not set.
    pub fn print(&self, outcome: bool) {
        println!("{}\n", self.title());
        print_table(&self.table());
        if outcome {
            println!("\n{}", self.outcome().join("\n"));
        }
        for warning in &self.warnings {
            println!("\nwarning: {warning}");
        }
        for error in &self.errors {
            eprintln!("error: {error}");
        }
    }

    pub fn markdown(&self) -> String {
        let table = self.table();
        let row = |cells: &Vec<String>| format!("| {} |", cells.join(" | "));
        let mut lines = vec![format!("### {}", self.title()), String::new()];
        lines.push(row(&table[0]));
        lines.push(format!("|{}", " --- |".repeat(table[0].len())));
        lines.extend(table[1..].iter().map(row));
        lines.extend([String::new(), "```".to_owned()]);
        lines.extend(self.outcome());
        lines.push("```".to_owned());
        let warnings = self.warnings.iter();
        lines.extend(warnings.map(|warning| format!("\n**Warning:** {warning}")));
        let errors = self.errors.iter();
        lines.extend(errors.map(|error| format!("\n**Error:** {error}")));
        lines.join("\n") + "\n"
    }

    pub fn json(&self) -> serde_json::Value {
        let crates: Vec<_> = self
            .crates
            .iter()
            .map(|planned| {
                json!({
                    "crate": planned.report.name,
                    "version": planned.report.version,
                    "tag": planned.report.tag,
                    "state": planned.state.name(),
                })
            })
            .collect();
        let selected = self.selected();
        let command = (!selected.is_empty()).then(|| self.cargo_publish(&[], &selected));
        json!({
            "registry": self.registry.label,
            "commit": self.head,
            "tag": self.tag,
            "rehearsal": self.rehearsal,
            "crates": crates,
            "publish": names(&self.selected()),
            "released": names(&self.released()),
            "command": command,
            "warnings": self.warnings,
            "errors": self.errors,
        })
    }
}
