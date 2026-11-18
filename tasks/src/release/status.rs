//! Report the release status of every crate published from this repository.
//!
//! Answers the two questions asked before each release:
//!   - which crates changed since their last release and need a version bump?
//!   - which crates are bumped in Cargo.toml but not published yet?

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use cargo_metadata::semver::Version;
use cargo_metadata::{DependencyKind, Metadata, Package};
use clap::Args;
use serde::Serialize;

use super::registry::{Published, Registry};
use super::repo::Repo;
use super::{Failure, Result, Target, print_table};

const MERMAID_HEADER: &str = "---
config:
  layout: elk
  elk:
    mergeEdges: true
    nodePlacementStrategy: NETWORK_SIMPLEX
---
flowchart TD";

/// Packages of the workspace, by name.
pub type Packages = BTreeMap<String, Package>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    /// The version of the manifest is published and the crate did not change since.
    Ok,
    /// The version of the manifest is published but the crate changed since.
    Bump,
    /// The version of the manifest is not published, and no tag names it.
    Tag,
    /// The version of the manifest is tagged but not published.
    Publish,
    /// The manifest, the tags and the registry do not agree, see the detail.
    Mismatch,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Status::Ok => "OK",
            Status::Bump => "BUMP",
            Status::Tag => "TAG",
            Status::Publish => "PUBLISH",
            Status::Mismatch => "MISMATCH",
        })
    }
}

/// Where a crate stands.
#[derive(Debug, Serialize)]
pub struct CrateReport {
    #[serde(rename = "crate")]
    pub name: String,
    /// Version declared by the manifest.
    pub version: Version,
    /// Latest version in the registry.
    pub published: Option<Version>,
    /// Whether the version of the manifest is in the registry.
    pub is_published: bool,
    /// Of the crate file the registry holds for this version, if any.
    pub checksum: Option<String>,
    /// Release the crate is compared with to tell whether it changed.
    pub baseline_tag: Option<String>,
    /// Tag releasing the version of the manifest.
    pub tag: String,
    pub tag_exists: bool,
    pub tag_commit: Option<String>,
    pub manifest: String,
    pub changed_files: Vec<String>,
    pub status: Status,
    pub detail: String,
    /// Released crates this one depends on.
    pub dependencies: Vec<String>,
}

/// Release tags are named `<package name>-<version>`, except for the main crate.
fn tag_prefix(name: &str) -> &str {
    if name == "tfhe" { "tfhe-rs" } else { name }
}

pub fn workspace_packages(metadata: &Metadata) -> Packages {
    let packages = metadata.packages.iter();
    packages
        .map(|package| (package.name.to_string(), package.clone()))
        .collect()
}

/// Crates this repo releases: every package cargo may publish to `registry`.
pub fn release_crates(packages: &Packages, registry: &Registry) -> Vec<String> {
    let publishable = packages.iter().filter(|(_, package)| {
        // No list of registries means any of them, an empty one means none.
        let allowed = package.publish.as_ref();
        allowed.is_none_or(|registries| registries.contains(&registry.name))
    });
    publishable.map(|(name, _)| name.clone()).collect()
}

/// Crates of `names` that `package` depends on, dev-dependencies excluded.
fn release_dependencies(package: &Package, names: &[String]) -> Vec<String> {
    let dependencies: BTreeSet<&String> = package
        .dependencies
        .iter()
        .filter(|dependency| dependency.kind != DependencyKind::Development)
        .map(|dependency| &dependency.name)
        .filter(|name| names.contains(name))
        .collect();
    dependencies.into_iter().cloned().collect()
}

/// Crate names sorted so that a crate comes after the crates it depends on.
fn publish_order(names: &[String], packages: &Packages) -> Vec<String> {
    let requirements: BTreeMap<&String, Vec<String>> = names
        .iter()
        .map(|name| (name, release_dependencies(&packages[name], names)))
        .collect();
    let mut ordered: Vec<String> = Vec::new();
    while ordered.len() < names.len() {
        let left = || names.iter().filter(|name| !ordered.contains(name));
        let mut ready: Vec<String> = left()
            .filter(|name| requirements[name].iter().all(|need| ordered.contains(need)))
            .cloned()
            .collect();
        if ready.is_empty() {
            // A dependency cycle: there is no right order.
            ready = left().cloned().collect();
        }
        ready.sort();
        ordered.extend(ready);
    }
    ordered
}

/// Manifest contents that a consumer of the published crate can observe.
///
/// dev-dependencies only build this repo's own tests and benches, so changing them is not a
/// reason to release a new version.
fn strip_not_consumer_facing_keys(mut manifest: toml::Table) -> toml::Table {
    manifest.remove("dev-dependencies");
    if let Some(toml::Value::Table(targets)) = manifest.get_mut("target") {
        for (_, target) in targets.iter_mut() {
            if let toml::Value::Table(target) = target {
                target.remove("dev-dependencies");
            }
        }
    }
    manifest
}

/// Commit this branch was cut from, be it main or a release branch.
fn fork_point(repo: &Repo) -> Result<String> {
    if repo
        .git(&["rev-parse", "HEAD^@"])?
        .split_whitespace()
        .count()
        > 1
    {
        // A merge carries the merged branch's commits, which are not this branch's work.
        return Err(Failure::new(
            "HEAD is a merge commit, pass a base: --pr-gate HEAD^1 in CI",
        ));
    }
    let own = repo.git(&[
        "rev-list",
        "HEAD",
        "--not",
        "--glob=refs/remotes/origin/release/",
        "origin/main",
    ])?;
    match own.lines().last() {
        Some(first) => Ok(format!("{first}^")),
        None => Err(Failure::new(
            "HEAD has no commits of its own, there is nothing to gate.",
        )),
    }
}

/// Where crate `package` stands, given the commit of each tag of the repository and the versions
/// of the crate published to `registry`.
fn crate_status(
    repo: &Repo,
    package: &Package,
    tags: &BTreeMap<String, String>,
    published: &Published,
    registry: &Registry,
    base: Option<&str>,
) -> Result<CrateReport> {
    let name = package.name.to_string();
    let version = &package.version;
    let manifest = package
        .manifest_path
        .strip_prefix(&repo.root)
        .map_err(|_| {
            Failure::new(format!(
                "{} is not in the repository",
                package.manifest_path
            ))
        })?;
    let directory = manifest.parent().map_or("", |directory| directory.as_str());
    let directory = if directory.is_empty() { "." } else { directory };
    let manifest = manifest.to_string();
    let prefix = tag_prefix(&name);

    let mut own_tags: Vec<Version> = tags
        .keys()
        .filter_map(|tag| tag.strip_prefix(prefix)?.strip_prefix('-'))
        .filter_map(|version| Version::parse(version).ok())
        .collect();
    own_tags.sort();
    // The baseline is the newest release that is not newer than the manifest, so that a release
    // branch compares against its own last dot release rather than against a later release made
    // on main. Tags are not filtered by reachability because squash-merging leaves release tags
    // off the branch they landed on. `base` overrides all of this for the pull request gate.
    let released = own_tags.iter().rfind(|tagged| *tagged <= version);
    let baseline = match base {
        Some(base) => Some(base.to_owned()),
        None => released.map(|released| format!("{prefix}-{released}")),
    };
    let tag = format!("{prefix}-{version}");
    let tag_exists = own_tags.contains(version);

    let mut changed: Vec<String> = match &baseline {
        Some(baseline) => {
            let range = format!("{baseline}..HEAD");
            let diff = repo.git(&["diff", "--name-only", &range, "--", directory])?;
            diff.lines().map(str::to_owned).collect()
        }
        None => Vec::new(),
    };
    if let Some(baseline) = &baseline
        && changed.contains(&manifest)
        && strip_not_consumer_facing_keys(repo.manifest_at(baseline, &manifest)?)
            == strip_not_consumer_facing_keys(repo.manifest_at("HEAD", &manifest)?)
    {
        changed.retain(|path| path != &manifest);
    }
    let latest = published.keys().next_back();
    // A release branch legitimately sits below the latest version published from main, so only
    // a release on the manifest's own line, its major and minor, means it is stale.
    let same_line = |other: &&Version| (other.major, other.minor) == (version.major, version.minor);
    let line_latest = published.keys().rfind(same_line);

    let mut detail = String::new();
    let status = if base.is_some() && changed.is_empty() {
        // A crate the pull request does not touch is never its problem.
        Status::Ok
    } else if published.contains_key(version) {
        if changed.is_empty() {
            Status::Ok
        } else {
            Status::Bump
        }
    } else if let Some(line_latest) = line_latest.filter(|line_latest| version < *line_latest) {
        detail = format!(
            "manifest version is behind {} ({line_latest})",
            registry.label
        );
        Status::Mismatch
    } else if tag_exists {
        let at_tag = repo.version_at(&tag, &manifest)?;
        if at_tag == version.to_string() {
            Status::Publish
        } else {
            detail = format!("tag {tag} points at a commit declaring version {at_tag}");
            Status::Mismatch
        }
    } else {
        // The version is read from the working tree but the tag would land on HEAD, so an
        // uncommitted bump would tag the version it replaces.
        let at_head = repo.version_at("HEAD", &manifest)?;
        if at_head == version.to_string() {
            Status::Tag
        } else {
            detail = format!("HEAD declares version {at_head}, commit the bump before tagging");
            Status::Mismatch
        }
    };

    Ok(CrateReport {
        version: version.clone(),
        published: latest.cloned(),
        is_published: published.contains_key(version),
        checksum: published.get(version).cloned(),
        baseline_tag: baseline,
        tag_commit: tags.get(&tag).filter(|_| tag_exists).cloned(),
        tag,
        tag_exists,
        manifest,
        changed_files: changed,
        status,
        detail,
        dependencies: Vec::new(),
        name,
    })
}

/// Status of each crate of `names`, in the order they have to be published.
pub fn crate_reports(
    repo: &Repo,
    names: &[String],
    packages: &Packages,
    release: &[String],
    registry: &Registry,
    base: Option<&str>,
) -> Result<Vec<CrateReport>> {
    let tags = repo.tag_commits()?;
    let published = registry.fetch_published(names).map_err(|error| {
        Failure::unreachable(format!("could not reach {}: {error}", registry.index))
    })?;
    let mut reports = Vec::new();
    for name in publish_order(names, packages) {
        let package = &packages[&name];
        let mut report = crate_status(repo, package, &tags, &published[&name], registry, base)?;
        report.dependencies = release_dependencies(package, release);
        reports.push(report);
    }
    Ok(reports)
}

fn print_reports(reports: &[CrateReport], registry: &Registry) {
    let header = [
        "crate",
        "manifest",
        &registry.label,
        "baseline",
        "changes",
        "status",
    ];
    let mut rows = vec![header.map(str::to_owned).to_vec()];
    for report in reports {
        let dash = || "-".to_owned();
        rows.push(vec![
            report.name.clone(),
            report.version.to_string(),
            report
                .published
                .as_ref()
                .map_or_else(dash, Version::to_string),
            report.baseline_tag.clone().unwrap_or_else(dash),
            match report.baseline_tag {
                Some(_) => report.changed_files.len().to_string(),
                None => dash(),
            },
            report.status.to_string(),
        ]);
    }
    print_table(&rows);
}

fn print_actions(reports: &[CrateReport], registry: &Registry, show_files: bool, brief: bool) {
    let with = |status| reports.iter().filter(move |report| report.status == status);

    for report in with(Status::Mismatch) {
        println!("\n!! {}: {}", report.name, report.detail);
    }

    if with(Status::Bump).next().is_some() {
        println!("\nChanged without a version bump:");
        for report in with(Status::Bump) {
            println!(
                "  {}: {} changed file(s) since {}, bump {}",
                report.name,
                report.changed_files.len(),
                report.baseline_tag.as_deref().unwrap_or("-"),
                report.manifest
            );
            if show_files {
                for path in &report.changed_files {
                    println!("      {path}");
                }
            }
        }
    }

    if brief {
        return;
    }

    if with(Status::Tag).next().is_some() {
        println!("\nBumped but not tagged, tag the commit they are released from:");
        for report in with(Status::Tag) {
            println!(
                "  git tag -s -a -m \"{} {} release\" {tag} && git push origin tag {tag}",
                report.name,
                report.version,
                tag = report.tag
            );
        }
    }

    if with(Status::Publish).next().is_some() {
        println!("\nTagged but not on {}:", registry.label);
        for report in with(Status::Publish) {
            let commit = report.tag_commit.as_deref().unwrap_or_default();
            println!(
                "  {} {}, tag {} on commit {:.9}",
                report.name, report.version, report.tag, commit
            );
        }
        // A single run publishes the crates tagged on a commit, in dependency order: there is
        // no order to follow by hand.
        println!(
            "Run the make_release_tfhe workflow from one of the tags of a commit to release \
            every crate tagged on it,\n`make release_plan TAG=<tag>` shows what that run would \
            publish."
        );
    }

    if reports.iter().all(|report| report.status == Status::Ok) {
        println!(
            "\nNothing to do: every released crate is up to date on {}.",
            registry.label
        );
    }
}

/// Dependency edges with the transitive ones removed, keeping the graph readable.
///
/// An edge is kept only when the dependency cannot already be reached through another
/// dependency, so `tfhe -> tfhe-versionable` is dropped in favour of
/// `tfhe -> tfhe-zk-pok -> tfhe-safe-serialize -> tfhe-versionable`.
fn pruned_dependencies(names: &[String], packages: &Packages) -> BTreeMap<String, Vec<String>> {
    let mut closure: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut kept = BTreeMap::new();
    // publish order guarantees that a crate is visited after its dependencies.
    for name in publish_order(names, packages) {
        let direct = release_dependencies(&packages[&name], names);
        let indirect: BTreeSet<String> = direct
            .iter()
            .flat_map(|dependency| closure[dependency].iter().cloned())
            .collect();
        let needed = |dependency: &&String| !indirect.contains(*dependency);
        kept.insert(
            name.clone(),
            direct.iter().filter(needed).cloned().collect(),
        );
        closure.insert(name, direct.into_iter().chain(indirect).collect());
    }
    kept
}

fn print_mermaid(names: &[String], packages: &Packages) {
    println!("{MERMAID_HEADER}");
    let edges = pruned_dependencies(names, packages);
    let node = |name: &str| name.replace('-', "_");
    for name in publish_order(names, packages) {
        println!("    {}[\"{name}\"]", node(&name));
    }
    for name in names {
        for dependency in &edges[name] {
            println!("    {} --> {}", node(dependency), node(name));
        }
    }
}

#[derive(Args)]
pub struct StatusArgs {
    /// Only report these crates
    #[arg(long, num_args = 1.., value_name = "CRATE")]
    crates: Vec<String>,

    /// List the changed files
    #[arg(long)]
    files: bool,

    /// Print a JSON report
    #[arg(long)]
    json: bool,

    /// Print the release dependency graph
    #[arg(long)]
    mermaid: bool,

    /// Gate a pull request: judge only what changed since REF, defaulting to the branch's fork
    /// point, and exit with 1 on a missing bump
    #[arg(long, value_name = "REF", num_args = 0..=1, default_missing_value = "")]
    pr_gate: Option<String>,

    #[command(flatten)]
    target: Target,
}

/// Show which released crates need a version bump, a tag or a publication.
pub fn release_status(args: &StatusArgs) -> Result<i32> {
    let (repo, registry) = args.target.open()?;
    let packages = workspace_packages(&repo.metadata()?);
    let release = release_crates(&packages, &registry);
    let unknown: Vec<&str> = args
        .crates
        .iter()
        .filter(|name| !release.contains(name))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        let unknown = unknown.join(", ");
        return Err(Failure::new(format!(
            "not released from this repo: {unknown}"
        )));
    }
    let names: Vec<String> = release
        .iter()
        .filter(|name| args.crates.is_empty() || args.crates.contains(name))
        .cloned()
        .collect();

    if args.mermaid {
        print_mermaid(&release, &packages);
        return Ok(0);
    }

    let base = match args.pr_gate.as_deref() {
        Some("") => Some(fork_point(&repo)?),
        base => base.map(str::to_owned),
    };
    let gate = base.is_some();
    let reports = crate_reports(
        &repo,
        &names,
        &packages,
        &release,
        &registry,
        base.as_deref(),
    )?;

    // TAG means the bump was made, which is what the gate asked for. Whether a crate is ready
    // to be released is for the release plan to tell.
    let rejected =
        |report: &CrateReport| gate && matches!(report.status, Status::Bump | Status::Mismatch);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    } else {
        print_reports(&reports, &registry);
        print_actions(&reports, &registry, args.files, gate);
    }

    Ok(reports.iter().any(rejected).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(manifest: &str) -> toml::Table {
        toml::from_str(manifest).unwrap()
    }

    #[test]
    fn dev_dependencies_are_not_consumer_facing() {
        let before = table(
            r#"
            [package]
            name = "crate"
            [dependencies]
            serde = "1"
            [dev-dependencies]
            rand = "0.8"
            [target.'cfg(unix)'.dev-dependencies]
            libc = "0.2"
            "#,
        );
        let after = table(
            r#"
            [package]
            name = "crate"
            [dependencies]
            serde = "1"
            [dev-dependencies]
            rand = "0.9"
            [target.'cfg(unix)'.dev-dependencies]
            libc = "0.3"
            "#,
        );
        assert_ne!(before, after);
        assert_eq!(
            strip_not_consumer_facing_keys(before.clone()),
            strip_not_consumer_facing_keys(after)
        );

        let other = table(
            r#"
            [package]
            name = "crate"
            [dependencies]
            serde = "2"
            "#,
        );
        assert_ne!(
            strip_not_consumer_facing_keys(before),
            strip_not_consumer_facing_keys(other)
        );
    }

    #[test]
    fn the_main_crate_has_its_own_tag_prefix() {
        assert_eq!(tag_prefix("tfhe"), "tfhe-rs");
        assert_eq!(tag_prefix("tfhe-fft"), "tfhe-fft");
    }
}
