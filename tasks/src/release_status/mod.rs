//! Report the release status of every crate published from this repository.
//!
//! Answers the two questions asked before each release:
//!   - which crates changed since their last release and need a version bump?
//!   - which crates are bumped in Cargo.toml but not published on crates.io yet?
//!
//! Everything is derived, nothing is hand-maintained: the crate list, versions and the dependency
//! graph come from `cargo metadata`, releases from the git tags, published versions from the
//! crates.io index.

mod crate_registry;
mod git;
mod render;
mod status;
#[cfg(test)]
mod testing;
mod workspace;

use crate::utils::project_root;
use cargo_metadata::semver::Version;
use crate_registry::{CrateRegistry, CratesIo};
use git::{Git, Vcs};
use status::{Report, Status, crate_status};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Write;
use workspace::{ReleaseCrate, Workspace};

/// Release tags are named `<package name>-<version>`, except for the main crate.
const TAG_PREFIXES: [(&str, &str); 1] = [("tfhe", "tfhe-rs")];

/// Crates released by a single workflow dispatch, hence from one of their tags.
const SHARED_TAGS: [&[&str]; 1] = [&["tfhe-versionable", "tfhe-versionable-derive"]];

#[derive(clap::Args, Debug, Default)]
pub struct Args {
    /// Only report these crates
    #[arg(long, value_name = "CRATE", num_args = 1..)]
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

    /// Gate a release: exit with 1 unless the selected crates are ready to be released from TAG
    #[arg(long, value_name = "TAG")]
    release_gate: Option<String>,

    /// Gate a pull request: judge only what changed since REF, defaulting to the branch's fork
    /// point, and exit with 1 on a missing bump
    #[arg(long, value_name = "REF", num_args = 0..=1, default_missing_value = "")]
    pr_gate: Option<String>,
}

/// Why no verdict could be given.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The command line asks for something that cannot be done.
    Usage(String),
    /// crates.io could not be asked for the published versions.
    Registry(String),
    /// Git or cargo failed, or the repository is not in a state that can be judged.
    Fatal(String),
}

impl Error {
    fn exit_code(&self) -> i32 {
        match self {
            // As a gate that says no: either way the answer is not a yes.
            Error::Fatal(_) => 1,
            Error::Usage(_) | Error::Registry(_) => 2,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usage(message) | Error::Registry(message) | Error::Fatal(message) => {
                f.write_str(message)
            }
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Fatal(format!("could not print the report: {error}"))
    }
}

/// The question a run answers, each gate accepts the statuses answering its own with a yes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gate {
    /// Only report.
    None,
    /// Did the pull request bump what it changed?
    PullRequest,
    /// Can the crate be released from this tag?
    Release,
}

impl Gate {
    fn of(args: &Args) -> Self {
        if args.release_gate.is_some() {
            Gate::Release
        } else if args.pr_gate.is_some() {
            Gate::PullRequest
        } else {
            Gate::None
        }
    }

    fn accepts(self, status: Status) -> bool {
        match self {
            Gate::None => true,
            // TAG means the bump was made, which is what the gate asked for.
            Gate::PullRequest => matches!(status, Status::Ok | Status::Tag | Status::Publish),
            // A crate ready to release is tagged at a version crates.io does not have yet.
            Gate::Release => status == Status::Publish,
        }
    }
}

/// Whether every selected crate passed the gate.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Accepted,
    Rejected,
}

/// Run the command on this repository, return the exit code of the process: 0 unless a gate
/// rejects a crate (1) or no verdict can be given (1 or 2, see [`Error`]).
pub fn run(args: &Args) -> i32 {
    let verdict = Workspace::load(&project_root()).and_then(|workspace| {
        let git = Git::new(&workspace.root);
        execute(
            args,
            &workspace,
            &git,
            &CratesIo,
            &mut std::io::stdout().lock(),
        )
    });
    match verdict {
        Ok(Verdict::Accepted) => 0,
        Ok(Verdict::Rejected) => 1,
        Err(error) => {
            eprintln!("{error}");
            error.exit_code()
        }
    }
}

fn execute(
    args: &Args,
    workspace: &Workspace,
    vcs: &dyn Vcs,
    registry: &dyn CrateRegistry,
    out: &mut dyn Write,
) -> Result<Verdict, Error> {
    let unknown: BTreeSet<&str> = args
        .crates
        .iter()
        .map(String::as_str)
        .filter(|name| workspace.get(name).is_none())
        .collect();
    if !unknown.is_empty() {
        return Err(Error::Usage(format!(
            "not released from this repo: {}",
            Vec::from_iter(unknown).join(", ")
        )));
    }
    let names: Vec<&str> = workspace
        .names()
        .filter(|name| {
            args.crates.is_empty() || args.crates.iter().any(|selected| selected == name)
        })
        .collect();

    if args.mermaid {
        for line in render::mermaid(workspace) {
            writeln!(out, "{line}")?;
        }
        return Ok(Verdict::Accepted);
    }

    if let Some(tag) = &args.release_gate {
        if tag.is_empty() {
            // Not a silent pass: a gate that is not told its tag has nothing to check.
            return Err(Error::Usage(
                "--release-gate needs the tag the release is made from, got an empty one"
                    .to_owned(),
            ));
        }
        // Offline, so a tag naming the wrong crate fails before any crates.io call.
        for name in &names {
            let krate = released(workspace, name)?;
            writeln!(out, "{}", check_release_tag(tag, krate)?)?;
        }
    }

    let tags = vcs.tags()?;
    let base = match args.pr_gate.as_deref() {
        None => None,
        Some("") => Some(vcs.fork_point()?),
        Some(base) if base.starts_with('-') => {
            // Git would take it for one of its options.
            return Err(Error::Usage(format!(
                "--pr-gate: `{base}` is not a git revision"
            )));
        }
        Some(base) => Some(base.to_owned()),
    };

    let published = published_versions(registry, &names)?;

    let mut reports = Vec::with_capacity(names.len());
    for name in workspace.publish_order(&names) {
        let versions = published.get(name).map(Vec::as_slice).unwrap_or_default();
        reports.push(crate_status(
            released(workspace, name)?,
            &tags,
            versions,
            base.as_deref(),
            vcs,
        )?);
    }

    let gate = Gate::of(args);
    let rejected: Vec<&Report> = reports
        .iter()
        .filter(|report| !gate.accepts(report.status))
        .collect();

    if args.json {
        let json = serde_json::to_string_pretty(&reports)
            .map_err(|error| Error::Fatal(format!("could not print the report: {error}")))?;
        writeln!(out, "{json}")?;
    } else {
        for line in render::table(&reports) {
            writeln!(out, "{line}")?;
        }
        for line in render::actions(&reports, args.files, gate != Gate::None) {
            writeln!(out, "{line}")?;
        }
        if let Some(tag) = &args.release_gate {
            for report in &rejected {
                writeln!(out, "\n{}", render::not_ready(report, tag))?;
            }
        }
    }

    Ok(if rejected.is_empty() {
        Verdict::Accepted
    } else {
        Verdict::Rejected
    })
}

fn released<'a>(workspace: &'a Workspace, name: &str) -> Result<&'a ReleaseCrate, Error> {
    workspace
        .get(name)
        .ok_or_else(|| Error::Fatal(format!("{name} is not released from this repo")))
}

/// Prefix of the release tags of the crate `name`.
fn tag_prefix(name: &str) -> &str {
    TAG_PREFIXES
        .iter()
        .find(|(krate, _)| *krate == name)
        .map_or(name, |(_, prefix)| prefix)
}

/// Check the release tag names the crate and the version declared at this commit.
fn check_release_tag(tag: &str, krate: &ReleaseCrate) -> Result<String, Error> {
    let mut released_together = BTreeSet::from([krate.name.as_str()]);
    for group in SHARED_TAGS {
        if group.contains(&krate.name.as_str()) {
            released_together.extend(group);
        }
    }
    let expected: BTreeSet<String> = released_together
        .into_iter()
        .map(|name| format!("{}-{}", tag_prefix(name), krate.version))
        .collect();

    if !expected.contains(tag) {
        return Err(Error::Fatal(format!(
            "{tag} does not release {}, expected {}",
            krate.name,
            Vec::from_iter(expected).join(" or ")
        )));
    }
    Ok(format!("{tag} releases {} {}", krate.name, krate.version))
}

/// Versions crates.io has of each crate of `names`.
fn published_versions<'a>(
    registry: &dyn CrateRegistry,
    names: &[&'a str],
) -> Result<BTreeMap<&'a str, Vec<Version>>, Error> {
    // One request per crate, so the fetches are worth overlapping.
    std::thread::scope(|scope| {
        let fetches: Vec<_> = names
            .iter()
            .map(|name| (*name, scope.spawn(|| registry.published_versions(name))))
            .collect();
        fetches
            .into_iter()
            .map(|(name, fetch)| {
                let versions = fetch.join().map_err(|_| {
                    Error::Registry(format!("asking crates.io for {name} did not end well"))
                })??;
                Ok((name, versions))
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::testing::{FakeRegistry, FakeRepo, krate, manifest};
    use super::*;

    /// tfhe 1.1.0 depends on tfhe-csprng 0.10.0, both were released at 1.0.0 and 0.10.0.
    fn workspace() -> Workspace {
        Workspace::new(
            "/repo",
            [
                krate("tfhe", "1.1.0", &["tfhe-csprng"]),
                krate("tfhe-csprng", "0.10.0", &[]),
                krate("tfhe-versionable", "0.8.2", &["tfhe-versionable-derive"]),
                krate("tfhe-versionable-derive", "0.8.2", &[]),
            ],
        )
    }

    fn registry() -> FakeRegistry {
        FakeRegistry::default()
            .publish("tfhe", &["1.0.0"])
            .publish("tfhe-csprng", &["0.10.0"])
            .publish("tfhe-versionable", &["0.8.2"])
            .publish("tfhe-versionable-derive", &["0.8.2"])
    }

    /// A repository matching [`workspace`]: the bump of tfhe is committed and not tagged.
    fn repo() -> FakeRepo {
        FakeRepo::default()
            .tags(&[
                "tfhe-rs-1.0.0",
                "tfhe-csprng-0.10.0",
                "tfhe-versionable-0.8.2",
                "tfhe-versionable-derive-0.8.2",
            ])
            .change("tfhe-rs-1.0.0", "tfhe", &["tfhe/src/lib.rs"])
            .file("HEAD", "tfhe/Cargo.toml", &manifest("1.1.0", ""))
    }

    fn args(args: &[&str]) -> Args {
        use clap::Parser;

        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            args: Args,
        }
        Cli::try_parse_from(std::iter::once(&"release-status").chain(args))
            .unwrap()
            .args
    }

    fn run_on(
        args: &Args,
        repo: &FakeRepo,
        registry: &FakeRegistry,
    ) -> (Result<Verdict, Error>, String) {
        let mut out = Vec::new();
        let verdict = execute(args, &workspace(), repo, registry, &mut out);
        (verdict, String::from_utf8(out).unwrap())
    }

    #[test]
    fn command_line_is_the_one_of_the_makefile() {
        // check_cuda_version_bump outside of a pull request: the flag comes without a value.
        let parsed = args(&["--files", "--pr-gate", "--crates", "tfhe", "tfhe-csprng"]);
        assert_eq!(parsed.pr_gate.as_deref(), Some(""));
        assert_eq!(parsed.crates, ["tfhe", "tfhe-csprng"]);
        assert!(parsed.files);

        // And in one.
        let parsed = args(&["--pr-gate", "HEAD^1", "--crates", "tfhe"]);
        assert_eq!(parsed.pr_gate.as_deref(), Some("HEAD^1"));

        // check_release_ready.
        let parsed = args(&["--release-gate", "tfhe-rs-1.1.0", "--crates", "tfhe"]);
        assert_eq!(parsed.release_gate.as_deref(), Some("tfhe-rs-1.1.0"));
        assert_eq!(parsed.pr_gate, None);

        let parsed = args(&["--crates", "tfhe", "--json", "--crates", "tfhe-csprng"]);
        assert_eq!(parsed.crates, ["tfhe", "tfhe-csprng"]);
        assert!(parsed.json);
    }

    #[test]
    fn report_never_rejects() {
        // tfhe-csprng changed after its release without a bump.
        let repo = repo().change(
            "tfhe-csprng-0.10.0",
            "tfhe-csprng",
            &["tfhe-csprng/src/lib.rs"],
        );
        let (verdict, out) = run_on(&args(&[]), &repo, &registry());

        assert_eq!(verdict, Ok(Verdict::Accepted));
        assert_eq!(
            out,
            "\
crate                    manifest  crates.io  baseline                       changes  status
tfhe-csprng              0.10.0    0.10.0     tfhe-csprng-0.10.0             1        BUMP
tfhe-versionable-derive  0.8.2     0.8.2      tfhe-versionable-derive-0.8.2  0        OK
tfhe                     1.1.0     1.0.0      tfhe-rs-1.0.0                  1        TAG
tfhe-versionable         0.8.2     0.8.2      tfhe-versionable-0.8.2         0        OK

Changed without a version bump:
  tfhe-csprng: 1 changed file(s) since tfhe-csprng-0.10.0, bump tfhe-csprng/Cargo.toml

Bumped but not tagged, create the tags in this order:
  git tag -s -a -m \"tfhe 1.1.0 release\" tfhe-rs-1.1.0 && git push origin tag tfhe-rs-1.1.0
"
        );
    }

    #[test]
    fn selected_crates_are_the_only_ones_reported() {
        let (verdict, out) = run_on(&args(&["--crates", "tfhe-csprng"]), &repo(), &registry());

        assert_eq!(verdict, Ok(Verdict::Accepted));
        assert_eq!(
            out,
            "\
crate        manifest  crates.io  baseline            changes  status
tfhe-csprng  0.10.0    0.10.0     tfhe-csprng-0.10.0  0        OK

Nothing to do: every released crate is up to date on crates.io.
"
        );
    }

    #[test]
    fn unknown_crate_is_a_usage_error() {
        let (verdict, out) = run_on(
            &args(&["--crates", "tfhe", "tasks", "not-a-crate"]),
            &repo(),
            &registry(),
        );

        let error = verdict.unwrap_err();
        assert_eq!(
            error,
            Error::Usage("not released from this repo: not-a-crate, tasks".to_owned())
        );
        assert_eq!(error.exit_code(), 2);
        assert!(out.is_empty());
    }

    #[test]
    fn pull_request_gate_rejects_a_change_without_a_bump() {
        let repo = repo().change("HEAD^1", "tfhe-csprng", &["tfhe-csprng/src/lib.rs"]);
        let (verdict, out) = run_on(
            &args(&["--files", "--pr-gate", "HEAD^1"]),
            &repo,
            &registry(),
        );

        assert_eq!(verdict, Ok(Verdict::Rejected));
        assert_eq!(
            out,
            "\
crate                    manifest  crates.io  baseline  changes  status
tfhe-csprng              0.10.0    0.10.0     HEAD^1    1        BUMP
tfhe-versionable-derive  0.8.2     0.8.2      HEAD^1    0        OK
tfhe                     1.1.0     1.0.0      HEAD^1    0        OK
tfhe-versionable         0.8.2     0.8.2      HEAD^1    0        OK

Changed without a version bump:
  tfhe-csprng: 1 changed file(s) since HEAD^1, bump tfhe-csprng/Cargo.toml
      tfhe-csprng/src/lib.rs
"
        );
    }

    #[test]
    fn pull_request_gate_accepts_a_change_with_a_bump() {
        // tfhe changed, and 1.1.0 is not on crates.io.
        let repo = repo().change("HEAD^1", "tfhe", &["tfhe/src/lib.rs"]);
        let (verdict, out) = run_on(&args(&["--pr-gate", "HEAD^1"]), &repo, &registry());

        assert_eq!(verdict, Ok(Verdict::Accepted));
        assert!(
            out.contains("tfhe                     1.1.0     1.0.0      HEAD^1    1        TAG")
        );
        // The steps of a release are not what the gate was asked.
        assert!(!out.contains("git tag"), "{out}");
    }

    #[test]
    fn pull_request_gate_defaults_to_the_fork_point() {
        let repo = repo().fork_point("abc123^").change(
            "abc123^",
            "tfhe-csprng",
            &["tfhe-csprng/src/lib.rs"],
        );
        let (verdict, out) = run_on(&args(&["--pr-gate"]), &repo, &registry());

        assert_eq!(verdict, Ok(Verdict::Rejected));
        assert!(out.contains("since abc123^"), "{out}");

        // Without a fork point there is no verdict, which is not a pass.
        let (verdict, _) = run_on(&args(&["--pr-gate"]), &self::repo(), &registry());
        assert_eq!(verdict.unwrap_err().exit_code(), 1);
    }

    #[test]
    fn pull_request_gate_refuses_a_base_that_reads_as_an_option() {
        let (verdict, _) = run_on(&args(&["--pr-gate=--output=x"]), &repo(), &registry());

        assert!(matches!(verdict, Err(Error::Usage(_))), "{verdict:?}");
    }

    #[test]
    fn release_gate_accepts_a_tagged_crate_that_is_not_published() {
        let repo = repo().tags(&["tfhe-rs-1.0.0", "tfhe-rs-1.1.0"]).file(
            "tfhe-rs-1.1.0",
            "tfhe/Cargo.toml",
            &manifest("1.1.0", ""),
        );
        let (verdict, out) = run_on(
            &args(&["--release-gate", "tfhe-rs-1.1.0", "--crates", "tfhe"]),
            &repo,
            &registry(),
        );

        assert_eq!(verdict, Ok(Verdict::Accepted));
        assert_eq!(
            out,
            "\
tfhe-rs-1.1.0 releases tfhe 1.1.0
crate  manifest  crates.io  baseline       changes  status
tfhe   1.1.0     1.0.0      tfhe-rs-1.1.0  0        PUBLISH
"
        );
    }

    #[test]
    fn release_gate_rejects_what_is_not_ready() {
        // Not tagged.
        let (verdict, out) = run_on(
            &args(&["--release-gate", "tfhe-rs-1.1.0", "--crates", "tfhe"]),
            &repo(),
            &registry(),
        );
        assert_eq!(verdict, Ok(Verdict::Rejected));
        assert!(
            out.ends_with(
                "\n\ntfhe is not ready to release from tfhe-rs-1.1.0: no tag names this version\n"
            ),
            "{out}"
        );

        // Already published.
        let (verdict, out) = run_on(
            &args(&[
                "--release-gate",
                "tfhe-csprng-0.10.0",
                "--crates",
                "tfhe-csprng",
            ]),
            &repo(),
            &registry(),
        );
        assert_eq!(verdict, Ok(Verdict::Rejected));
        assert!(
            out.ends_with(
                "\n\ntfhe-csprng is not ready to release from tfhe-csprng-0.10.0: this version \
                is already on crates.io\n"
            ),
            "{out}"
        );

        // Tagged on a commit that declares another version.
        let repo = repo().tags(&["tfhe-rs-1.0.0", "tfhe-rs-1.1.0"]).file(
            "tfhe-rs-1.1.0",
            "tfhe/Cargo.toml",
            &manifest("1.0.0", ""),
        );
        let (verdict, out) = run_on(
            &args(&["--release-gate", "tfhe-rs-1.1.0", "--crates", "tfhe"]),
            &repo,
            &registry(),
        );
        assert_eq!(verdict, Ok(Verdict::Rejected));
        assert!(
            out.ends_with(
                "\n\ntfhe is not ready to release from tfhe-rs-1.1.0: tag tfhe-rs-1.1.0 points \
                at a commit declaring version 1.0.0\n"
            ),
            "{out}"
        );
    }

    #[test]
    fn release_gate_refuses_the_tag_of_something_else() {
        for tag in ["tfhe-rs-1.0.0", "tfhe-csprng-1.1.0", "tfhe-1.1.0", "v1.1.0"] {
            let (verdict, out) = run_on(
                &args(&["--release-gate", tag, "--crates", "tfhe"]),
                &repo(),
                &registry(),
            );

            let error = verdict.unwrap_err();
            assert_eq!(
                error,
                Error::Fatal(format!(
                    "{tag} does not release tfhe, expected tfhe-rs-1.1.0"
                ))
            );
            assert_eq!(error.exit_code(), 1);
            assert!(out.is_empty());
        }
    }

    #[test]
    fn release_gate_refuses_an_empty_tag() {
        let (verdict, out) = run_on(
            &args(&["--release-gate", "", "--crates", "tfhe-csprng"]),
            &repo(),
            &registry(),
        );

        assert!(matches!(verdict, Err(Error::Usage(_))), "{verdict:?}");
        assert!(out.is_empty());
    }

    #[test]
    fn crates_released_together_share_their_tags() {
        let workspace = workspace();
        let derive = workspace.get("tfhe-versionable-derive").unwrap();
        let versionable = workspace.get("tfhe-versionable").unwrap();

        for krate in [derive, versionable] {
            for tag in ["tfhe-versionable-0.8.2", "tfhe-versionable-derive-0.8.2"] {
                assert_eq!(
                    check_release_tag(tag, krate),
                    Ok(format!("{tag} releases {} 0.8.2", krate.name))
                );
            }
        }
        assert_eq!(
            check_release_tag("tfhe-versionable-0.8.1", derive),
            Err(Error::Fatal(
                "tfhe-versionable-0.8.1 does not release tfhe-versionable-derive, expected \
                tfhe-versionable-0.8.2 or tfhe-versionable-derive-0.8.2"
                    .to_owned()
            ))
        );
    }

    #[test]
    fn unreachable_registry_is_not_a_verdict() {
        let (verdict, out) = run_on(
            &args(&["--pr-gate", "HEAD^1"]),
            &repo(),
            &registry().unreachable("tfhe-csprng"),
        );

        let error = verdict.unwrap_err();
        assert!(matches!(error, Error::Registry(_)), "{error:?}");
        assert_eq!(error.exit_code(), 2);
        assert!(out.is_empty());
    }

    #[test]
    fn crate_that_was_never_published_is_reported() {
        let registry = FakeRegistry::default().publish("tfhe", &["1.0.0"]);
        let repo = repo().file(
            "tfhe-csprng-0.10.0",
            "tfhe-csprng/Cargo.toml",
            &manifest("0.10.0", ""),
        );
        let (verdict, out) = run_on(&args(&["--crates", "tfhe-csprng"]), &repo, &registry);

        assert_eq!(verdict, Ok(Verdict::Accepted));
        assert!(
            out.contains("tfhe-csprng  0.10.0    -          tfhe-csprng-0.10.0  0        PUBLISH"),
            "{out}"
        );
    }

    #[test]
    fn json_report_has_every_selected_crate_in_publish_order() {
        let (verdict, out) = run_on(
            &args(&["--json", "--crates", "tfhe", "tfhe-csprng"]),
            &repo(),
            &registry(),
        );

        assert_eq!(verdict, Ok(Verdict::Accepted));
        let reports: serde_json::Value = serde_json::from_str(&out).unwrap();
        let reports = reports.as_array().unwrap();
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0]["crate"], "tfhe-csprng");
        assert_eq!(reports[0]["status"], "OK");
        assert_eq!(reports[1]["crate"], "tfhe");
        assert_eq!(reports[1]["status"], "TAG");
        assert_eq!(reports[1]["dependencies"][0], "tfhe-csprng");
        assert_eq!(reports[1]["changed_files"][0], "tfhe/src/lib.rs");
        assert!(out.starts_with("[\n  {\n    \"crate\": \"tfhe-csprng\","));
    }

    #[test]
    fn mermaid_graph_shows_every_released_crate() {
        let (verdict, out) = run_on(
            &args(&["--mermaid", "--crates", "tfhe"]),
            &repo(),
            &registry(),
        );

        assert_eq!(verdict, Ok(Verdict::Accepted));
        assert!(out.contains("    tfhe_csprng --> tfhe\n"), "{out}");
        assert!(
            out.contains("    tfhe_versionable_derive --> tfhe_versionable\n"),
            "{out}"
        );
    }

    #[test]
    fn main_crate_is_the_only_one_with_its_own_tag_prefix() {
        assert_eq!(tag_prefix("tfhe"), "tfhe-rs");
        assert_eq!(tag_prefix("tfhe-csprng"), "tfhe-csprng");
        assert_eq!(tag_prefix("wasm-par-mq"), "wasm-par-mq");
    }
}
