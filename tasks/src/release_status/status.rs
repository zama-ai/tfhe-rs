//! The verdict on one crate: is it released, and if not, what is missing.

use super::git::Vcs;
use super::workspace::ReleaseCrate;
use super::{Error, tag_prefix};
use cargo_metadata::semver::Version;
use serde::{Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The manifest version is on crates.io and the crate did not change since.
    Ok,
    /// The manifest version is on crates.io and the crate changed since.
    Bump,
    /// The manifest version is not on crates.io and no tag names it.
    Tag,
    /// The manifest version is tagged and not on crates.io.
    Publish,
    /// The manifest, the tags and crates.io contradict each other, the report has the detail.
    Mismatch,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::Bump => "BUMP",
            Status::Tag => "TAG",
            Status::Publish => "PUBLISH",
            Status::Mismatch => "MISMATCH",
        }
    }

    /// Why a status other than PUBLISH stops a release, MISMATCH carries its own detail.
    pub fn why_not_ready(self) -> &'static str {
        match self {
            Status::Ok => "this version is already on crates.io",
            Status::Bump => "this version is already on crates.io and the crate changed since",
            Status::Tag => "no tag names this version",
            Status::Publish | Status::Mismatch => "",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

impl Serialize for Status {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// The release status of one crate. Printed as is by `--json`, so the names and the order of the
/// fields are part of the interface of the tool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    #[serde(rename = "crate")]
    pub name: String,
    /// Version declared by the manifest of the working tree.
    pub version: String,
    /// Newest version on crates.io.
    pub published: Option<String>,
    /// What the crate is compared to: its last release, or the base of the pull request.
    pub baseline_tag: Option<String>,
    /// Tag a release of `version` is made from.
    pub tag: String,
    pub tag_exists: bool,
    pub manifest: String,
    /// Files of the crate that differ from `baseline_tag`.
    pub changed_files: Vec<String>,
    pub status: Status,
    /// What is wrong when the status is MISMATCH, empty otherwise.
    pub detail: String,
    /// Released crates this one depends on.
    pub dependencies: Vec<String>,
}

/// Judge `krate` from the `tags` of the repository and the versions `published` on crates.io.
///
/// Without a `base` the crate is compared to its last release. With one, the base of a pull
/// request, it is compared to that commit and only judged when it changed since.
pub fn crate_status(
    krate: &ReleaseCrate,
    tags: &[String],
    published: &[Version],
    base: Option<&str>,
    vcs: &dyn Vcs,
) -> Result<Report, Error> {
    let version = &krate.version;
    let prefix = tag_prefix(&krate.name);

    let mut releases: Vec<Version> = tags
        .iter()
        .filter_map(|tag| release_version(prefix, tag))
        .collect();
    releases.sort_by(Version::cmp_precedence);
    // The baseline is the newest release that is not newer than the manifest, so that a release
    // branch compares against its own last dot release rather than against a later release made
    // on main. Tags are not filtered by reachability because squash-merging leaves release tags
    // off the branch they landed on. `base` overrides all of this for the pull request gate.
    let last_release = releases
        .iter()
        .rfind(|release| release.cmp_precedence(version) != Ordering::Greater);
    let baseline = match base {
        Some(base) => Some(base.to_owned()),
        None => last_release.map(|release| format!("{prefix}-{release}")),
    };
    let tag = format!("{prefix}-{version}");
    let tag_exists = releases.contains(version);

    let mut changed = match &baseline {
        Some(baseline) => vcs.changed_files(baseline, &krate.directory)?,
        None => Vec::new(),
    };
    if let Some(baseline) = &baseline
        && changed.contains(&krate.manifest)
        && !consumers_see_a_difference(vcs, baseline, &krate.manifest)?
    {
        changed.retain(|path| path != &krate.manifest);
    }

    let latest = newest(published);
    // A release branch legitimately sits below the latest version published from main, so only a
    // release on the manifest's own line means it is stale.
    let line_latest = newest(
        published
            .iter()
            .filter(|release| release_line(release) == release_line(version)),
    );

    let (status, detail) = if base.is_some() && changed.is_empty() {
        // A crate the pull request does not touch is never its problem.
        (Status::Ok, String::new())
    } else if published.contains(version) {
        let status = if changed.is_empty() {
            Status::Ok
        } else {
            Status::Bump
        };
        (status, String::new())
    } else if let Some(line_latest) =
        line_latest.filter(|latest| version.cmp_precedence(latest) == Ordering::Less)
    {
        (
            Status::Mismatch,
            format!("manifest version is behind crates.io ({line_latest})"),
        )
    } else if tag_exists {
        match declared_version(vcs, &tag, &krate.manifest)? {
            Some(at_tag) => {
                if at_tag == version.to_string() {
                    (Status::Publish, String::new())
                } else {
                    (
                        Status::Mismatch,
                        format!("tag {tag} points at a commit declaring version {at_tag}"),
                    )
                }
            }
            None => (
                Status::Mismatch,
                format!("tag {tag} points at a commit without {}", krate.manifest),
            ),
        }
    } else {
        // The version is read from the working tree but the tag would land on HEAD, so an
        // uncommitted bump would tag the version it replaces.
        match declared_version(vcs, "HEAD", &krate.manifest)? {
            Some(at_head) => {
                if at_head == version.to_string() {
                    (Status::Tag, String::new())
                } else {
                    (
                        Status::Mismatch,
                        format!("HEAD declares version {at_head}, commit the bump before tagging"),
                    )
                }
            }
            None => (
                Status::Mismatch,
                format!(
                    "HEAD has no {}, commit the crate before tagging",
                    krate.manifest
                ),
            ),
        }
    };

    Ok(Report {
        name: krate.name.clone(),
        version: version.to_string(),
        published: latest.map(Version::to_string),
        baseline_tag: baseline,
        tag,
        tag_exists,
        manifest: krate.manifest.clone(),
        changed_files: changed,
        status,
        detail,
        dependencies: krate.dependencies.clone(),
    })
}

/// Version released by `tag` if it is a release tag of the crate tagged with `prefix`.
fn release_version(prefix: &str, tag: &str) -> Option<Version> {
    // `tfhe-versionable-derive-0.8.0` starts like a tag of tfhe-versionable, what follows the
    // prefix is not a version though.
    let version = tag.strip_prefix(prefix)?.strip_prefix('-')?;
    Version::parse(version).ok()
}

/// Newest of `versions` as semver orders them: 1.0.0-alpha.9 < 1.0.0-alpha.10 < 1.0.0.
fn newest<'a>(versions: impl IntoIterator<Item = &'a Version>) -> Option<&'a Version> {
    versions
        .into_iter()
        .max_by(|left, right| left.cmp_precedence(right))
}

/// Major and minor of `version`, identifying the line it is released from: 1.6.5 and
/// 1.6.0-alpha.0 belong to the 1.6 line, 1.8.0 does not.
fn release_line(version: &Version) -> (u64, u64) {
    (version.major, version.minor)
}

/// Whether `manifest` differs between `baseline` and HEAD in a way that a consumer of the
/// published crate can observe.
fn consumers_see_a_difference(
    vcs: &dyn Vcs,
    baseline: &str,
    manifest: &str,
) -> Result<bool, Error> {
    let (Some(before), Some(after)) = (
        vcs.file_at(baseline, manifest)?,
        vcs.file_at("HEAD", manifest)?,
    ) else {
        // The crate was added or removed in between.
        return Ok(true);
    };
    Ok(consumer_facing(&before, baseline, manifest)? != consumer_facing(&after, "HEAD", manifest)?)
}

/// Content of a manifest that a consumer of the published crate can observe.
///
/// dev-dependencies only build this repo's own tests and benches, so changing them is not a
/// reason to release a new version.
fn consumer_facing(text: &str, rev: &str, manifest: &str) -> Result<toml::Table, Error> {
    let mut parsed = parse_manifest(text, rev, manifest)?;
    parsed.remove("dev-dependencies");
    if let Some(toml::Value::Table(targets)) = parsed.get_mut("target") {
        for (_, target) in targets.iter_mut() {
            if let toml::Value::Table(target) = target {
                target.remove("dev-dependencies");
            }
        }
    }
    Ok(parsed)
}

/// Version declared by `manifest` at `rev`, `None` when there is no such file at `rev`.
fn declared_version(vcs: &dyn Vcs, rev: &str, manifest: &str) -> Result<Option<String>, Error> {
    let Some(text) = vcs.file_at(rev, manifest)? else {
        return Ok(None);
    };
    let parsed = parse_manifest(&text, rev, manifest)?;
    match parsed
        .get("package")
        .and_then(|package| package.get("version"))
    {
        Some(toml::Value::String(version)) => Ok(Some(version.clone())),
        _ => Err(Error::Fatal(format!(
            "{manifest} at {rev} does not declare the version of its package"
        ))),
    }
}

fn parse_manifest(text: &str, rev: &str, manifest: &str) -> Result<toml::Table, Error> {
    text.parse()
        .map_err(|error| Error::Fatal(format!("cannot read {manifest} at {rev}:\n{error}")))
}

#[cfg(test)]
mod tests {
    use super::super::testing::{FakeRepo, krate, manifest, tags, versions};
    use super::*;

    const MANIFEST: &str = "tfhe-csprng/Cargo.toml";
    const SOURCE: &str = "tfhe-csprng/src/lib.rs";
    const RELEASE_0_10_0: &str = "tfhe-csprng-0.10.0";

    fn csprng(version: &str) -> ReleaseCrate {
        krate("tfhe-csprng", version, &["tfhe-versionable"])
    }

    /// A repository where tfhe-csprng 0.10.0 was released, and `changed` since.
    fn released_then(changed: &[&str]) -> FakeRepo {
        FakeRepo::default().change(RELEASE_0_10_0, "tfhe-csprng", changed)
    }

    #[test]
    fn released_and_untouched_is_ok() {
        let report = crate_status(
            &csprng("0.10.0"),
            &tags(&["tfhe-csprng-0.9.0", RELEASE_0_10_0]),
            &versions(&["0.9.0", "0.10.0"]),
            None,
            &released_then(&[]),
        )
        .unwrap();

        assert_eq!(
            report,
            Report {
                name: "tfhe-csprng".to_owned(),
                version: "0.10.0".to_owned(),
                published: Some("0.10.0".to_owned()),
                baseline_tag: Some(RELEASE_0_10_0.to_owned()),
                tag: RELEASE_0_10_0.to_owned(),
                tag_exists: true,
                manifest: MANIFEST.to_owned(),
                changed_files: vec![],
                status: Status::Ok,
                detail: String::new(),
                dependencies: vec!["tfhe-versionable".to_owned()],
            }
        );
    }

    #[test]
    fn released_and_changed_needs_a_bump() {
        let report = crate_status(
            &csprng("0.10.0"),
            &tags(&[RELEASE_0_10_0]),
            &versions(&["0.10.0"]),
            None,
            &released_then(&[SOURCE]),
        )
        .unwrap();

        assert_eq!(report.status, Status::Bump);
        assert_eq!(report.changed_files, [SOURCE]);
        assert_eq!(report.baseline_tag.as_deref(), Some(RELEASE_0_10_0));
    }

    #[test]
    fn bumped_needs_a_tag() {
        let repo = released_then(&[MANIFEST, SOURCE])
            .file(RELEASE_0_10_0, MANIFEST, &manifest("0.10.0", ""))
            .file("HEAD", MANIFEST, &manifest("0.10.1", ""));
        let report = crate_status(
            &csprng("0.10.1"),
            &tags(&[RELEASE_0_10_0]),
            &versions(&["0.10.0"]),
            None,
            &repo,
        )
        .unwrap();

        assert_eq!(report.status, Status::Tag);
        assert_eq!(report.tag, "tfhe-csprng-0.10.1");
        assert!(!report.tag_exists);
        assert_eq!(report.baseline_tag.as_deref(), Some(RELEASE_0_10_0));
        assert_eq!(report.changed_files, [MANIFEST, SOURCE]);
        assert_eq!(report.published.as_deref(), Some("0.10.0"));
    }

    #[test]
    fn tagged_needs_publishing() {
        let repo =
            FakeRepo::default().file("tfhe-csprng-0.10.1", MANIFEST, &manifest("0.10.1", ""));
        let report = crate_status(
            &csprng("0.10.1"),
            &tags(&[RELEASE_0_10_0, "tfhe-csprng-0.10.1"]),
            &versions(&["0.10.0"]),
            None,
            &repo,
        )
        .unwrap();

        assert_eq!(report.status, Status::Publish);
        assert!(report.tag_exists);
        // Its own tag is the newest release that is not newer than the manifest.
        assert_eq!(report.baseline_tag.as_deref(), Some("tfhe-csprng-0.10.1"));
    }

    #[test]
    fn tag_on_a_commit_declaring_another_version_is_a_mismatch() {
        let repo =
            FakeRepo::default().file("tfhe-csprng-0.10.1", MANIFEST, &manifest("0.10.0", ""));
        let report = crate_status(
            &csprng("0.10.1"),
            &tags(&["tfhe-csprng-0.10.1"]),
            &versions(&["0.10.0"]),
            None,
            &repo,
        )
        .unwrap();

        assert_eq!(report.status, Status::Mismatch);
        assert_eq!(
            report.detail,
            "tag tfhe-csprng-0.10.1 points at a commit declaring version 0.10.0"
        );
    }

    #[test]
    fn tag_on_a_commit_without_the_crate_is_a_mismatch() {
        let report = crate_status(
            &csprng("0.10.1"),
            &tags(&["tfhe-csprng-0.10.1"]),
            &versions(&["0.10.0"]),
            None,
            &FakeRepo::default(),
        )
        .unwrap();

        assert_eq!(report.status, Status::Mismatch);
        assert_eq!(
            report.detail,
            "tag tfhe-csprng-0.10.1 points at a commit without tfhe-csprng/Cargo.toml"
        );
    }

    #[test]
    fn bump_that_is_not_committed_is_a_mismatch() {
        let repo = FakeRepo::default().file("HEAD", MANIFEST, &manifest("0.10.0", ""));
        let report = crate_status(
            &csprng("0.10.1"),
            &tags(&[RELEASE_0_10_0]),
            &versions(&["0.10.0"]),
            None,
            &repo,
        )
        .unwrap();

        assert_eq!(report.status, Status::Mismatch);
        assert_eq!(
            report.detail,
            "HEAD declares version 0.10.0, commit the bump before tagging"
        );
    }

    #[test]
    fn crate_that_is_not_committed_is_a_mismatch() {
        let report = crate_status(&csprng("0.1.0"), &[], &[], None, &FakeRepo::default()).unwrap();

        assert_eq!(report.status, Status::Mismatch);
        assert_eq!(
            report.detail,
            "HEAD has no tfhe-csprng/Cargo.toml, commit the crate before tagging"
        );
    }

    #[test]
    fn manifest_behind_crates_io_is_a_mismatch() {
        let repo = FakeRepo::default().file("HEAD", MANIFEST, &manifest("0.10.1", ""));
        let report = crate_status(
            &csprng("0.10.1"),
            &tags(&[RELEASE_0_10_0]),
            &versions(&["0.10.0", "0.10.2"]),
            None,
            &repo,
        )
        .unwrap();

        assert_eq!(report.status, Status::Mismatch);
        assert_eq!(
            report.detail,
            "manifest version is behind crates.io (0.10.2)"
        );
    }

    #[test]
    fn release_branch_sits_below_the_latest_release() {
        let tfhe = krate("tfhe", "1.8.3", &[]);
        let repo = FakeRepo::default()
            .change("tfhe-rs-1.8.2", "tfhe", &["tfhe/src/lib.rs"])
            .file("HEAD", "tfhe/Cargo.toml", &manifest("1.8.3", ""));
        let report = crate_status(
            &tfhe,
            &tags(&["tfhe-rs-1.8.2", "tfhe-rs-1.9.0"]),
            &versions(&["1.8.2", "1.9.0", "1.9.1"]),
            None,
            &repo,
        )
        .unwrap();

        // 1.9.1 is out, yet 1.8.3 is ahead of everything released on the 1.8 line.
        assert_eq!(report.status, Status::Tag);
        assert_eq!(report.published.as_deref(), Some("1.9.1"));
        // Compared to its own last dot release, not to the later release made on main.
        assert_eq!(report.baseline_tag.as_deref(), Some("tfhe-rs-1.8.2"));
        assert_eq!(report.changed_files, ["tfhe/src/lib.rs"]);
    }

    #[test]
    fn prerelease_of_the_same_line_is_older() {
        let repo = FakeRepo::default().file("HEAD", MANIFEST, &manifest("1.0.0", ""));
        let report = crate_status(
            &csprng("1.0.0"),
            &tags(&["tfhe-csprng-1.0.0-alpha.9", "tfhe-csprng-1.0.0-alpha.10"]),
            &versions(&["1.0.0-alpha.9", "1.0.0-alpha.10"]),
            None,
            &repo,
        )
        .unwrap();

        assert_eq!(report.status, Status::Tag);
        // Ordered as semver does: alpha.10 is newer than alpha.9, unlike plain strings.
        assert_eq!(
            report.baseline_tag.as_deref(),
            Some("tfhe-csprng-1.0.0-alpha.10")
        );
        assert_eq!(report.published.as_deref(), Some("1.0.0-alpha.10"));
    }

    #[test]
    fn dev_dependencies_are_not_a_change() {
        let before = manifest(
            "0.10.0",
            "[dependencies]\nserde = \"1.0\"\n\
            [dev-dependencies]\nclap = \"=4.6.6\"\n\
            [target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n\
            [target.'cfg(unix)'.dev-dependencies]\nnix = \"0.29\"\n",
        );
        let after = manifest(
            "0.10.0",
            "[dependencies]\nserde = \"1.0\"\n\
            [dev-dependencies]\nclap = \"=4.6.7\"\ncriterion = \"0.8\"\n\
            [target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n\
            [target.'cfg(unix)'.dev-dependencies]\nnix = \"0.30\"\n",
        );
        let repo = released_then(&[MANIFEST, SOURCE])
            .file(RELEASE_0_10_0, MANIFEST, &before)
            .file("HEAD", MANIFEST, &after);
        let report = crate_status(
            &csprng("0.10.0"),
            &tags(&[RELEASE_0_10_0]),
            &versions(&["0.10.0"]),
            None,
            &repo,
        )
        .unwrap();

        // The manifest is out of the changes, the rest stays.
        assert_eq!(report.changed_files, [SOURCE]);
        assert_eq!(report.status, Status::Bump);

        let repo = released_then(&[MANIFEST])
            .file(RELEASE_0_10_0, MANIFEST, &before)
            .file("HEAD", MANIFEST, &after);
        let report = crate_status(
            &csprng("0.10.0"),
            &tags(&[RELEASE_0_10_0]),
            &versions(&["0.10.0"]),
            None,
            &repo,
        )
        .unwrap();

        assert!(report.changed_files.is_empty());
        assert_eq!(report.status, Status::Ok);
    }

    #[test]
    fn dependencies_are_a_change() {
        for (before, after) in [
            (
                "[dependencies]\nserde = \"1.0\"\n",
                "[dependencies]\nserde = \"1.1\"\n",
            ),
            (
                "[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n",
                "[target.'cfg(unix)'.dependencies]\nlibc = \"0.3\"\n",
            ),
            (
                "[build-dependencies]\ncmake = \"0.1\"\n",
                "[build-dependencies]\ncmake = \"0.2\"\n",
            ),
            (
                "[features]\ndefault = []\n",
                "[features]\ndefault = [\"a\"]\na = []\n",
            ),
        ] {
            let repo = released_then(&[MANIFEST])
                .file(RELEASE_0_10_0, MANIFEST, &manifest("0.10.0", before))
                .file("HEAD", MANIFEST, &manifest("0.10.0", after));
            let report = crate_status(
                &csprng("0.10.0"),
                &tags(&[RELEASE_0_10_0]),
                &versions(&["0.10.0"]),
                None,
                &repo,
            )
            .unwrap();

            assert_eq!(report.changed_files, [MANIFEST], "{before} -> {after}");
            assert_eq!(report.status, Status::Bump, "{before} -> {after}");
        }
    }

    #[test]
    fn formatting_of_the_manifest_is_not_a_change() {
        let repo = released_then(&[MANIFEST])
            .file(
                RELEASE_0_10_0,
                MANIFEST,
                &manifest(
                    "0.10.0",
                    "[dependencies]\nserde = \"1.0\"\nlibc = \"0.2\"\n",
                ),
            )
            .file(
                "HEAD",
                MANIFEST,
                &manifest(
                    "0.10.0",
                    "# sorted\n[dependencies]\nlibc    = \"0.2\"\nserde   = \"1.0\"\n",
                ),
            );
        let report = crate_status(
            &csprng("0.10.0"),
            &tags(&[RELEASE_0_10_0]),
            &versions(&["0.10.0"]),
            None,
            &repo,
        )
        .unwrap();

        assert_eq!(report.status, Status::Ok);
    }

    #[test]
    fn manifest_that_cannot_be_read_is_an_error() {
        let repo = released_then(&[MANIFEST])
            .file(RELEASE_0_10_0, MANIFEST, "this is = not [toml")
            .file("HEAD", MANIFEST, &manifest("0.10.0", ""));
        let error = crate_status(
            &csprng("0.10.0"),
            &tags(&[RELEASE_0_10_0]),
            &versions(&["0.10.0"]),
            None,
            &repo,
        );

        assert!(matches!(error, Err(Error::Fatal(_))), "{error:?}");
    }

    #[test]
    fn manifest_without_its_own_version_is_an_error() {
        let repo = FakeRepo::default().file(
            "HEAD",
            MANIFEST,
            "[package]\nname = \"tfhe-csprng\"\nversion.workspace = true\n",
        );
        let error = crate_status(&csprng("0.10.1"), &[], &[], None, &repo);

        assert!(matches!(error, Err(Error::Fatal(_))), "{error:?}");
    }

    #[test]
    fn pull_request_is_not_judged_on_a_crate_it_does_not_touch() {
        // The crate changed since its release and its manifest is behind crates.io: something is
        // wrong, which is not the doing of a pull request that leaves the crate alone.
        let judge = |base| {
            crate_status(
                &csprng("0.10.1"),
                &tags(&[RELEASE_0_10_0]),
                &versions(&["0.10.0", "0.10.2"]),
                base,
                &released_then(&[SOURCE]),
            )
            .unwrap()
        };
        assert_eq!(judge(None).status, Status::Mismatch);

        let report = judge(Some("HEAD^1"));
        assert_eq!(report.status, Status::Ok);
        // The base replaces the last release as what the crate is compared to.
        assert_eq!(report.baseline_tag.as_deref(), Some("HEAD^1"));
        assert!(report.changed_files.is_empty());
    }

    #[test]
    fn release_branch_at_a_published_version_needs_a_bump_once_changed() {
        // A backport lands on a release branch sitting at its last dot release, while main
        // already released the next minor.
        let tfhe = krate("tfhe", "1.8.2", &[]);
        let all_tags = tags(&["tfhe-rs-1.8.1", "tfhe-rs-1.8.2", "tfhe-rs-1.9.0"]);
        let published = versions(&["1.8.1", "1.8.2", "1.9.0"]);

        let untouched = crate_status(&tfhe, &all_tags, &published, None, &FakeRepo::default());
        assert_eq!(untouched.unwrap().status, Status::Ok);

        let repo = FakeRepo::default().change("tfhe-rs-1.8.2", "tfhe", &["tfhe/src/lib.rs"]);
        let report = crate_status(&tfhe, &all_tags, &published, None, &repo).unwrap();
        assert_eq!(report.status, Status::Bump);
        assert_eq!(report.baseline_tag.as_deref(), Some("tfhe-rs-1.8.2"));
        assert_eq!(report.published.as_deref(), Some("1.9.0"));

        let repo = FakeRepo::default().change("HEAD^1", "tfhe", &["tfhe/src/lib.rs"]);
        let report = crate_status(&tfhe, &all_tags, &published, Some("HEAD^1"), &repo).unwrap();
        assert_eq!(report.status, Status::Bump);
    }

    #[test]
    fn pull_request_changing_a_published_version_needs_a_bump() {
        let repo = FakeRepo::default().change("HEAD^1", "tfhe-csprng", &[SOURCE]);
        let report = crate_status(
            &csprng("0.10.0"),
            &tags(&[RELEASE_0_10_0]),
            &versions(&["0.10.0"]),
            Some("HEAD^1"),
            &repo,
        )
        .unwrap();

        assert_eq!(report.status, Status::Bump);
        assert_eq!(report.changed_files, [SOURCE]);
    }

    #[test]
    fn pull_request_changing_a_bumped_version_passes() {
        let repo = FakeRepo::default()
            .change("HEAD^1", "tfhe-csprng", &[SOURCE])
            .file("HEAD", MANIFEST, &manifest("0.10.1", ""));
        let report = crate_status(
            &csprng("0.10.1"),
            &tags(&[RELEASE_0_10_0]),
            &versions(&["0.10.0"]),
            Some("HEAD^1"),
            &repo,
        )
        .unwrap();

        assert_eq!(report.status, Status::Tag);
    }

    #[test]
    fn pull_request_adding_a_crate_is_judged() {
        // No manifest at the base: the crate does not exist there.
        let repo = FakeRepo::default()
            .change("HEAD^1", "tfhe-csprng", &[MANIFEST, SOURCE])
            .file("HEAD", MANIFEST, &manifest("0.1.0", ""));
        let report = crate_status(&csprng("0.1.0"), &[], &[], Some("HEAD^1"), &repo).unwrap();

        assert_eq!(report.status, Status::Tag);
        assert_eq!(report.changed_files, [MANIFEST, SOURCE]);
        assert_eq!(report.published, None);
    }

    #[test]
    fn never_released_crate_has_no_baseline() {
        let repo = FakeRepo::default().file("HEAD", MANIFEST, &manifest("0.1.0", ""));
        let report = crate_status(&csprng("0.1.0"), &[], &[], None, &repo).unwrap();

        assert_eq!(report.status, Status::Tag);
        assert_eq!(report.baseline_tag, None);
        assert_eq!(report.published, None);
        assert!(report.changed_files.is_empty());
    }

    #[test]
    fn tags_of_other_crates_are_not_releases() {
        let versionable = krate("tfhe-versionable", "0.8.0", &[]);
        let repo = FakeRepo::default().file("HEAD", &versionable.manifest, &manifest("0.8.0", ""));
        let report = crate_status(
            &versionable,
            &tags(&[
                "tfhe-versionable-derive-0.8.0",
                "tfhe-versionable-0.7.0",
                "tfhe-versionable-not-a-version",
                "tfhe-versionable0.8.0",
                "tfhe-rs-0.8.0",
                "0.8.0",
            ]),
            &[],
            None,
            &repo,
        )
        .unwrap();

        assert!(!report.tag_exists);
        assert_eq!(report.status, Status::Tag);
        assert_eq!(
            report.baseline_tag.as_deref(),
            Some("tfhe-versionable-0.7.0")
        );
    }

    #[test]
    fn main_crate_is_tagged_with_the_name_of_the_repository() {
        let repo = FakeRepo::default().file("HEAD", "tfhe/Cargo.toml", &manifest("1.9.0", ""));
        let report = crate_status(
            &krate("tfhe", "1.9.0", &[]),
            &tags(&["tfhe-rs-1.8.2", "tfhe-1.9.0"]),
            &versions(&["1.8.2"]),
            None,
            &repo,
        )
        .unwrap();

        assert_eq!(report.tag, "tfhe-rs-1.9.0");
        assert!(!report.tag_exists);
        assert_eq!(report.baseline_tag.as_deref(), Some("tfhe-rs-1.8.2"));
        assert_eq!(report.status, Status::Tag);
    }

    #[test]
    fn report_is_printed_as_json_with_stable_names() {
        let report = crate_status(
            &csprng("0.10.0"),
            &tags(&[RELEASE_0_10_0]),
            &versions(&["0.10.0"]),
            None,
            &released_then(&[SOURCE]),
        )
        .unwrap();

        assert_eq!(
            serde_json::to_string_pretty(&report).unwrap(),
            r#"{
  "crate": "tfhe-csprng",
  "version": "0.10.0",
  "published": "0.10.0",
  "baseline_tag": "tfhe-csprng-0.10.0",
  "tag": "tfhe-csprng-0.10.0",
  "tag_exists": true,
  "manifest": "tfhe-csprng/Cargo.toml",
  "changed_files": [
    "tfhe-csprng/src/lib.rs"
  ],
  "status": "BUMP",
  "detail": "",
  "dependencies": [
    "tfhe-versionable"
  ]
}"#
        );
    }
}
