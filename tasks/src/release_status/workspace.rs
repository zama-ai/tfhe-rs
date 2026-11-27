//! The crates this repository releases, as `cargo metadata` describes them.

use super::Error;
use cargo_metadata::camino::Utf8Path;
use cargo_metadata::semver::Version;
use cargo_metadata::{DependencyKind, MetadataCommand};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// A crate published on crates.io from this repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseCrate {
    pub name: String,
    /// Version declared by the manifest of the working tree.
    pub version: Version,
    /// Path of the manifest from the root of the repository.
    pub manifest: String,
    /// Directory of the crate from the root of the repository.
    pub directory: String,
    /// Released crates this one depends on, dev-dependencies excluded, sorted.
    pub dependencies: Vec<String>,
}

/// The released crates of the workspace, which is every package cargo may publish on crates.io.
pub struct Workspace {
    pub root: PathBuf,
    crates: BTreeMap<String, ReleaseCrate>,
}

impl Workspace {
    pub fn new(root: impl Into<PathBuf>, crates: impl IntoIterator<Item = ReleaseCrate>) -> Self {
        Self {
            root: root.into(),
            crates: crates
                .into_iter()
                .map(|krate| (krate.name.clone(), krate))
                .collect(),
        }
    }

    /// Read the workspace `root` belongs to.
    pub fn load(root: &Path) -> Result<Self, Error> {
        // --locked keeps this read-only: without it a stale Cargo.lock would be rewritten just by
        // asking for the crate versions.
        let metadata = MetadataCommand::new()
            .current_dir(root)
            .no_deps()
            .other_options(vec!["--locked".to_owned()])
            .exec()
            .map_err(|error| {
                Error::Fatal(format!(
                    "{error}\nIf Cargo.lock is out of date, run `make update_cargo_lock`."
                ))
            })?;

        let released: Vec<_> = metadata
            .packages
            .iter()
            .filter(|package| is_released(package.publish.as_deref()))
            .collect();
        let names: BTreeSet<&str> = released
            .iter()
            .map(|package| package.name.as_str())
            .collect();

        let mut crates = Vec::with_capacity(released.len());
        for package in &released {
            let manifest = relative_path(&metadata.workspace_root, &package.manifest_path)?;
            let directory = match manifest.rsplit_once('/') {
                Some((directory, _)) => directory.to_owned(),
                None => ".".to_owned(),
            };
            let dependencies: BTreeSet<&str> = package
                .dependencies
                .iter()
                .filter(|dependency| dependency.kind != DependencyKind::Development)
                .map(|dependency| dependency.name.as_str())
                .filter(|name| names.contains(name))
                .collect();
            crates.push(ReleaseCrate {
                name: package.name.to_string(),
                version: package.version.clone(),
                manifest,
                directory,
                dependencies: dependencies.into_iter().map(str::to_owned).collect(),
            });
        }
        Ok(Self::new(metadata.workspace_root.as_std_path(), crates))
    }

    /// Names of the released crates, sorted.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.crates.keys().map(String::as_str)
    }

    pub fn get(&self, name: &str) -> Option<&ReleaseCrate> {
        self.crates.get(name)
    }

    /// `names` sorted so that a crate comes after the crates it depends on.
    ///
    /// Only the dependencies between the crates of `names` are considered.
    pub fn publish_order<'a>(&'a self, names: &[&'a str]) -> Vec<&'a str> {
        let selected: BTreeSet<&str> = names.iter().copied().collect();
        let mut ordered = Vec::with_capacity(selected.len());
        let mut done = BTreeSet::new();
        while ordered.len() < selected.len() {
            let mut ready: Vec<&str> = selected
                .iter()
                .copied()
                .filter(|name| !done.contains(name))
                .filter(|name| {
                    self.selected_dependencies(name, &selected)
                        .all(|dependency| done.contains(dependency))
                })
                .collect();
            if ready.is_empty() {
                // A dependency cycle has no order: list what is left rather than never end.
                ready = selected.difference(&done).copied().collect();
            }
            done.extend(ready.iter().copied());
            ordered.extend(ready);
        }
        ordered
    }

    /// Dependencies between the crates of `names` with the transitive ones removed, which keeps
    /// the graph readable.
    ///
    /// A dependency is kept only when it cannot already be reached through another one, so
    /// `tfhe -> tfhe-versionable` is dropped in favour of
    /// `tfhe -> tfhe-zk-pok -> tfhe-safe-serialize -> tfhe-versionable`.
    pub fn pruned_dependencies<'a>(&'a self, names: &[&'a str]) -> BTreeMap<&'a str, Vec<&'a str>> {
        let selected: BTreeSet<&str> = names.iter().copied().collect();
        let mut reachable: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        let mut kept = BTreeMap::new();
        // The publish order guarantees that a crate is visited after its dependencies.
        for name in self.publish_order(names) {
            let direct: Vec<&str> = self.selected_dependencies(name, &selected).collect();
            let indirect: BTreeSet<&str> = direct
                .iter()
                .filter_map(|dependency| reachable.get(dependency))
                .flatten()
                .copied()
                .collect();
            kept.insert(
                name,
                direct
                    .iter()
                    .copied()
                    .filter(|dependency| !indirect.contains(dependency))
                    .collect(),
            );
            let mut all = indirect;
            all.extend(direct);
            reachable.insert(name, all);
        }
        kept
    }

    /// Dependencies of `name` that belong to `selected`, sorted.
    fn selected_dependencies<'a, 's>(
        &'a self,
        name: &str,
        selected: &'s BTreeSet<&str>,
    ) -> impl Iterator<Item = &'a str> + use<'a, 's> {
        self.crates
            .get(name)
            .into_iter()
            .flat_map(|krate| &krate.dependencies)
            .map(String::as_str)
            .filter(|dependency| selected.contains(dependency))
    }
}

/// Whether cargo may publish a package with this `publish` key on crates.io.
///
/// `cargo metadata` reports no value when the key is absent, an empty list for `publish = false`
/// and the registries otherwise.
fn is_released(publish: Option<&[String]>) -> bool {
    match publish {
        None => true,
        Some(registries) => registries.iter().any(|registry| registry == "crates-io"),
    }
}

/// `path` from `root`, written the way git writes paths.
fn relative_path(root: &Utf8Path, path: &Utf8Path) -> Result<String, Error> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| Error::Fatal(format!("{path} is not in the workspace {root}")))?;
    Ok(relative
        .components()
        .map(|component| component.as_str())
        .collect::<Vec<_>>()
        .join("/"))
}

#[cfg(test)]
mod tests {
    use super::super::testing::{TempDir, krate};
    use super::*;
    use crate::utils::project_root;

    fn workspace(crates: &[(&str, &[&str])]) -> Workspace {
        Workspace::new(
            "/repo",
            crates
                .iter()
                .map(|(name, dependencies)| krate(name, "1.0.0", dependencies)),
        )
    }

    #[test]
    fn only_what_cargo_may_publish_on_crates_io_is_released() {
        let registries = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();

        assert!(is_released(None));
        assert!(!is_released(Some(&[])));
        assert!(is_released(Some(&registries(&["crates-io"]))));
        assert!(is_released(Some(&registries(&["private", "crates-io"]))));
        assert!(!is_released(Some(&registries(&["private"]))));
    }

    #[test]
    fn paths_are_relative_to_the_root_with_forward_slashes() {
        let root = Utf8Path::new("/repo");
        assert_eq!(
            relative_path(
                root,
                Utf8Path::new("/repo/utils/tfhe-versionable/Cargo.toml")
            )
            .unwrap(),
            "utils/tfhe-versionable/Cargo.toml"
        );
        assert_eq!(
            relative_path(root, Utf8Path::new("/repo/Cargo.toml")).unwrap(),
            "Cargo.toml"
        );
        assert!(relative_path(root, Utf8Path::new("/elsewhere/Cargo.toml")).is_err());
    }

    #[test]
    fn publish_order_puts_dependencies_first() {
        let workspace = workspace(&[
            ("tfhe", &["tfhe-csprng", "tfhe-versionable", "tfhe-fft"]),
            ("tfhe-csprng", &["tfhe-versionable"]),
            ("tfhe-fft", &[]),
            ("tfhe-versionable", &["tfhe-versionable-derive"]),
            ("tfhe-versionable-derive", &[]),
        ]);
        let names: Vec<&str> = workspace.names().collect();

        // Crates that are ready at the same time come in alphabetical order.
        assert_eq!(
            workspace.publish_order(&names),
            [
                "tfhe-fft",
                "tfhe-versionable-derive",
                "tfhe-versionable",
                "tfhe-csprng",
                "tfhe"
            ]
        );
    }

    #[test]
    fn publish_order_only_looks_at_the_selected_crates() {
        let workspace = workspace(&[
            ("tfhe", &["tfhe-csprng"]),
            ("tfhe-csprng", &["tfhe-versionable"]),
            ("tfhe-versionable", &[]),
        ]);

        // tfhe-csprng is not selected: nothing orders tfhe after tfhe-versionable.
        assert_eq!(
            workspace.publish_order(&["tfhe-versionable", "tfhe"]),
            ["tfhe", "tfhe-versionable"]
        );
        assert_eq!(
            workspace.publish_order(&["tfhe", "tfhe-csprng"]),
            ["tfhe-csprng", "tfhe"]
        );
        assert!(workspace.publish_order(&[]).is_empty());
    }

    #[test]
    fn publish_order_ends_on_a_dependency_cycle() {
        let workspace = workspace(&[("a", &["b"]), ("b", &["a"]), ("c", &[])]);

        assert_eq!(workspace.publish_order(&["a", "b", "c"]), ["c", "a", "b"]);
        // Not a panic either.
        assert_eq!(workspace.pruned_dependencies(&["a", "b", "c"]).len(), 3);
    }

    #[test]
    fn pruned_dependencies_drop_what_is_reachable_otherwise() {
        let workspace = workspace(&[
            (
                "tfhe",
                &["tfhe-safe-serialize", "tfhe-versionable", "tfhe-zk-pok"],
            ),
            ("tfhe-safe-serialize", &["tfhe-versionable"]),
            ("tfhe-versionable", &[]),
            ("tfhe-zk-pok", &["tfhe-safe-serialize", "tfhe-versionable"]),
        ]);
        let names: Vec<&str> = workspace.names().collect();

        let kept = workspace.pruned_dependencies(&names);
        assert_eq!(kept["tfhe"], ["tfhe-zk-pok"]);
        assert_eq!(kept["tfhe-zk-pok"], ["tfhe-safe-serialize"]);
        assert_eq!(kept["tfhe-safe-serialize"], ["tfhe-versionable"]);
        assert!(kept["tfhe-versionable"].is_empty());
    }

    #[test]
    fn workspace_is_read_from_cargo() {
        let package = |name: &str, rest: &str| {
            format!("[package]\nname = \"{name}\"\nversion = \"1.2.3\"\nedition = \"2021\"\n{rest}")
        };
        let directory = TempDir::new();
        directory.write(
            "Cargo.toml",
            "[workspace]\nresolver = \"2\"\nmembers = [\"released\", \"utils/*\", \"private\"]\n",
        );
        directory.write(
            "released/Cargo.toml",
            &package(
                "released",
                "[dependencies]\n\
                dependency = { version = \"1.2.3\", path = \"../utils/dependency\" }\n\
                private = { path = \"../private\" }\n\
                [dev-dependencies]\n\
                only-for-tests = { path = \"../utils/only-for-tests\" }\n\
                [build-dependencies]\n\
                only-for-build = { version = \"1.2.3\", path = \"../utils/only-for-build\" }\n\
                [target.'cfg(unix)'.dependencies]\n\
                only-for-unix = { version = \"1.2.3\", path = \"../utils/only-for-unix\" }\n",
            ),
        );
        directory.write("utils/dependency/Cargo.toml", &package("dependency", ""));
        directory.write(
            "utils/only-for-tests/Cargo.toml",
            &package("only-for-tests", "publish = [\"crates-io\"]\n"),
        );
        directory.write(
            "utils/only-for-build/Cargo.toml",
            &package("only-for-build", ""),
        );
        directory.write(
            "utils/only-for-unix/Cargo.toml",
            &package("only-for-unix", ""),
        );
        directory.write(
            "utils/elsewhere/Cargo.toml",
            &package("elsewhere", "publish = [\"another-registry\"]\n"),
        );
        directory.write(
            "private/Cargo.toml",
            &package("private", "publish = false\n"),
        );
        for member in [
            "released",
            "utils/dependency",
            "utils/only-for-tests",
            "utils/only-for-build",
            "utils/only-for-unix",
            "utils/elsewhere",
            "private",
        ] {
            directory.write(&format!("{member}/src/lib.rs"), "");
        }

        let workspace = Workspace::load(directory.path()).unwrap();

        // Neither `private` nor `elsewhere` may be published on crates.io.
        assert_eq!(
            workspace.names().collect::<Vec<_>>(),
            [
                "dependency",
                "only-for-build",
                "only-for-tests",
                "only-for-unix",
                "released"
            ]
        );
        let released = workspace.get("released").unwrap();
        assert_eq!(released.version, Version::new(1, 2, 3));
        assert_eq!(released.manifest, "released/Cargo.toml");
        assert_eq!(released.directory, "released");
        // Whatever builds the published crate counts, what only builds its tests does not.
        assert_eq!(
            released.dependencies,
            ["dependency", "only-for-build", "only-for-unix"]
        );
        let dependency = workspace.get("dependency").unwrap();
        assert_eq!(dependency.manifest, "utils/dependency/Cargo.toml");
        assert_eq!(dependency.directory, "utils/dependency");
        assert!(dependency.dependencies.is_empty());
    }

    #[test]
    fn workspace_that_cargo_cannot_read_is_reported() {
        let directory = TempDir::new();
        directory.write("Cargo.toml", "not a manifest");

        assert!(matches!(
            Workspace::load(directory.path()),
            Err(Error::Fatal(_))
        ));
    }

    /// The real thing: this very repository is read, whatever crates it releases by then.
    #[test]
    fn this_repository_is_read() {
        let workspace = Workspace::load(&project_root()).unwrap();

        let tfhe = workspace.get("tfhe").expect("tfhe is released");
        assert_eq!(tfhe.manifest, "tfhe/Cargo.toml");
        assert_eq!(tfhe.directory, "tfhe");
        assert!(tfhe.dependencies.is_sorted());
        // This very crate has `publish = false`.
        assert!(workspace.get("tasks").is_none());

        let names: Vec<&str> = workspace.names().collect();
        assert!(names.is_sorted());
        let order = workspace.publish_order(&names);
        assert_eq!(order.len(), names.len());
        for (position, name) in order.iter().enumerate() {
            for dependency in &workspace.get(name).unwrap().dependencies {
                assert!(
                    order[..position].contains(&dependency.as_str()),
                    "{dependency} has to be published before {name}"
                );
            }
        }
    }
}
