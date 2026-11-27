//! What the release status needs to know from git, asked to the `git` command line.

use super::Error;
use std::path::PathBuf;
use std::process::Command;

/// The questions asked to the repository, behind a trait so that the verdicts can be tested
/// without one.
pub trait Vcs {
    /// Names of all the tags of the repository.
    fn tags(&self) -> Result<Vec<String>, Error>;

    /// Commit this branch was cut from, be it main or a release branch.
    fn fork_point(&self) -> Result<String, Error>;

    /// Paths under `directory` that differ between the commit `base` and HEAD.
    fn changed_files(&self, base: &str, directory: &str) -> Result<Vec<String>, Error>;

    /// Content of `path` at the commit `rev`, `None` when the file does not exist there.
    fn file_at(&self, rev: &str, path: &str) -> Result<Option<String>, Error>;
}

/// The repository checked out at `root`, paths are relative to it.
pub struct Git {
    root: PathBuf,
}

impl Git {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn run(&self, args: &[&str]) -> Result<String, Error> {
        let output = Command::new("git")
            .args(args)
            .current_dir(&self.root)
            .output()
            .map_err(|error| Error::Fatal(format!("could not run git: {error}")))?;
        if !output.status.success() {
            return Err(Error::Fatal(format!(
                "git {} failed:\n{}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| Error::Fatal(format!("git {} did not print valid UTF-8", args.join(" "))))
    }
}

impl Vcs for Git {
    fn tags(&self) -> Result<Vec<String>, Error> {
        let tags = self.run(&["tag"])?;
        Ok(tags.split_whitespace().map(str::to_owned).collect())
    }

    fn fork_point(&self) -> Result<String, Error> {
        if self
            .run(&["rev-parse", "HEAD^@"])?
            .split_whitespace()
            .count()
            > 1
        {
            // A merge carries the merged branch's commits, which are not this branch's work.
            return Err(Error::Fatal(
                "HEAD is a merge commit, pass a base: --pr-gate HEAD^1 in CI".to_owned(),
            ));
        }
        let own = self.run(&[
            "rev-list",
            "HEAD",
            "--not",
            "--glob=refs/remotes/origin/release/",
            "origin/main",
        ])?;
        match own.lines().last() {
            Some(oldest) => Ok(format!("{oldest}^")),
            None => Err(Error::Fatal(
                "HEAD has no commits of its own, there is nothing to gate.".to_owned(),
            )),
        }
    }

    fn changed_files(&self, base: &str, directory: &str) -> Result<Vec<String>, Error> {
        let range = format!("{base}..HEAD");
        let changed = self.run(&["diff", "--name-only", &range, "--", directory])?;
        Ok(changed.lines().map(str::to_owned).collect())
    }

    fn file_at(&self, rev: &str, path: &str) -> Result<Option<String>, Error> {
        // Asked first so that a file missing at `rev`, the manifest of a crate that did not exist
        // yet for instance, is told apart from git failing.
        if self
            .run(&["ls-tree", "--name-only", rev, "--", path])?
            .trim()
            .is_empty()
        {
            return Ok(None);
        }
        self.run(&["show", &format!("{rev}:{path}")]).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::TempDir;
    use super::*;
    use std::path::Path;

    /// A scratch repository.
    struct TempRepo {
        directory: TempDir,
    }

    impl TempRepo {
        fn new() -> Self {
            let repo = Self {
                directory: TempDir::new(),
            };
            repo.git(&["init", "--quiet"]);
            repo
        }

        /// Run a git command that sets the repository up, isolated from the configuration of
        /// the machine running the tests.
        fn git(&self, args: &[&str]) -> String {
            let path = self.directory.path();
            let output = Command::new("git")
                .args(["-c", "user.name=xtask", "-c", "user.email=xtask@localhost"])
                .args(["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
                .args(args)
                .current_dir(path)
                .env("HOME", path)
                .env("XDG_CONFIG_HOME", path)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        }

        fn write(&self, path: &str, content: &str) {
            self.directory.write(path, content);
        }

        fn remove(&self, path: &str) {
            std::fs::remove_file(self.directory.path().join(path)).unwrap();
        }

        /// Commit everything in the working tree, return the commit.
        fn commit(&self, message: &str) -> String {
            self.git(&["add", "--all"]);
            self.git(&["commit", "--quiet", "--allow-empty", "-m", message]);
            self.git(&["rev-parse", "HEAD"])
        }

        fn as_git(&self) -> Git {
            Git::new(self.directory.path())
        }
    }

    fn fatal_message(result: Result<String, Error>) -> String {
        match result {
            Err(Error::Fatal(message)) => message,
            other => panic!("expected a fatal error, got {other:?}"),
        }
    }

    #[test]
    fn changed_files_are_limited_to_the_directory() {
        let repo = TempRepo::new();
        repo.write("tfhe/src/lib.rs", "one");
        repo.write("tfhe-csprng/src/lib.rs", "one");
        let base = repo.commit("base");
        repo.write("tfhe/src/lib.rs", "two");
        repo.write("tfhe/src/new.rs", "new");
        repo.write("tfhe-csprng/src/lib.rs", "two");
        repo.commit("change");

        let git = repo.as_git();
        assert_eq!(
            git.changed_files(&base, "tfhe").unwrap(),
            ["tfhe/src/lib.rs", "tfhe/src/new.rs"]
        );
        // `tfhe` is a prefix of `tfhe-csprng`, which is another crate all the same.
        assert_eq!(
            git.changed_files(&base, "tfhe-csprng").unwrap(),
            ["tfhe-csprng/src/lib.rs"]
        );
    }

    #[test]
    fn changed_files_ignore_what_is_not_committed() {
        let repo = TempRepo::new();
        repo.write("tfhe/src/lib.rs", "one");
        let base = repo.commit("base");
        repo.write("tfhe/src/lib.rs", "not committed");

        assert!(
            repo.as_git()
                .changed_files(&base, "tfhe")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn changed_files_list_deletions() {
        let repo = TempRepo::new();
        repo.write("tfhe/src/lib.rs", "one");
        repo.write("tfhe/src/gone.rs", "one");
        let base = repo.commit("base");
        repo.remove("tfhe/src/gone.rs");
        repo.commit("delete");

        assert_eq!(
            repo.as_git().changed_files(&base, "tfhe").unwrap(),
            ["tfhe/src/gone.rs"]
        );
    }

    #[test]
    fn changed_files_fail_on_an_unknown_base() {
        let repo = TempRepo::new();
        repo.commit("base");

        let error = repo.as_git().changed_files("not-a-revision", "tfhe");
        assert!(matches!(error, Err(Error::Fatal(_))), "{error:?}");
    }

    #[test]
    fn file_at_reads_the_file_of_that_commit() {
        let repo = TempRepo::new();
        repo.write("tfhe/Cargo.toml", "old");
        let old = repo.commit("old");
        repo.write("tfhe/Cargo.toml", "new");
        repo.commit("new");
        repo.write("tfhe/Cargo.toml", "not committed");

        let git = repo.as_git();
        assert_eq!(
            git.file_at(&old, "tfhe/Cargo.toml").unwrap().unwrap(),
            "old"
        );
        assert_eq!(
            git.file_at("HEAD", "tfhe/Cargo.toml").unwrap().unwrap(),
            "new"
        );
    }

    #[test]
    fn file_at_tells_a_missing_file_from_a_failure() {
        let repo = TempRepo::new();
        repo.write("tfhe/src/lib.rs", "moved in from another crate");
        let before = repo.commit("before the manifest exists");
        repo.write("tfhe/Cargo.toml", "new");
        repo.commit("add the manifest");

        let git = repo.as_git();
        assert_eq!(git.file_at(&before, "tfhe/Cargo.toml").unwrap(), None);
        assert_eq!(git.file_at("HEAD", "tfhe-csprng/Cargo.toml").unwrap(), None);
        assert!(git.file_at(&before, "tfhe/src/lib.rs").unwrap().is_some());
        let error = git.file_at("not-a-revision", "tfhe/Cargo.toml");
        assert!(matches!(error, Err(Error::Fatal(_))), "{error:?}");
    }

    #[test]
    fn file_at_reads_through_an_annotated_tag() {
        let repo = TempRepo::new();
        repo.write("tfhe/Cargo.toml", "tagged");
        repo.commit("release");
        repo.git(&["tag", "-a", "-m", "release", "tfhe-rs-1.0.0"]);
        repo.write("tfhe/Cargo.toml", "later");
        repo.commit("later");

        assert_eq!(
            repo.as_git()
                .file_at("tfhe-rs-1.0.0", "tfhe/Cargo.toml")
                .unwrap()
                .unwrap(),
            "tagged"
        );
    }

    #[test]
    fn tags_are_listed() {
        let repo = TempRepo::new();
        repo.commit("release");
        repo.git(&["tag", "tfhe-rs-1.0.0"]);
        repo.git(&["tag", "-a", "-m", "release", "tfhe-csprng-0.1.0"]);

        assert_eq!(
            repo.as_git().tags().unwrap(),
            ["tfhe-csprng-0.1.0", "tfhe-rs-1.0.0"]
        );
        assert!(TempRepo::new().as_git().tags().unwrap().is_empty());
    }

    #[test]
    fn fork_point_is_the_parent_of_the_first_own_commit() {
        let repo = TempRepo::new();
        let main = repo.commit("main");
        repo.git(&["update-ref", "refs/remotes/origin/main", &main]);
        repo.commit("first own commit");
        repo.commit("second own commit");

        let fork_point = repo.as_git().fork_point().unwrap();
        assert_eq!(repo.git(&["rev-parse", &fork_point]), main);
    }

    #[test]
    fn fork_point_of_a_branch_cut_from_a_release_branch() {
        let repo = TempRepo::new();
        let main = repo.commit("main");
        repo.git(&["update-ref", "refs/remotes/origin/main", &main]);
        let release = repo.commit("only on the release branch");
        repo.git(&["update-ref", "refs/remotes/origin/release/1.8.x", &release]);
        repo.commit("backport");

        let fork_point = repo.as_git().fork_point().unwrap();
        assert_eq!(repo.git(&["rev-parse", &fork_point]), release);
    }

    #[test]
    fn fork_point_needs_commits_to_gate() {
        let repo = TempRepo::new();
        let main = repo.commit("main");
        repo.git(&["update-ref", "refs/remotes/origin/main", &main]);

        assert_eq!(
            fatal_message(repo.as_git().fork_point()),
            "HEAD has no commits of its own, there is nothing to gate."
        );
    }

    #[test]
    fn fork_point_refuses_a_merge_commit() {
        let repo = TempRepo::new();
        let main = repo.commit("main");
        repo.git(&["update-ref", "refs/remotes/origin/main", &main]);
        repo.git(&["checkout", "--quiet", "-b", "side"]);
        repo.write("side.txt", "side");
        repo.commit("side");
        repo.git(&["checkout", "--quiet", "--detach", &main]);
        repo.write("other.txt", "other");
        repo.commit("other");
        repo.git(&["merge", "--quiet", "--no-ff", "-m", "merge", "side"]);

        assert_eq!(
            fatal_message(repo.as_git().fork_point()),
            "HEAD is a merge commit, pass a base: --pr-gate HEAD^1 in CI"
        );
    }

    #[test]
    fn a_missing_repository_is_reported() {
        let git = Git::new(Path::new("/this/path/does/not/exist"));
        assert!(matches!(git.tags(), Err(Error::Fatal(_))));
    }
}
