#!/usr/bin/env python3
"""Check that the Dependabot configuration tracks all the dependency manifests.

Dependabot only looks for version updates in the directories listed in its
configuration file: the dependencies of a manifest added anywhere else are not kept up
to date, and nothing reports it. Among several listed directories, one that does not
exist is skipped just as silently. For each package ecosystem of the configuration,
this script fails if:
  - a manifest of the repository is not tracked through any of the listed directories
  - a listed directory tracks no manifest, e.g. a typo or a project that was moved

It also fails if the configuration cannot be read or uses something this script does
not model, a new ecosystem for instance: better stop than report manifests as tracked
when they are not. Ecosystems absent from the configuration are not checked.

Manifests are searched among the files known to git, tracked or not ignored, so that
build directories, venvs and node_modules are left out.

What a listed directory tracks depends on the ecosystem: the rules are the functions of
the ECOSYSTEMS table at the end of this script. They follow the file fetchers of
Dependabot, its code choosing which files of a directory to read, listed next to the
table, but keep to what is documented: when Dependabot would also pick a manifest up by
other means, its directory has to be listed anyway.

Usage: make check_dependabot_coverage
"""

import os
import posixpath
import re
import subprocess
import sys
import tomllib
from collections import defaultdict
from pathlib import Path, PurePosixPath

import yaml

# Files and directories are named by their path from the root of the repository, with
# '/' on any system, as git lists them and as Dependabot and cargo write them, hence
# PurePosixPath: PurePath would follow the rules of the system running the script,
# e.g. ignore the case on Windows. Only Path, used to read the files, is a location on
# the disk: where the repository is comes from git, see main().

# The repo root is the "/" directory when taken relative to the repo directory
REPO_ROOT = PurePosixPath()
WORKFLOWS = PurePosixPath(".github/workflows")
CONFIG_FILES = (
    PurePosixPath(".github/dependabot.yml"),
    PurePosixPath(".github/dependabot.yaml"),
)

# Options of an update entry changing which manifests it tracks in ways this script
# does not model
UNSUPPORTED_OPTIONS = {
    "exclude-paths": "the manifests it excludes would be reported as tracked",
    "target-branch": "the manifests tracked are the ones of another branch",
}

# Manifests left out of Dependabot on purpose, as {path: reason}. A path that is not,
# or no longer, an untracked manifest is an error, so that the list cannot outlive its
# purpose.
UNTRACKED_ON_PURPOSE = {}


class Tree:
    """Files of the repository known to git."""

    def __init__(self, toplevel):
        self.toplevel = toplevel
        # Tracked and untracked files, honoring .gitignore. A file removed from the
        # working tree is still listed until the removal is staged, hence the filter.
        listed = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=toplevel,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.files = {
            PurePosixPath(name)
            for name in os.fsdecode(listed).split("\0")
            if name and (toplevel / name).is_file()
        }
        self.dirs = {REPO_ROOT}
        self._files_in = defaultdict(set)
        self._dirs_in = defaultdict(set)
        for path in self.files:
            self._files_in[path.parent].add(path)
            # The last parent is the root, which is in no directory
            for directory in path.parents[:-1]:
                self.dirs.add(directory)
                self._dirs_in[directory.parent].add(directory)

    def files_in(self, directory):
        """Files directly in a directory."""
        return self._files_in.get(directory, set())

    def dirs_in(self, directory):
        """Directories directly in a directory."""
        return self._dirs_in.get(directory, set())

    def walk(self, directory):
        """A directory and all the directories below it."""
        yield directory
        for sub_directory in self.dirs_in(directory):
            yield from self.walk(sub_directory)

    def read(self, path):
        return (self.toplevel / path).read_bytes()


def resolve(directory, path):
    """Path of the repository for a path relative to a directory, as in a Cargo.toml.

    Its '.' and '..' are resolved by name, like Dependabot does with Pathname#cleanpath
    of Ruby, which pathlib cannot do: it only resolves paths against the file system.
    """
    return PurePosixPath(posixpath.normpath(directory / path))


def directory_problem(directory, glob):
    """What prevents expanding a 'directory' or 'directories' value, if anything."""
    if not isinstance(directory, str):
        return "is not a string"
    if ".." in PurePosixPath(directory).parts:
        return "must not contain '..'"
    if any(character in directory for character in "?[]{}\\"):
        return "uses a glob syntax other than '*' and '**', which is not supported"
    if "*" in directory and not glob:
        return "is a glob, which only 'directories' supports"
    return None


def expand_directory(tree, pattern):
    """Directories of the repository selected by a 'directory' or 'directories' value.

    Dependabot expands globs with Dir.glob(pattern, File::FNM_DOTMATCH) of Ruby: '*'
    matches any name, hidden ones included, and '**' any number of nested directories,
    none included, when it is a whole component followed by another one, otherwise it
    is the same as '*'.
    """
    # The values start from the root of the repository, with or without a leading '/'
    components = PurePosixPath(pattern.strip("/")).parts
    selected = {REPO_ROOT}
    for index, component in enumerate(components):
        if component == "**" and index < len(components) - 1:
            selected = {nested for start in selected for nested in tree.walk(start)}
        elif "*" in component:
            matcher = re.compile("[^/]*".join(map(re.escape, component.split("*"))))
            selected = {
                sub_directory
                for directory in selected
                for sub_directory in tree.dirs_in(directory)
                if matcher.fullmatch(sub_directory.name)
            }
        else:
            selected = {directory / component for directory in selected} & tree.dirs
    return selected


def manifests_in(tree, directory, is_manifest):
    return {path for path in tree.files_in(directory) if is_manifest(path)}


def is_github_actions_manifest(path):
    if path.name in ("action.yml", "action.yaml"):
        return True
    return path.parent == WORKFLOWS and path.name.endswith((".yml", ".yaml"))


def github_actions_tracked(tree, directory):
    """Workflows and actions of a directory, the root including .github/workflows."""
    tracked = manifests_in(tree, directory, is_github_actions_manifest)
    if directory == REPO_ROOT:
        tracked |= manifests_in(tree, WORKFLOWS, is_github_actions_manifest)
    return tracked


def is_cargo_manifest(path):
    return path.name == "Cargo.toml"


def cargo_members(tree, directory, member):
    """Directories selected by a 'members' value of the workspace of a directory.

    Globs are expanded the way Dependabot does, which supports less than cargo: '*' is
    the only wildcard, only the directories directly in the path leading to the first
    one are candidates, and a wildcard does not match a leading '.'.
    """
    if "*" not in member:
        return {resolve(directory, member)}
    # A glob is matched as text against the paths relative to the workspace
    member = posixpath.normpath(member)
    # The directories listed by Dependabot are the ones of the path before the first
    # '*', cut after its last '/': without a '/' it is not cut and nothing is found,
    # which is the case of 'prefix-*', unlike '*' and 'crates/prefix-*'
    prefix = member.split("*")[0]
    if (prefix and "/" not in prefix) or any(char in member for char in "?[]{}\\"):
        return set()
    parent = prefix[: prefix.rfind("/") + 1]
    matcher = re.compile(".*".join(map(re.escape, member.split("*"))))
    members = set()
    for candidate in tree.dirs_in(resolve(directory, parent)):
        relative = parent + candidate.name
        hidden = relative.startswith(".") and not member.startswith(".")
        if matcher.fullmatch(relative) and not hidden:
            members.add(candidate)
    return members


def cargo_tracked(tree, directory):
    """Cargo.toml of a directory and, if it is a workspace root, of the members.

    Members are updated along with their root, unlike the other path dependencies of a
    crate, which Dependabot only reads to resolve versions. Like cargo does, a member
    in an excluded path is left out.
    """
    manifest = directory / "Cargo.toml"
    if manifest not in tree.files:
        return set()
    try:
        workspace = tomllib.loads(tree.read(manifest).decode()).get("workspace", {})
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        sys.exit(f"ERROR: cannot parse {manifest}: {error}")

    excluded = [resolve(directory, path) for path in workspace.get("exclude", [])]
    tracked = {manifest}
    for member in workspace.get("members", []):
        for member_directory in cargo_members(tree, directory, member):
            if not any(member_directory.is_relative_to(path) for path in excluded):
                tracked |= manifests_in(tree, member_directory, is_cargo_manifest)
    return tracked


def is_npm_manifest(path):
    return path.name == "package.json"


def npm_tracked(tree, directory):
    """package.json of a directory.

    Workspaces are not resolved: list the directory of each package, or teach them to
    this script.
    """
    return manifests_in(tree, directory, is_npm_manifest)


def is_pip_manifest(path):
    if path.name in ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile"):
        return True
    # The naming of the requirements files of this repository, see
    # scripts/python_requirements.sh
    return "requirements" in path.name and path.suffix in (".txt", ".in")


def pip_tracked(tree, directory):
    """Requirements and project files of a directory.

    Dependabot also reads the requirements files one directory below, which is not
    documented, so not relied upon.
    """
    return manifests_in(tree, directory, is_pip_manifest)


# Per 'package-ecosystem' value: what a manifest is, and the manifests tracked through
# a directory. The file fetchers these rules come from are, in
# https://github.com/dependabot/dependabot-core:
#   github_actions/lib/dependabot/github_actions/file_fetcher.rb
#   cargo/lib/dependabot/cargo/file_fetcher.rb
#   npm_and_yarn/lib/dependabot/npm_and_yarn/file_fetcher.rb
#   python/lib/dependabot/python/file_fetcher.rb and shared_file_fetcher.rb
# and the globs of 'directories' are expanded in
#   updater/lib/dependabot/file_fetcher_command.rb
ECOSYSTEMS = {
    "github-actions": (is_github_actions_manifest, github_actions_tracked),
    "cargo": (is_cargo_manifest, cargo_tracked),
    "npm": (is_npm_manifest, npm_tracked),
    "pip": (is_pip_manifest, pip_tracked),
}


def main():
    script = sys.argv[0]
    # Ask git where the repository is, to work from any of its directories
    toplevel = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.rstrip("\n")
    tree = Tree(Path(toplevel))

    configs = [path for path in CONFIG_FILES if path in tree.files]
    if len(configs) != 1:
        expected = " or ".join(map(str, CONFIG_FILES))
        sys.exit(f"ERROR: expected {expected}, found {len(configs)} of them")
    config = configs[0]
    try:
        document = yaml.safe_load(tree.read(config))
    except yaml.YAMLError as error:
        sys.exit(f"ERROR: cannot parse {config}, Dependabot will not either:\n{error}")
    updates = document.get("updates") if isinstance(document, dict) else None
    if not isinstance(updates, list) or not all(
        isinstance(update, dict) for update in updates
    ):
        sys.exit(f"ERROR: {config} has no valid 'updates' list")

    errors = []
    tracked = {}
    for index, update in enumerate(updates):
        ecosystem = update.get("package-ecosystem")
        where = f"{config}: updates[{index}] ({ecosystem})"
        if ecosystem not in ECOSYSTEMS:
            errors.append(f"{where}: unknown ecosystem, teach it to {script}")
            continue
        _, tracked_through = ECOSYSTEMS[ecosystem]
        tracked.setdefault(ecosystem, set())
        for option, reason in UNSUPPORTED_OPTIONS.items():
            if option in update:
                errors.append(f"{where}: '{option}' is not supported, {reason}")

        directories = update.get("directories", [])
        if not isinstance(directories, list):
            errors.append(f"{where}: 'directories' is not a list")
            continue
        # Only 'directories' supports globbing
        directories = [(directory, True) for directory in directories]
        if "directory" in update:
            directories.append((update["directory"], False))
        if not directories:
            errors.append(f"{where}: no directory")
        for directory, glob in directories:
            problem = directory_problem(directory, glob)
            if problem is not None:
                errors.append(f"{where}: directory {directory!r} {problem}")
                continue
            found = set()
            for expanded in expand_directory(tree, directory):
                found |= tracked_through(tree, expanded)
            if not found:
                errors.append(f"{where}: directory {directory!r} tracks no manifest")
            tracked[ecosystem] |= found

    untracked = {}
    for ecosystem in sorted(tracked):
        is_manifest, _ = ECOSYSTEMS[ecosystem]
        manifests = {path for path in tree.files if is_manifest(path)}
        missing = manifests - tracked[ecosystem]
        untracked.update(dict.fromkeys(missing, ecosystem))
        count = len(manifests) - len(missing)
        print(f"{ecosystem}: {count} of {len(manifests)} manifests tracked")

    on_purpose = {PurePosixPath(key): why for key, why in UNTRACKED_ON_PURPOSE.items()}
    for path in sorted(on_purpose.keys() - untracked.keys()):
        errors.append(f"UNTRACKED_ON_PURPOSE: {path} is not an untracked manifest")
    for path in sorted(on_purpose.keys() & untracked.keys()):
        print(f"{path}: untracked on purpose, {on_purpose[path]}")
    forgotten = sorted(untracked.keys() - on_purpose.keys())
    for path in forgotten:
        errors.append(f"{path}: {untracked[path]} manifest not tracked by Dependabot")

    if errors:
        sys.stdout.flush()
        print("\n".join(f"ERROR: {error}" for error in errors), file=sys.stderr)
        if forgotten:
            print(
                "Add the directory of each untracked manifest to the directories of its"
                f" ecosystem in {config}, see {script} for what a directory tracks.",
                file=sys.stderr,
            )
        sys.exit(1)


if __name__ == "__main__":
    main()
