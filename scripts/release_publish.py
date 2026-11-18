#!/usr/bin/env python3
"""Publish the crates released from the current commit with a single cargo run.

A crate is released when its version is not in the registry yet and its release
tag points at the commit being released: the tag is what declares it ready, a
crate merely bumped on the way to its next release is left alone. That subset
is handed to cargo, which publishes it in dependency order.

  plan       show what a release from this commit publishes
  publish    hand those crates to cargo publish, see --dry-run and --no-verify
  reproduce  package the released crates again, check them against the registry

Verifying and uploading are meant to be two runs: `publish --dry-run` builds
every crate with no registry token around, then `publish --no-verify` uploads
them without running any code of their dependencies while the token is there.

Built on scripts/release_status.py. `make test_release_tooling` runs all of it
against a local registry.
"""

import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

import release_status as status

# What a release does about a crate.
PUBLISH = "publish"
PUBLISHED = "published"
UNTAGGED = "untagged"
ELSEWHERE = "tagged elsewhere"

# What cargo prints once a crate is sent to the registry, colors stripped.
UPLOADED = re.compile(r"^\s*Uploaded (\S+) v\S+ to ", re.MULTILINE)
COLORS = re.compile(r"\x1b\[[0-9;]*m")

CHECKSUMS = "SHA256SUMS"
# Seconds between two looks at the index while waiting for a crate to show there.
POLL_SECONDS = 5


def sha256(path):
    with open(path, "rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def error(message):
    print(f"error: {message}", file=sys.stderr)


class Plan:
    """What a release from the current commit publishes, and what is in its way."""

    def __init__(self, registry, tag=None, rehearsal=False, allow_new_crates=False):
        self.registry = registry
        self.tag = tag
        self.rehearsal = rehearsal
        metadata = status.cargo_metadata()
        packages = status.workspace_packages(metadata)
        release = status.release_crates(packages, registry.name)
        self.target_directory = Path(metadata["target_directory"])
        self.head = status.git("rev-parse", "HEAD").strip()
        # In the order they have to be published: dependencies first.
        self.reports = status.crate_reports(release, packages, release, registry)
        for report in self.reports:
            report["state"] = self.state(report)
        self.errors = self.tag_errors() + self.selection_errors(allow_new_crates)
        self.warnings = self.selection_warnings()

    def state(self, report):
        if report["is_published"]:
            return PUBLISHED
        # A rehearsal checks that everything bumped could be released from here.
        if self.rehearsal or report["tag_commit"] == self.head:
            return PUBLISH
        return ELSEWHERE if report["tag_exists"] else UNTAGGED

    @property
    def selected(self):
        """Crates to publish, in publish order."""
        return [report for report in self.reports if report["state"] == PUBLISH]

    @property
    def released(self):
        """Crates released from this commit, by this run or by an earlier one."""
        return [
            report
            for report in self.reports
            if report["state"] == PUBLISH or report["tag_commit"] == self.head
        ]

    def tag_errors(self):
        """Check the release was asked from a tag releasing a crate from this commit."""
        if not self.tag:
            return []
        commits = [r["tag_commit"] for r in self.reports if r["tag"] == self.tag]
        if not any(commits):
            expected = ", ".join(report["tag"] for report in self.reports)
            return [
                f"{self.tag} is not the release tag of a crate at the version this"
                f" commit declares, which would be one of: {expected}"
            ]
        if commits[0] != self.head:
            return [
                f"{self.tag} points at commit {commits[0][:9]}"
                f" but {self.head[:9]} is checked out"
            ]
        return []

    def selection_errors(self, allow_new_crates):
        by_name = {report["crate"]: report for report in self.reports}
        registry = self.registry.label
        errors = []
        for report in self.selected:
            crate = f"{report['crate']} {report['version']}"
            if report["status"] == status.MISMATCH:
                errors.append(f"{crate}: {report['detail']}")
            if report["published"] is None and not allow_new_crates:
                errors.append(
                    f"{crate} would be the first version of this crate on {registry}:"
                    " trusted publishing cannot create a crate, publish this version"
                    " with an API token and register the release workflow as its"
                    " trusted publisher (--allow-new-crates to go ahead anyway)"
                )
            # cargo resolves the dependencies of what it publishes from the
            # registry and from the crates published along: one that is in
            # neither fails the run, possibly after some crates were uploaded.
            for name in report["dependencies"]:
                dependency = by_name[name]
                needed = f"{crate} depends on {name} {dependency['version']}, which is"
                if dependency["state"] == UNTAGGED:
                    errors.append(
                        f"{needed} neither on {registry} nor tagged: tag this commit"
                        f" with {dependency['tag']} to release it as well"
                    )
                elif dependency["state"] == ELSEWHERE:
                    errors.append(
                        f"{needed} not on {registry} and tagged on another commit:"
                        f" release it from {dependency['tag']}"
                        f" ({dependency['tag_commit'][:9]}) first"
                    )
        return errors

    def selection_warnings(self):
        by_name = {report["crate"]: report for report in self.reports}
        dependents = {}
        for report in self.selected:
            for name in report["dependencies"]:
                if by_name[name]["status"] == status.BUMP:
                    dependents.setdefault(name, []).append(report["crate"])
        return [
            f"{name} changed since {by_name[name]['baseline_tag']} without a version"
            f" bump ({len(by_name[name]['changed_files'])} changed file(s)):"
            f" {', '.join(users)} will be used with the {name}"
            f" {by_name[name]['version']} that is on {self.registry.label},"
            " not with these changes"
            for name, users in dependents.items()
        ]

    def crate_file(self, report):
        """Where cargo leaves the crate file it packages."""
        name = f"{report['crate']}-{report['version']}.crate"
        return self.target_directory / "package" / name

    def cargo_publish(self, *options, reports=None):
        """The cargo command publishing `reports`, the selected crates by default."""
        command = ["cargo", "publish", "--locked", *options]
        if self.registry.name != status.CRATES_IO:
            command += ["--registry", self.registry.name]
        for report in self.selected if reports is None else reports:
            command += ["-p", report["crate"]]
        return command

    def title(self):
        origin = f"commit {self.head[:9]}"
        if self.tag:
            origin += f" (tag {self.tag})"
        if self.rehearsal:
            return (
                f"Rehearsal of a release to {self.registry.label} from {origin}:"
                " every crate that is not published yet is selected, tagged or not"
            )
        return f"Release to {self.registry.label} from {origin}"

    def table(self):
        header = ("crate", "version", self.registry.label, "release tag", "state")
        rows = [header]
        for report in self.reports:
            state = report["state"]
            if state == ELSEWHERE:
                state = f"tagged on {report['tag_commit'][:9]}"
            rows.append(
                (
                    report["crate"],
                    report["version"],
                    report["published"] or "-",
                    report["tag"] if report["tag_exists"] else "-",
                    state,
                )
            )
        return rows

    def outcome(self):
        """What the release is going to do, in a few lines."""
        if not self.selected:
            if self.rehearsal:
                reason = f"every crate is on {self.registry.label} already"
            elif not any(r["tag_commit"] == self.head for r in self.reports):
                reason = (
                    "no release tag points at this commit"
                    " (--rehearsal selects the crates that are not published yet)"
                )
            else:
                reason = (
                    "the crates tagged on this commit are on"
                    f" {self.registry.label} already"
                )
            return [f"Nothing to publish: {reason}."]
        lines = [f"To publish to {self.registry.label}, dependencies first:"]
        lines += [f"  {r['crate']} {r['version']}" for r in self.selected]
        lines += ["with:", "  " + shlex.join(self.cargo_publish())]
        return lines

    def print(self, outcome=True):
        print(self.title() + "\n")
        rows = self.table()
        widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
        for row in rows:
            cells = (cell.ljust(width) for cell, width in zip(row, widths))
            print("  ".join(cells).rstrip())
        if outcome:
            print("\n" + "\n".join(self.outcome()))
        for warning in self.warnings:
            print(f"\nwarning: {warning}")
        sys.stdout.flush()
        for message in self.errors:
            error(message)

    def markdown(self):
        header, *rows = self.table()
        lines = [f"### {self.title()}", ""]
        lines += ["| " + " | ".join(header) + " |", "|" + " --- |" * len(header)]
        lines += ["| " + " | ".join(row) + " |" for row in rows]
        lines += ["", "```", *self.outcome(), "```"]
        lines += [f"\n**Warning:** {warning}" for warning in self.warnings]
        lines += [f"\n**Error:** {message}" for message in self.errors]
        return "\n".join(lines) + "\n"

    def json(self):
        return {
            "registry": self.registry.label,
            "commit": self.head,
            "tag": self.tag,
            "rehearsal": self.rehearsal,
            "crates": [
                {key: report[key] for key in ("crate", "version", "tag", "state")}
                for report in self.reports
            ],
            "publish": [report["crate"] for report in self.selected],
            "released": [report["crate"] for report in self.released],
            "command": self.cargo_publish() if self.selected else None,
            "warnings": self.warnings,
            "errors": self.errors,
        }


def append(path, text):
    """Add `text` to the file at `path`, if any: how a step of a GitHub job reports."""
    if path:
        with open(path, "a") as file:
            file.write(text)


def run(command):
    """Run `command`, showing what it reports as it comes.

    Returns its exit code along with what it reported on its standard error,
    which is where cargo tells what it does.
    """
    print("+ " + shlex.join(command), flush=True)
    process = subprocess.Popen(
        command, cwd=status.REPO, stderr=subprocess.PIPE, text=True, errors="replace"
    )
    reported = []
    for line in process.stderr:
        sys.stderr.write(line)
        sys.stderr.flush()
        reported.append(line)
    return process.wait(), "".join(reported)


def wait_for_index(plan, reports, timeout):
    """Checksum the registry holds for each crate of `reports`, by crate name.

    The index, often served from a cache, can take a while to show a version
    that was just uploaded: the ones still missing after `timeout` seconds are
    left out of the result.
    """
    found = {}
    deadline = time.monotonic() + timeout
    while True:
        pending = [report for report in reports if report["crate"] not in found]
        names = [report["crate"] for report in pending]
        try:
            published = status.fetch_published(names, plan.registry.index)
        except OSError as problem:
            print(f"could not reach {plan.registry.index}: {problem}", file=sys.stderr)
            published = {}
        for report in pending:
            checksum = published.get(report["crate"], {}).get(report["version"])
            if checksum:
                found[report["crate"]] = checksum
        if len(found) == len(reports) or time.monotonic() >= deadline:
            return found
        time.sleep(POLL_SECONDS)


def upload(plan, options, timeout):
    """Have cargo upload the selected crates, return 0 once they all are.

    cargo gives up when the index takes more than a minute to show a crate that
    the next ones depend on, which leaves the release half done. As long as a run
    uploaded something it is worth running cargo again for what is left, once the
    index caught up: cargo refuses to publish a version it cannot see is missing.
    """
    remaining = plan.selected
    while True:
        code, reported = run(plan.cargo_publish(*options, reports=remaining))
        if code == 0:
            return 0
        uploaded = set(UPLOADED.findall(COLORS.sub("", reported)))
        done = [report for report in remaining if report["crate"] in uploaded]
        if not done:
            # Nothing went through: trying again would fail the same way.
            return code
        remaining = [report for report in remaining if report["crate"] not in uploaded]
        names = ", ".join(report["crate"] for report in done)
        print(
            f"\ncargo stopped after uploading {names},"
            f" waiting for {plan.registry.label} to list them",
            flush=True,
        )
        visible = wait_for_index(plan, done, timeout)
        late = [report["crate"] for report in done if report["crate"] not in visible]
        if late:
            error(
                f"{', '.join(late)} still not listed by {plan.registry.label}"
                f" after {timeout} seconds, run the release again later:"
                " it resumes with what is left to publish"
            )
            return 1
        if not remaining:
            return 0
        print(
            "resuming with " + ", ".join(report["crate"] for report in remaining),
            flush=True,
        )


def check_published(plan, timeout):
    """Check the registry holds, for each selected crate, the file packaged here."""
    checksums = wait_for_index(plan, plan.selected, timeout)
    failures = 0
    for report in plan.selected:
        crate = f"{report['crate']} {report['version']}"
        local = sha256(plan.crate_file(report))
        if report["crate"] not in checksums:
            error(f"{crate} is not listed by {plan.registry.label}")
            failures += 1
        elif checksums[report["crate"]] != local:
            error(
                f"{plan.registry.label} holds another {crate} than the one packaged"
                f" here: {checksums[report['crate']]} instead of {local}"
            )
            failures += 1
        else:
            print(f"{crate} is on {plan.registry.label}, sha256 {local}")
    return failures


def output_directory(plan, args):
    return Path(args.output_dir or plan.target_directory / "release-crates")


def write_artifacts(plan, reports, directory):
    """Gather the crate files of `reports` in `directory` with their checksums."""
    directory.mkdir(parents=True, exist_ok=True)
    # Whatever an earlier run left there is not part of this release.
    for stale in [*directory.glob("*.crate"), directory / CHECKSUMS]:
        stale.unlink(missing_ok=True)
    lines = []
    for report in reports:
        source = plan.crate_file(report)
        shutil.copyfile(source, directory / source.name)
        lines.append(f"{sha256(source)}  {source.name}\n")
    (directory / CHECKSUMS).write_text("".join(lines))
    print(f"\n{directory / CHECKSUMS}:\n{''.join(lines)}", end="", flush=True)
    return lines


def publish(plan, args):
    if plan.rehearsal and not args.dry_run:
        error(
            "a rehearsal selects crates that are not tagged, it can only be a dry run"
        )
        return 1
    if not plan.selected:
        return 0

    options = ["--no-verify"] if args.no_verify else []
    if args.dry_run:
        code, _ = run(plan.cargo_publish("--dry-run", *options))
    else:
        code = upload(plan, options, args.index_timeout)
    if code:
        return code
    if not args.dry_run and check_published(plan, args.index_timeout):
        return 1

    lines = write_artifacts(plan, plan.selected, output_directory(plan, args))
    if not args.dry_run:
        append(
            args.summary,
            f"### Published to {plan.registry.label}\n\n```\n{''.join(lines)}```\n",
        )
    return 0


def read_checksums(path):
    """File names of a SHA256SUMS file, with their checksum."""
    lines = Path(path).read_text().splitlines()
    return {name.lstrip("*"): checksum for checksum, name in map(str.split, lines)}


def reproduce(plan, args):
    """Package crates again and check they are the very files that were released.

    Packaging is deterministic: a commit and a version of cargo always give the
    same crate file. This is what lets a machine that took no part in the upload
    vouch for what is in the registry, or, with --against, for the files another
    machine packaged.
    """
    by_file = {plan.crate_file(report).name: report for report in plan.reports}
    if args.against:
        expected = read_checksums(args.against)
        reference = args.against
        unknown = sorted(set(expected) - set(by_file))
        if unknown:
            error(f"{reference} lists files this commit does not release: {unknown}")
            return 1
    else:
        # Not only what this run published: an earlier run that stopped half way
        # leaves crates that were never vouched for.
        expected = {
            plan.crate_file(report).name: report["checksum"]
            for report in plan.reports
            if report["is_published"] and report["tag_commit"] == plan.head
        }
        reference = plan.registry.label
    reports = [report for name, report in by_file.items() if name in expected]
    append(args.github_output, f"count={len(reports)}\n")
    if not reports:
        print(f"Nothing to reproduce: {reference} has no crate from this commit.")
        return 0

    # A dry run rather than `cargo package`, to package the way the release did.
    # It only warns about the versions that are published already.
    code, _ = run(plan.cargo_publish("--dry-run", "--no-verify", reports=reports))
    if code:
        return code
    failures = 0
    for report in reports:
        file = plan.crate_file(report)
        if sha256(file) != expected[file.name]:
            error(
                f"{file.name} does not reproduce: {reference} has"
                f" {expected[file.name]}, packaging this commit gives {sha256(file)}"
            )
            failures += 1
    if failures:
        cargo = subprocess.run(
            ["cargo", "--version"], cwd=status.REPO, capture_output=True, text=True
        )
        error(
            "a crate file only depends on the commit and on the version of cargo"
            f" packaging it, which is {cargo.stdout.strip()} here"
        )
        return 1
    print(f"\nThe crates packaged from this commit are the ones of {reference}.")
    write_artifacts(plan, reports, output_directory(plan, args))
    return 0


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument(
        "--tag",
        help="tag the release was asked from, which has to release a crate from the"
        " current commit",
    )
    selection.add_argument(
        "--rehearsal",
        action="store_true",
        help="select every crate that is not published yet, tagged or not, to check"
        " they could all be released from the current commit",
    )
    parser.add_argument(
        "--allow-new-crates",
        action="store_true",
        help="publish crates the registry has no version of, which a token obtained"
        " through trusted publishing is not allowed to do",
    )
    parser.add_argument(
        "--github-output",
        metavar="FILE",
        help="file to write the outputs of a GitHub step to: publish and released,"
        " the JSON lists of the crates to publish and of the crates released from"
        " this commit, or count, the number of crates reproduced",
    )
    parser.add_argument(
        "--summary", metavar="FILE", help="file to add a markdown summary to"
    )
    status.add_repo_arguments(parser)
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    plan_parser = commands.add_parser("plan", help="show what a release publishes")
    plan_parser.add_argument("--json", action="store_true", help="print it as JSON")

    publish_parser = commands.add_parser(
        "publish", help="hand the crates to release to cargo publish"
    )
    publish_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="package and verify the crates, upload nothing",
    )
    publish_parser.add_argument(
        "--no-verify",
        action="store_true",
        help="do not build the crates, when a dry run did",
    )
    publish_parser.add_argument(
        "--index-timeout",
        type=int,
        default=900,
        metavar="SECONDS",
        help="how long to wait for the registry to list an uploaded crate",
    )

    reproduce_parser = commands.add_parser(
        "reproduce",
        help="package the released crates again and compare them with the registry",
    )
    reproduce_parser.add_argument(
        "--against",
        metavar="SHA256SUMS",
        help="compare with the crates of this file, written by `publish`, instead of"
        " the ones in the registry",
    )
    for command_parser in (publish_parser, reproduce_parser):
        command_parser.add_argument(
            "--output-dir",
            metavar="DIR",
            help="where to gather the crate files and their SHA256SUMS,"
            " defaults to release-crates in the target directory of cargo",
        )

    args = parser.parse_args()
    registry = status.open_repo(args)
    plan = Plan(registry, args.tag, args.rehearsal, args.allow_new_crates)

    if args.command == "plan" and args.json:
        print(json.dumps(plan.json(), indent=2))
    else:
        # A reproduction publishes nothing: the state of the crates says enough.
        plan.print(outcome=args.command != "reproduce")
    if args.command != "reproduce":
        outputs = {"publish": plan.selected, "released": plan.released}
        for name, reports in outputs.items():
            crates = json.dumps([report["crate"] for report in reports])
            append(args.github_output, f"{name}={crates}\n")
    if args.command == "plan" or plan.errors:
        append(args.summary, plan.markdown())
    if plan.errors:
        return 1

    if args.command == "publish":
        return publish(plan, args)
    if args.command == "reproduce":
        return reproduce(plan, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
