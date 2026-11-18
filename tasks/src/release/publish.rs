//! Publish the crates released from the current commit with a single cargo run.
//!
//! Verifying and uploading are meant to be two runs: `publish --dry-run` builds every crate with
//! no registry token around, then `publish --no-verify` uploads them without building anything
//! while the token is there.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use clap::{Args, Subcommand};
use sha2::{Digest, Sha256};

use super::plan::{Plan, Planned, names};
use super::{Failure, Result, Target};

const CHECKSUMS: &str = "SHA256SUMS";
/// What ends the checksums in the outputs of a GitHub step, which hold them on several lines.
const CHECKSUMS_END: &str = "END_OF_SHA256SUMS";
/// Time between two looks at the index while waiting for a crate to show there.
const POLL: Duration = Duration::from_secs(5);

#[derive(Args)]
pub struct ReleaseArgs {
    /// Tag the release was asked from, which has to release a crate from the current commit
    #[arg(long, conflicts_with = "rehearsal")]
    tag: Option<String>,

    /// Select every crate that is not published yet, tagged or not, to check they could all be
    /// released from the current commit
    #[arg(long)]
    rehearsal: bool,

    /// Publish crates the registry has no version of, which a token obtained through trusted
    /// publishing is not allowed to do
    #[arg(long)]
    allow_new_crates: bool,

    /// File to write the outputs of a GitHub step to: `publish` and `released`, the JSON lists of
    /// the crates to publish and of the crates released from this commit, `checksums`, the
    /// SHA256SUMS of the crates packaged by `publish`, or `count`, the number of crates
    /// reproduced
    #[arg(long, value_name = "FILE")]
    github_output: Option<PathBuf>,

    /// File to add a markdown summary to
    #[arg(long, value_name = "FILE")]
    summary: Option<PathBuf>,

    #[command(flatten)]
    target: Target,

    #[command(subcommand)]
    command: ReleaseCommand,
}

#[derive(Subcommand)]
enum ReleaseCommand {
    /// Show what a release from the current commit publishes
    Plan {
        /// Print it as JSON
        #[arg(long)]
        json: bool,
    },
    /// Hand the crates to release to cargo publish
    Publish {
        /// Package and verify the crates, upload nothing
        #[arg(long)]
        dry_run: bool,

        /// Do not build the crates, when a dry run did
        #[arg(long)]
        no_verify: bool,

        /// How long to wait for the registry to list an uploaded crate
        #[arg(long, value_name = "SECONDS", default_value_t = 900)]
        index_timeout: u64,

        /// Where to gather the crate files and their SHA256SUMS, defaults to release-crates in
        /// the target directory of cargo
        #[arg(long, value_name = "DIR")]
        output_dir: Option<PathBuf>,
    },
    /// Package the released crates again and compare them with the registry
    Reproduce {
        /// Compare with the crates of this SHA256SUMS file, as `publish` writes it and gives it
        /// in its outputs, instead of the ones in the registry
        #[arg(long, value_name = "SHA256SUMS")]
        against: Option<PathBuf>,

        /// Where to gather the crate files and their SHA256SUMS, defaults to release-crates in
        /// the target directory of cargo
        #[arg(long, value_name = "DIR")]
        output_dir: Option<PathBuf>,
    },
}

fn error(message: &str) {
    eprintln!("error: {message}");
}

fn sha256(path: &Path) -> Result<String> {
    let content =
        fs::read(path).map_err(|error| Failure::new(format!("{}: {error}", path.display())))?;
    let digest = Sha256::digest(content);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Add `text` to the file at `path`, if any: how a step of a GitHub job reports.
fn append(path: Option<&Path>, text: &str) -> Result<()> {
    if let Some(path) = path {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        file.write_all(text.as_bytes())?;
    }
    Ok(())
}

/// `text` without the escape sequences coloring it.
fn without_colors(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        if character == '\x1b' {
            // Up to the letter ending the sequence.
            characters.find(|character| character.is_ascii_alphabetic());
        } else {
            plain.push(character);
        }
    }
    plain
}

/// Crates cargo reports as sent to the registry, in what it printed.
fn uploaded_crates(reported: &str) -> Vec<String> {
    let plain = without_colors(reported);
    plain
        .lines()
        .filter_map(|line| {
            // "Uploaded <crate> v<version> to registry ..."
            let mut words = line.trim_start().strip_prefix("Uploaded ")?.split(' ');
            let name = words.next()?;
            let sent = words.next()?.starts_with('v') && words.next()? == "to";
            sent.then(|| name.to_owned())
        })
        .collect()
}

/// Run `command`, showing what it reports as it comes.
///
/// Returns its exit code along with what it reported on its standard error, which is where cargo
/// tells what it does.
fn run(plan: &Plan, command: &[String]) -> Result<(i32, String)> {
    println!("+ {}", command.join(" "));
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .current_dir(&plan.repo.root)
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Failure::new(format!("could not run {}: {error}", command[0])))?;
    let mut lines = BufReader::new(child.stderr.take().expect("the error output is piped"));
    let mut reported = String::new();
    let mut line = Vec::new();
    while lines.read_until(b'\n', &mut line)? != 0 {
        let text = String::from_utf8_lossy(&line);
        eprint!("{text}");
        reported.push_str(&text);
        line.clear();
    }
    // Killed by a signal, a process has no exit code.
    Ok((child.wait()?.code().unwrap_or(1), reported))
}

/// Checksum the registry holds for each crate of `crates`, by crate name.
///
/// The index, often served from a cache, can take a while to show a version that was just
/// uploaded: the ones still missing after `timeout` are left out of the result.
fn wait_for_index(plan: &Plan, crates: &[&Planned], timeout: Duration) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    let deadline = Instant::now() + timeout;
    loop {
        let missing = |planned: &&&Planned| !found.contains_key(&planned.report.name);
        let pending: Vec<&Planned> = crates.iter().filter(missing).copied().collect();
        let asked: Vec<String> = names(&pending).into_iter().map(str::to_owned).collect();
        match plan.registry.fetch_published(&asked) {
            Ok(published) => {
                for planned in pending {
                    let report = &planned.report;
                    if let Some(checksum) = published[&report.name].get(&report.version) {
                        found.insert(report.name.clone(), checksum.clone());
                    }
                }
            }
            Err(reason) => eprintln!("could not reach {}: {reason}", plan.registry.index),
        }
        if found.len() == crates.len() || Instant::now() >= deadline {
            return found;
        }
        std::thread::sleep(POLL);
    }
}

/// Have cargo upload the selected crates, return 0 once they all are.
///
/// cargo gives up when the index takes more than a minute to show a crate that the next ones
/// depend on, which leaves the release half done. As long as a run uploaded something it is
/// worth running cargo again for what is left, once the index caught up: cargo refuses to
/// publish a version it cannot see is missing.
fn upload(plan: &Plan, options: &[&str], timeout: Duration) -> Result<i32> {
    let registry = &plan.registry.label;
    let mut remaining = plan.selected();
    loop {
        let (code, reported) = run(plan, &plan.cargo_publish(options, &remaining))?;
        if code == 0 {
            return Ok(0);
        }
        let uploaded = uploaded_crates(&reported);
        let sent = |planned: &&Planned| uploaded.contains(&planned.report.name);
        let (done, left): (Vec<&Planned>, Vec<&Planned>) = remaining.into_iter().partition(sent);
        if done.is_empty() {
            // Nothing went through: trying again would fail the same way.
            return Ok(code);
        }
        println!(
            "\ncargo stopped after uploading {}, waiting for {registry} to list them",
            names(&done).join(", ")
        );
        let visible = wait_for_index(plan, &done, timeout);
        let late: Vec<&Planned> = done
            .into_iter()
            .filter(|planned| !visible.contains_key(&planned.report.name))
            .collect();
        if !late.is_empty() {
            error(&format!(
                "{} still not listed by {registry} after {} seconds, run the release again \
                later: it resumes with what is left to publish",
                names(&late).join(", "),
                timeout.as_secs()
            ));
            return Ok(1);
        }
        if left.is_empty() {
            return Ok(0);
        }
        println!("resuming with {}", names(&left).join(", "));
        remaining = left;
    }
}

/// Check the registry holds, for each selected crate, the file packaged here.
fn check_published(plan: &Plan, timeout: Duration) -> Result<bool> {
    let registry = &plan.registry.label;
    let selected = plan.selected();
    let checksums = wait_for_index(plan, &selected, timeout);
    let mut published = true;
    for planned in selected {
        let id = planned.id();
        let local = sha256(&plan.crate_file(planned))?;
        match checksums.get(&planned.report.name) {
            None => {
                error(&format!("{id} is not listed by {registry}"));
                published = false;
            }
            Some(held) if held != &local => {
                error(&format!(
                    "{registry} holds another {id} than the one packaged here: {held} instead \
                    of {local}"
                ));
                published = false;
            }
            Some(_) => println!("{id} is on {registry}, sha256 {local}"),
        }
    }
    Ok(published)
}

/// Gather the crate files of `crates` in `directory` with their checksums, which are returned
/// the way they are written.
fn write_artifacts(plan: &Plan, crates: &[&Planned], directory: &Path) -> Result<String> {
    fs::create_dir_all(directory)?;
    // Whatever an earlier run left there is not part of this release.
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let is_crate = path
            .extension()
            .is_some_and(|extension| extension == "crate");
        if is_crate || path.file_name().is_some_and(|name| name == CHECKSUMS) {
            fs::remove_file(path)?;
        }
    }
    let mut checksums = String::new();
    for planned in crates {
        let source = plan.crate_file(planned);
        fs::copy(&source, directory.join(planned.file_name()))?;
        checksums += &format!("{}  {}\n", sha256(&source)?, planned.file_name());
    }
    let file = directory.join(CHECKSUMS);
    fs::write(&file, &checksums)?;
    print!("\n{}:\n{checksums}", file.display());
    Ok(checksums)
}

fn publish(
    plan: &Plan,
    dry_run: bool,
    no_verify: bool,
    timeout: Duration,
    output_directory: &Path,
    github_output: Option<&Path>,
    summary: Option<&Path>,
) -> Result<i32> {
    if plan.rehearsal && !dry_run {
        error("a rehearsal selects crates that are not tagged, it can only be a dry run");
        return Ok(1);
    }
    let selected = plan.selected();
    if selected.is_empty() {
        return Ok(0);
    }

    let verification: &[&str] = if no_verify { &["--no-verify"] } else { &[] };
    let code = if dry_run {
        let options = [&["--dry-run"], verification].concat();
        run(plan, &plan.cargo_publish(&options, &selected))?.0
    } else {
        upload(plan, verification, timeout)?
    };
    if code != 0 {
        return Ok(code);
    }
    if !dry_run && !check_published(plan, timeout)? {
        return Ok(1);
    }

    let checksums = write_artifacts(plan, &selected, output_directory)?;
    // For another job to check the crates it packages against these, with no file to hand over.
    let output = format!("checksums<<{CHECKSUMS_END}\n{checksums}{CHECKSUMS_END}\n");
    append(github_output, &output)?;
    if !dry_run {
        let registry = &plan.registry.label;
        let published = format!("### Published to {registry}\n\n```\n{checksums}```\n");
        append(summary, &published)?;
    }
    Ok(0)
}

/// File names of a SHA256SUMS file, with their checksum.
fn read_checksums(path: &Path) -> Result<BTreeMap<String, String>> {
    let content = fs::read_to_string(path)
        .map_err(|error| Failure::new(format!("{}: {error}", path.display())))?;
    let mut checksums = BTreeMap::new();
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let (Some(checksum), Some(name)) = (fields.next(), fields.next()) else {
            return Err(Failure::new(format!(
                "{}: not a checksum line: {line}",
                path.display()
            )));
        };
        // A star marks a file read in binary mode.
        let name = name.trim_start_matches('*');
        checksums.insert(name.to_owned(), checksum.to_owned());
    }
    Ok(checksums)
}

/// Package crates again and check they are the very files that were released.
///
/// Packaging is deterministic: a commit and a version of cargo always give the same crate file.
/// This is what lets a machine that took no part in the upload vouch for what is in the registry,
/// or, with `against`, for the files another machine packaged.
fn reproduce(
    plan: &Plan,
    against: Option<&Path>,
    output_directory: &Path,
    github_output: Option<&Path>,
) -> Result<i32> {
    let (expected, reference) = match against {
        Some(path) => (read_checksums(path)?, path.display().to_string()),
        None => {
            // Not only what this run published: an earlier run that stopped half way leaves
            // crates that were never vouched for.
            let released = plan
                .crates
                .iter()
                .filter(|planned| plan.tagged_here(planned));
            let expected = released
                .filter_map(|planned| Some((planned.file_name(), planned.report.checksum.clone()?)))
                .collect();
            (expected, plan.registry.label.clone())
        }
    };
    if against.is_some() && expected.is_empty() {
        // Comparing with nothing would vouch for anything.
        error(&format!("{reference} lists no crate file to compare with"));
        return Ok(1);
    }
    let listed = |planned: &&Planned| expected.contains_key(&planned.file_name());
    let crates: Vec<&Planned> = plan.crates.iter().filter(listed).collect();
    if crates.len() != expected.len() {
        let known: Vec<String> = crates.iter().map(|planned| planned.file_name()).collect();
        let unknown: Vec<&str> = expected
            .keys()
            .filter(|name| !known.contains(name))
            .map(String::as_str)
            .collect();
        error(&format!(
            "{reference} lists files this commit does not release: {}",
            unknown.join(", ")
        ));
        return Ok(1);
    }
    append(github_output, &format!("count={}\n", crates.len()))?;
    if crates.is_empty() {
        println!("Nothing to reproduce: {reference} has no crate from this commit.");
        return Ok(0);
    }

    // A dry run rather than `cargo package`, to package the way the release did. It only warns
    // about the versions that are published already.
    let command = plan.cargo_publish(&["--dry-run", "--no-verify"], &crates);
    let (code, _) = run(plan, &command)?;
    if code != 0 {
        return Ok(code);
    }
    let mut reproduced = true;
    for planned in &crates {
        let name = planned.file_name();
        let packaged = sha256(&plan.crate_file(planned))?;
        if packaged != expected[&name] {
            error(&format!(
                "{name} does not reproduce: {reference} has {}, packaging this commit gives \
                {packaged}",
                expected[&name]
            ));
            reproduced = false;
        }
    }
    if !reproduced {
        let cargo = Command::new("cargo")
            .arg("--version")
            .current_dir(&plan.repo.root)
            .output()?;
        error(&format!(
            "a crate file only depends on the commit and on the version of cargo packaging it, \
            which is {} here",
            String::from_utf8_lossy(&cargo.stdout).trim()
        ));
        return Ok(1);
    }
    println!("\nThe crates packaged from this commit are the ones of {reference}.");
    write_artifacts(plan, &crates, output_directory)?;
    Ok(0)
}

/// Plan, publish or reproduce the release of the current commit.
pub fn release(args: &ReleaseArgs) -> Result<i32> {
    let (repo, registry) = args.target.open()?;
    let plan = Plan::new(
        &repo,
        &registry,
        args.tag.as_deref(),
        args.rehearsal,
        args.allow_new_crates,
    )?;
    let github_output = args.github_output.as_deref();
    let summary = args.summary.as_deref();

    match &args.command {
        ReleaseCommand::Plan { json: true } => {
            println!("{}", serde_json::to_string_pretty(&plan.json())?);
        }
        // A reproduction publishes nothing: the state of the crates says enough.
        ReleaseCommand::Reproduce { .. } => plan.print(false),
        _ => plan.print(true),
    }
    if !matches!(args.command, ReleaseCommand::Reproduce { .. }) {
        let lists = [("publish", plan.selected()), ("released", plan.released())];
        for (output, crates) in lists {
            let crates = serde_json::to_string(&names(&crates))?;
            append(github_output, &format!("{output}={crates}\n"))?;
        }
    }
    let planning = matches!(args.command, ReleaseCommand::Plan { .. });
    if planning || !plan.errors.is_empty() {
        append(summary, &plan.markdown())?;
    }
    if !plan.errors.is_empty() {
        return Ok(1);
    }

    let default_output = plan.default_output_directory();
    match &args.command {
        ReleaseCommand::Plan { .. } => Ok(0),
        ReleaseCommand::Publish {
            dry_run,
            no_verify,
            index_timeout,
            output_dir,
        } => publish(
            &plan,
            *dry_run,
            *no_verify,
            Duration::from_secs(*index_timeout),
            output_dir.as_deref().unwrap_or(&default_output),
            github_output,
            summary,
        ),
        ReleaseCommand::Reproduce {
            against,
            output_dir,
        } => reproduce(
            &plan,
            against.as_deref(),
            output_dir.as_deref().unwrap_or(&default_output),
            github_output,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uploads_are_read_from_what_cargo_reports() {
        let reported = "\
   Uploading release-test-a v0.1.0 (/path/to/release-test-a)
    Uploaded release-test-a v0.1.0 to registry `test-mirror`
note: waiting for release-test-a v0.1.0 to be available at registry `test-mirror`.
\x1b[1m\x1b[92m    Uploaded\x1b[0m release-test-b v1.2.3-alpha.1 to registry `crates-io`
   Uploading release-test-c v0.1.0 (/path/to/release-test-c)
error: failed to publish release-test-c v0.1.0 to registry at http://127.0.0.1:1
";
        let uploaded = uploaded_crates(reported);
        assert_eq!(uploaded, ["release-test-a", "release-test-b"]);
    }

    #[test]
    fn colors_are_removed() {
        assert_eq!(
            without_colors("\x1b[1m\x1b[92mnote\x1b[0m: plain"),
            "note: plain"
        );
        assert_eq!(without_colors("plain"), "plain");
    }
}
