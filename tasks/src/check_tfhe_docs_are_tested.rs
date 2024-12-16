use no_comment::{languages, IntoWithoutComments};
use std::collections::HashSet;
use std::io::{Error, ErrorKind};

// TODO use .gitignore or git to resolve ignored files
const DIR_TO_IGNORE: [&str; 3] = [
    ".git",
    "target",
    // If the data repo has been cloned, we ignore its README
    "tests/tfhe-backward-compat-data",
];

const FILES_TO_IGNORE: [&str; 6] = [
    // This contains fragments of code that are unrelated to TFHE-rs
    "tfhe/docs/tutorials/sha256_bool.md",
    // TODO: This contains code that could be executed as a trivium docstring
    "apps/trivium/README.md",
    // TODO: should we test this ?
    "utils/tfhe-versionable/README.md",
    // TODO: find a way to test the tfhe-fft readme
    "tfhe-fft/README.md",
    // TODO: find a way to test the tfhe-ntt readme
    "tfhe-ntt/README.md",
    "utils/tfhe-lints/README.md",
];

pub fn check_tfhe_docs_are_tested() -> Result<(), Error> {
    let curr_dir = std::env::current_dir()?;
    let tfhe_src = curr_dir.join("tfhe/src");
    let test_user_doc_file = tfhe_src.join("test_user_docs.rs");

    if !test_user_doc_file.exists() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!(
                "{} does not exist, \
                did you launch the command from the repo root?",
                test_user_doc_file.display()
            ),
        ));
    }

    // Find files which are tested
    let file_content = std::fs::read_to_string(&test_user_doc_file)?;

    let file_content = file_content
        .chars()
        .without_comments(languages::rust())
        .collect::<String>();

    let mut file_content = file_content.as_str();

    let mut tested_files = HashSet::new();

    while let Some(doctest_macro_invocation) = file_content.find("doctest!(") {
        file_content = &file_content[doctest_macro_invocation + 9..];

        let opening_quote = file_content
            .find('"')
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "Could not find opening quote"))?;

        file_content = &file_content[opening_quote + 1..];

        let closing_quote = file_content
            .find('"')
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "Could not find closing quote"))?;

        let tested_file_name = &file_content[..closing_quote];

        file_content = &file_content[tested_file_name.len() + 1..];

        let mut tested_file_path = tfhe_src.join(tested_file_name);

        if tested_file_path.exists() {
            tested_file_path = tested_file_path.canonicalize().unwrap();
        }

        tested_files.insert(tested_file_path);
    }

    let mut walk_errs = vec![];

    let dir_entries = walkdir::WalkDir::new(&curr_dir)
        .into_iter()
        .flat_map(|e| match e {
            Ok(e) => Some(e),
            Err(err) => {
                walk_errs.push(err);
                None
            }
        })
        .collect::<Vec<_>>();

    if !walk_errs.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Encountered errors while walking repo: {walk_errs:#?}"),
        ));
    }

    let mut doc_files: HashSet<_> = dir_entries
        .into_iter()
        .filter_map(|entry| {
            let path = entry.path().canonicalize().ok()?;
            if path.is_file() && path.extension().is_some_and(|e| e == "md") {
                let file_content = std::fs::read_to_string(&path).ok()?;
                if file_content.contains("```rust") {
                    Some(path.to_path_buf())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    for dir_to_remove in DIR_TO_IGNORE {
        let path_to_remove = curr_dir.join(dir_to_remove);
        doc_files.retain(|v| !v.starts_with(&path_to_remove));
    }

    for value_to_remove in FILES_TO_IGNORE {
        let path_to_remove = curr_dir.join(value_to_remove).canonicalize()?.to_path_buf();
        doc_files.remove(&path_to_remove);
    }

    let difference = doc_files.difference(&tested_files);

    let debug_format = format!("missing file from user doc tests: {difference:#?}");

    if difference.count() != 0 {
        return Err(Error::new(ErrorKind::NotFound, debug_format));
    }

    Ok(())
}
