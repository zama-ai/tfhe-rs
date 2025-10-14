use cargo_toml::Manifest;
use clap::Parser;
use rayon::prelude::*;
use semver::{Prerelease, Version, VersionReq};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn is_at_least_1_0(version: &Version) -> bool {
    let mut version = version.clone();

    // Removes the pre-release tag because matches will always return
    version.pre = Prerelease::EMPTY;

    let req = ">=1.0.0";
    let min_version = VersionReq::parse(req).unwrap();

    min_version.matches(&version)
}

fn is_at_most(version: &Version, maximum_version_inclusive: &str) -> bool {
    let mut version = version.clone();

    // Removes the pre-release tag because matches will always return
    version.pre = Prerelease::EMPTY;

    let req = format!("<={maximum_version_inclusive}");
    let max_version_inclusive_req = VersionReq::parse(&req).unwrap();

    max_version_inclusive_req.matches(&version)
}

fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
    fs::create_dir_all(&dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let ty = entry.file_type().unwrap();
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name())).unwrap();
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name())).unwrap();
        }
    }
    Ok(())
}

fn get_dir_paths_recursively(dir: impl AsRef<Path>) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut walk_errs = vec![];

    let dir = dir.as_ref();
    let dir_entries = WalkDir::new(dir)
        .into_iter()
        .flat_map(|e| match e {
            Ok(e) => Some(e.into_path()),
            Err(err) => {
                walk_errs.push(err);
                None
            }
        })
        .collect::<Vec<_>>();

    if walk_errs.is_empty() {
        Ok(dir_entries)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Encountered errors while walking dir {}: {walk_errs:#?}",
                dir.display()
            ),
        ))
    }
}

/// On a syn::ItemConst representing a parameter set:
/// - Normalize the param name to be version independent by removing the version prefix
/// - Ignore the doc comments, the reason being that they are used instead of comments as comments
///   get stripped by syn, but they could differ through versions, creating artificial differences
///   killing the deduplication possibility
fn normalize_const_param_item(
    param: &syn::ItemConst,
    param_name_prefix: &str,
) -> Option<syn::ItemConst> {
    let mut normalized_param = param.clone();
    let current_param_ident_string = normalized_param.ident.to_string();
    let current_param_normalized_ident_str =
        current_param_ident_string.strip_prefix(param_name_prefix)?;

    normalized_param.ident = syn::Ident::new(
        current_param_normalized_ident_str,
        normalized_param.ident.span(),
    );

    normalized_param.attrs.retain(|x| {
        let is_doc_attr = {
            match &x.meta {
                syn::Meta::NameValue(meta_name_value) => meta_name_value.path.is_ident("doc"),
                _ => false,
            }
        };

        !is_doc_attr
    });

    Some(normalized_param)
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    tfhe_path: PathBuf,
    #[arg(
        long,
        help = "The version to deduplicate, format : v1_0 for version 1.0.x"
    )]
    to_deduplicate: String,
}

const SUBDIRS_TO_DEDUP: [&str; 2] = ["classic", "multi_bit"];

fn main() {
    let args = Args::parse();
    let tfhe_path = args.tfhe_path;

    // Get TFHE-rs version
    let cargo_toml_path = tfhe_path.join("Cargo.toml");
    let tfhe_manifest = Manifest::from_path(&cargo_toml_path).unwrap();
    assert_eq!(tfhe_manifest.package().name(), "tfhe");
    let tfhe_version = tfhe_manifest.package().version();

    let shortint_parameters_mod = tfhe_path.join("src/shortint/parameters");

    let mut shortint_parameters_per_version = vec![];

    let shortint_parameters_content = fs::read_dir(&shortint_parameters_mod).unwrap();
    for dir_entry in shortint_parameters_content {
        let dir_entry = dir_entry.unwrap();
        let dir_entry_metadata = dir_entry.metadata().unwrap();
        if dir_entry_metadata.is_file() {
            // We are looking for directories with a certain naming pattern
            continue;
        }

        let dir_entry_name = dir_entry.file_name();
        let module_name = dir_entry_name
            .to_str()
            .ok_or("Could not convert DirEntry name to rust str.")
            .unwrap();

        let mut module_version = match module_name.strip_prefix('v') {
            Some(stripped) => stripped.replace("_", "."),
            None => continue,
        };

        if module_version.split('.').count() >= 3 {
            // Could be a temporary dedup directory left, lib parameters modules are of the form
            // vX_Y
            continue;
        }

        if module_version.split('.').count() < 3 {
            // Add the minor, otherwise parsing fails for the semver version stuff
            module_version.push_str(".0");
        }

        let module_version = Version::parse(&module_version).unwrap();

        if !is_at_least_1_0(&module_version) {
            continue;
        }

        if !is_at_most(&module_version, tfhe_version) {
            panic!("Found module {module_name}, that is more recent than TFHE-rs {tfhe_version}")
        }

        // Store all the parameter modules per version we will want to inspect
        shortint_parameters_per_version.push((module_version, dir_entry.path()));
    }

    shortint_parameters_per_version
        .sort_by(|(version_a, _dir_a), (version_b, _dir_b)| version_a.cmp(version_b));

    shortint_parameters_per_version
        .iter()
        .find(|(version, _dir)| {
            let version_as_str = format!("v{}_{}", version.major, version.minor);
            version_as_str == args.to_deduplicate
        })
        .unwrap_or_else(|| {
            panic!(
                "Could not find version to deduplicate: {}",
                args.to_deduplicate
            )
        });

    println!("All versions: {shortint_parameters_per_version:?}");

    let to_deduplicate_version_str = args
        .to_deduplicate
        .strip_prefix('v')
        .expect("Could not format to_deduplicate argument")
        .replace("_", ".")
        + ".0";
    let to_deduplicate_version = {
        let mut tmp = Version::parse(&to_deduplicate_version_str).unwrap();
        tmp.pre = Prerelease::EMPTY;
        tmp
    };

    let to_deduplicate_dir = shortint_parameters_per_version
        .iter()
        .find_map(|(version, dir)| {
            if version == &to_deduplicate_version {
                Some(dir.to_owned())
            } else {
                None
            }
        })
        .unwrap();

    // Keep all previous versions
    shortint_parameters_per_version.retain(|(version, _dir)| version < &to_deduplicate_version);

    println!("Versions for analysis: {shortint_parameters_per_version:?}");

    let mut param_version_and_associated_file_parameters: HashMap<_, HashSet<syn::ItemConst>> =
        shortint_parameters_per_version
            .iter()
            .map(|(version, _dir)| (version, HashSet::new()))
            .collect();

    for (version, shortint_param_dir) in shortint_parameters_per_version.iter() {
        let param_ident_prefix = shortint_param_dir
            .file_name()
            .ok_or("Could not get file name")
            .unwrap()
            .to_str()
            .ok_or("Could not convert OsStr to rust str.")
            .unwrap()
            .to_uppercase()
            + "_";

        // Deduplicate classic and multi bit only for now, they are the main source of redundancy
        for param_sub_dir in SUBDIRS_TO_DEDUP {
            let curr_param_dir = shortint_param_dir.join(param_sub_dir);

            let curr_param_dir_entries = get_dir_paths_recursively(curr_param_dir).unwrap();

            for dir_entry in curr_param_dir_entries {
                if dir_entry.metadata().unwrap().is_dir() {
                    continue;
                }

                let maybe_param_file = dir_entry;
                let content = fs::read_to_string(&maybe_param_file).unwrap();
                let syn_file = syn::parse_file(&content).unwrap();

                if syn_file
                    .items
                    .iter()
                    .all(|x| !matches!(x, syn::Item::Const(_)))
                {
                    // No item is a const declaration, so skip
                    continue;
                }

                println!("Found : {}", maybe_param_file.display());

                for item in syn_file.items {
                    if let syn::Item::Const(param) = item {
                        let ident_string = param.ident.to_string();

                        // If the expr is a path, it means it's already an alias, so skip the
                        // processing if that's the case
                        if ident_string.starts_with(&param_ident_prefix)
                            && !matches!(param.expr.as_ref(), &syn::Expr::Path(_))
                        {
                            println!("Processing: {ident_string}");
                        } else {
                            println!("Skipped: {ident_string}");
                            continue;
                        };

                        let original_param_ident = param.ident.clone();

                        let normalized_param =
                            normalize_const_param_item(&param, &param_ident_prefix).unwrap();

                        match param_version_and_associated_file_parameters.entry(version) {
                            Entry::Occupied(occupied_entry) => {
                                let version_parameters = occupied_entry.into_mut();
                                if !version_parameters.insert(normalized_param) {
                                    panic!("Duplicated parameter {original_param_ident}");
                                }
                            }
                            Entry::Vacant(_) => {
                                panic!("Uninitialized Entry for {version}",)
                            }
                        }
                    }
                }
            }
        }
    }

    let deduped_dir_orig = to_deduplicate_dir.with_file_name(
        to_deduplicate_dir
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
            + "_orig",
    );

    if deduped_dir_orig.exists() {
        std::fs::remove_dir_all(&deduped_dir_orig).unwrap();
    }

    copy_dir_all(&to_deduplicate_dir, &deduped_dir_orig).unwrap();

    let deduped_dir = &to_deduplicate_dir;

    let deduped_dir_entries = get_dir_paths_recursively(deduped_dir).unwrap();
    let current_param_prefix = format!(
        "V{}_{}_",
        to_deduplicate_version.major, to_deduplicate_version.minor
    );

    let formatting_toolchain = {
        let tmp = fs::read_to_string("toolchain.txt").unwrap();
        let tmp = tmp.trim();
        format!("+{tmp}")
    };

    let mut modified_files = vec![];

    for dir_entry in deduped_dir_entries {
        if dir_entry.metadata().unwrap().is_dir() {
            continue;
        }

        let file_to_process = dir_entry;
        let content = fs::read_to_string(&file_to_process).unwrap();
        let mut syn_file = syn::parse_file(&content).unwrap();

        let mut modified_item_count = 0;
        let mut param_types = HashSet::new();

        // Go backwards in versions to naturally find the most recent parameter set that may dedup
        for (old_version, old_dir) in shortint_parameters_per_version.iter().rev() {
            if old_version >= &to_deduplicate_version {
                // We need older parameters, so here skip this version
                continue;
            }

            let old_param_dir_name = old_dir.file_name().unwrap().to_str().unwrap();
            let old_param_prefix = format!("V{}_{}_", old_version.major, old_version.minor);
            // get the files for that version that have parameters
            if let Some(old_params) = param_version_and_associated_file_parameters.get(&old_version)
            {
                // Now check the items in the current file
                for item in syn_file.items.iter_mut() {
                    if let syn::Item::Const(param) = item {
                        param_types.insert(param.ty.clone());
                        let Some(current_normalized_param) =
                            normalize_const_param_item(param, &current_param_prefix)
                        else {
                            // If we can't normalize it it's not a parameter set
                            continue;
                        };

                        let current_normalized_param_ident_str =
                            current_normalized_param.ident.to_string();

                        // Does it exist and is it the same as the one in the version we are
                        // checking
                        if old_params.contains(&current_normalized_param) {
                            let old_param_path_expr = syn::parse_str(&format!(
                                    "crate::shortint::parameters::{old_param_dir_name}::{old_param_prefix}{current_normalized_param_ident_str}"
                                )).unwrap();

                            param.expr = Box::new(old_param_path_expr);

                            modified_item_count += 1;
                        }
                    }
                }
            }
        }

        // We check if all const items in the file already are assigned a path, meaning all are
        // already aliases
        let all_const_items_are_aliases = syn_file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Const(item_const) => Some(item_const),
                _ => None,
            })
            .all(|item_const| matches!(item_const.expr.as_ref(), &syn::Expr::Path(_)));

        // All const items have been mapped to old parameters, so we can remove all imports except
        // for the parameter types used in the file
        if all_const_items_are_aliases {
            // Remove all use statements
            syn_file.items.retain(|x| !matches!(x, syn::Item::Use(_)));

            let mut use_statement_as_string = String::new();
            use_statement_as_string += "use crate::shortint::parameters::{";
            for param_type in param_types {
                match &*param_type {
                    syn::Type::Path(type_path) => {
                        use_statement_as_string += &type_path.path.get_ident().unwrap().to_string();
                        use_statement_as_string += ",";
                    }
                    _ => panic!("Unsupported param type for use statement"),
                }
            }
            use_statement_as_string += "};";
            let use_statement: syn::Item = syn::parse_str(&use_statement_as_string).unwrap();
            syn_file.items.insert(0, use_statement);
        }

        if modified_item_count > 0 {
            let formatted = prettyplease::unparse(&syn_file);
            std::fs::write(&file_to_process, formatted).unwrap();
            modified_files.push(file_to_process);
        }
    }

    let fmt_res: Vec<_> = modified_files
        .par_iter()
        .map(|f| {
            (
                f,
                std::process::Command::new("cargo")
                    .args([&formatting_toolchain, "fmt", "--", &f.display().to_string()])
                    .status(),
            )
        })
        .collect();

    for (f, res) in fmt_res {
        if !res
            .unwrap_or_else(|_| panic!("Error while formatting {}", f.display()))
            .success()
        {
            panic!("Error while formatting {}", f.display());
        }
    }

    println!("All done! Result in {}", deduped_dir.display());
}
