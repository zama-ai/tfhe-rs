//! Instantiate a new data generation crate for a version of TFHE-rs.

use cargo_toml::Manifest;
use clap::Parser;
use minijinja::Environment;
use semver::Version;
use serde::Serialize;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::{env, fs};

/// Relative dir where the templates are found from the Cargo.toml of this crate
const RELATIVE_TEMPLATE_PATH: &str = "template";

/// Relative dir where the generated crates must be stored from the Cargo.toml of this crate
const RELATIVE_CRATES_PATH: &str = "..";

/// Variables that should be replaced in the templates
#[derive(Serialize)]
struct TemplateVars {
    /// Short version: "1.4"
    tfhe_version_short: String,
    /// Complete version: "1.4.0"
    tfhe_version_exact: String,
    /// Short version with an underscore: "1_4"
    tfhe_version_underscored: String,
}

#[derive(Debug, Clone)]
struct CrateVersion(Version);

impl CrateVersion {
    fn exact(&self) -> String {
        format!("{}.{}.{}", self.0.major, self.0.minor, self.0.patch)
    }

    fn short(&self) -> String {
        format!("{}.{}", self.0.major, self.0.minor)
    }

    fn underscored(&self) -> String {
        format!("{}_{}", self.0.major, self.0.minor)
    }
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, value_parser = parse_version, help = "TFHE-rs version to instantiate, as <major.minor.patch> (e.g, '1.4.0')")]
    tfhe_version: CrateVersion,
}

fn parse_version(input: &str) -> Result<CrateVersion, String> {
    Version::parse(input)
        .map_err(|e| e.to_string())
        .map(CrateVersion)
}

/// Recursively processes a directory, rendering templates and copying files.
fn process_dir(
    env: &Environment,
    vars: &TemplateVars,
    template_dir: &Path,
    src_dir: &Path,
    crate_dir: &Path,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(crate_dir)?;

    for entry in fs::read_dir(src_dir)? {
        let entry = entry?;
        let src_path = entry.path();
        let dest_path = crate_dir.join(entry.file_name());

        if src_path.is_dir() {
            process_dir(env, vars, template_dir, &src_path, &dest_path)?;
        } else if src_path.is_file() {
            // Template files should be processed
            if src_path.extension().is_some_and(|s| s == "j2") {
                let mut dest_path_rendered = dest_path.clone();
                // Remove the extra ".j2" extension
                dest_path_rendered.set_extension("");

                println!(
                    "Rendering {} -> {}",
                    src_path.display(),
                    dest_path_rendered.display()
                );

                let template_name = src_path
                    .strip_prefix(template_dir)?
                    .to_str()
                    .ok_or("Invalid template path")?;

                let template = env.get_template(template_name)?;
                let rendered_content = template.render(vars)?;
                fs::write(&dest_path_rendered, rendered_content)?;
            } else {
                // Regular files are simply copied
                println!("Copying {} -> {}", src_path.display(), dest_path.display());
                fs::copy(&src_path, &dest_path)?;
            }
        }
    }

    Ok(())
}

/// Gets the list of previously implemented versions by parsing the crates directory
fn get_existing_versions(crates_dir: &Path) -> Result<Vec<CrateVersion>, Box<dyn Error>> {
    fs::read_dir(crates_dir)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .strip_prefix("generate_")
                .map(|s| s.replace("_", "."))
        })
        .flat_map(|version_str| {
            parse_version(&version_str)
                .map(|version| check_existing_version(crates_dir, version.clone()).map(|_| version))
        })
        .collect()
}

/// Returns an error if the previous version is still using a path in its Cargo.toml
fn check_existing_version(crates_dir: &Path, version: CrateVersion) -> Result<(), Box<dyn Error>> {
    let crate_name = format!("generate_{}", version.underscored());
    let previous_version_crate_dir = crates_dir.join(&crate_name);

    let manifest = Manifest::from_path(previous_version_crate_dir.join("Cargo.toml"))?;

    if manifest.dependencies["tfhe"]
        .detail()
        .ok_or(format!("Missing TFHE dependency in {crate_name}"))?
        .path
        .is_some()
    {
        return Err(format!(
            "{crate_name} is still using a path dependency for TFHE, please fix it and re-run this \
command.\n\n"
        )
        .into());
    }

    if manifest.dependencies["tfhe-versionable"]
        .detail()
        .ok_or(format!(
            "Missing tfhe-versionable dependency in {crate_name}"
        ))?
        .path
        .is_some()
    {
        return Err(format!(
            "{crate_name} is still using a path dependency for versionable, please fix it and \
re-run this command.\n\n"
        )
        .into());
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let tfhe_version_exact = args.tfhe_version.exact();
    let tfhe_version_underscored = args.tfhe_version.underscored();
    let crate_name = format!("generate_{}", tfhe_version_underscored);

    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let all_versions_dir = base_dir.join(RELATIVE_CRATES_PATH);
    let version_crate_dir = all_versions_dir.join(&crate_name);
    if version_crate_dir.exists() {
        return Err(format!(
            "Output directory '{}' already exists.",
            version_crate_dir.display()
        )
        .into());
    }

    for version in get_existing_versions(&all_versions_dir)? {
        check_existing_version(&all_versions_dir, version)?
    }

    println!(
        "Instantiating data generation crate '{}' for TFHE-rs version {}\n",
        crate_name, tfhe_version_exact
    );

    let vars = TemplateVars {
        tfhe_version_exact,
        tfhe_version_short: args.tfhe_version.short(),
        tfhe_version_underscored,
    };

    let template_dir = base_dir.join(RELATIVE_TEMPLATE_PATH);

    let mut env = Environment::new();
    env.set_keep_trailing_newline(true);
    env.set_loader(minijinja::path_loader(&template_dir));

    process_dir(
        &env,
        &vars,
        &template_dir,
        &template_dir,
        &version_crate_dir,
    )?;

    println!(
        "\nSuccessfully instantiated crate in '{}'\n
Now you can edit the `// <TODO>` comments to add the code to generate your data",
        version_crate_dir.display()
    );
    Ok(())
}
