use log::{debug, info};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering::Relaxed;

pub type Environment = HashMap<&'static str, &'static str>;

#[allow(dead_code)]
pub fn execute(cmd: &str, env: Option<&Environment>, cwd: Option<&PathBuf>) -> Result<(), Error> {
    info!("Executing {}", cmd);
    debug!("Env {:?}", env);
    debug!("Cwd {:?}", cwd);
    if crate::DRY_RUN.load(Relaxed) {
        info!("Skipping execution because of --dry-run mode");
        return Ok(());
    }
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(cmd)
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit());
    if let Some(env) = env {
        for (key, val) in env.iter() {
            command.env(key, val);
        }
    }
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let output = command.output()?;
    if !output.status.success() {
        Err(Error::new(
            ErrorKind::Other,
            "Command exited with nonzero status.",
        ))
    } else {
        Ok(())
    }
}

pub fn project_root() -> PathBuf {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf()
}
