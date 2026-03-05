use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::{Context, Result};

/// Directory for quictun runtime state (PID files).
pub fn runtime_dir() -> PathBuf {
    if cfg!(target_os = "linux") {
        PathBuf::from("/run/quictun")
    } else {
        std::env::temp_dir().join("quictun")
    }
}

fn validate_interface_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.contains('\0')
    {
        anyhow::bail!(
            "invalid interface name: must not contain path separators, '..', or null bytes"
        );
    }
    Ok(())
}

/// Write the current process PID to `<runtime_dir>/<name>.pid`.
pub fn write_pid_file(name: &str) -> Result<PathBuf> {
    validate_interface_name(name)?;
    let dir = runtime_dir();
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create runtime dir {}", dir.display()))?;

    let path = dir.join(format!("{name}.pid"));
    fs::write(&path, std::process::id().to_string())
        .with_context(|| format!("failed to write PID file {}", path.display()))?;

    tracing::debug!(path = %path.display(), "wrote PID file");
    Ok(path)
}

/// Read a PID from `<runtime_dir>/<name>.pid`. Returns `None` if the file
/// does not exist.
pub fn read_pid_file(name: &str) -> Result<Option<u32>> {
    validate_interface_name(name)?;
    let path = runtime_dir().join(format!("{name}.pid"));
    match fs::read_to_string(&path) {
        Ok(contents) => {
            let pid = contents
                .trim()
                .parse::<u32>()
                .with_context(|| format!("invalid PID in {}", path.display()))?;
            Ok(Some(pid))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
    }
}

/// Remove the PID file for `name` (best-effort).
pub fn remove_pid_file(name: &str) {
    let path = runtime_dir().join(format!("{name}.pid"));
    if let Err(e) = fs::remove_file(&path)
        && e.kind() != ErrorKind::NotFound
    {
        tracing::warn!(path = %path.display(), error = %e, "failed to remove PID file");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_interface_name_rejects_traversal() {
        assert!(validate_interface_name("../etc/passwd").is_err());
        assert!(validate_interface_name("foo/bar").is_err());
        assert!(validate_interface_name("foo\\bar").is_err());
        assert!(validate_interface_name("").is_err());
        assert!(validate_interface_name("foo\0bar").is_err());
    }

    #[test]
    fn validate_interface_name_accepts_valid() {
        assert!(validate_interface_name("quictun0").is_ok());
        assert!(validate_interface_name("wg-tunnel").is_ok());
        assert!(validate_interface_name("my.iface").is_ok());
    }
}

/// RAII guard that removes the PID file on drop.
pub struct PidFileGuard {
    name: String,
}

impl PidFileGuard {
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        remove_pid_file(&self.name);
    }
}
