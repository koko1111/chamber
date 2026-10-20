use std::path::{Component, Path, PathBuf};

use crate::error::{ApiError, ApiResult};

const OUTSIDE: &str = "Path is outside the vault config directory";
const ESCAPES: &str = "Path escapes the vault config directory";

/// Directory that holds vault databases: `dirs::config_dir()/chamber`.
pub(crate) fn vault_config_dir() -> ApiResult<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| ApiError::InternalError("No config directory".to_string()))?;
    let dir = base.join("chamber");
    std::fs::create_dir_all(&dir)
        .map_err(|error| ApiError::InternalError(format!("Failed to create vault config directory: {error}")))?;
    dir.canonicalize()
        .map_err(|error| ApiError::InternalError(format!("Failed to resolve vault config directory: {error}")))
}

/// Accept `path` only when its canonical location stays inside the vault config directory.
///
/// `..` is rejected before canonicalization so a lexical escape cannot be normalized back in.
pub(crate) fn confine_to_vault_config(path: &Path) -> ApiResult<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(ApiError::BadRequest(OUTSIDE.to_string()));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ApiError::BadRequest(ESCAPES.to_string()));
    }

    let config_dir = vault_config_dir()?;
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_dir.join(path)
    };
    let resolved = canonicalize_partial(&candidate).map_err(|_| ApiError::BadRequest(OUTSIDE.to_string()))?;
    if !resolved.starts_with(&config_dir) {
        return Err(ApiError::BadRequest(OUTSIDE.to_string()));
    }
    Ok(resolved)
}

/// Canonicalize the longest existing ancestor and append the remainder.
///
/// Export and vault-create targets often do not exist yet, so `Path::canonicalize`
/// on the full path would fail even for an allowed location.
fn canonicalize_partial(path: &Path) -> std::io::Result<PathBuf> {
    let mut pending = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        if current.exists() {
            let mut resolved = current.canonicalize()?;
            for part in pending.iter().rev() {
                resolved.push(part);
            }
            return Ok(resolved);
        }
        let Some(name) = current.file_name().map(std::ffi::OsStr::to_os_string) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "path has no existing ancestor",
            ));
        };
        pending.push(name);
        match current.parent() {
            Some(parent) if parent != current && !parent.as_os_str().is_empty() => {
                current = parent.to_path_buf();
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "path has no existing ancestor",
                ));
            }
        }
    }
}
