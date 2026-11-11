//! File helpers for the few things we write: all private to the user, never through a
//! symlink, and replaced atomically.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use rustix::fs::OFlags;

use crate::error::{IoContext, Result};

/// Create `dir` (and parents) if needed and make sure only the owner can enter it.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .io_context(format!("creating {}", dir.display()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .io_context(format!("securing {}", dir.display()))
}

fn nofollow() -> i32 {
    // The flag value fits an i32 on every Linux target.
    OFlags::NOFOLLOW.bits() as i32
}

/// Replace `path` with `contents`: written to a new private file next to it, synced, then
/// renamed over the old one.
pub fn write_private_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    ensure_private_dir(dir)?;
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).map_err(|e| crate::error::Error::Io {
        context: "getting random bytes".into(),
        source: std::io::Error::other(e.to_string()),
    })?;
    let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(".{name}.{hex}.tmp"));

    let write = || -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nofollow())
            .open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    };
    write()
        .inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })
        .io_context(format!("writing {}", path.display()))
}

/// Append one line to a private file, creating it if needed.
pub fn append_private(path: &Path, line: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        ensure_private_dir(dir)?;
    }
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(nofollow())
        .open(path)
        .io_context(format!("opening {}", path.display()))?;
    file.write_all(line.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .io_context(format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn atomic_write_is_private_and_replaces() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sub/config.toml");
        write_private_atomic(&path, b"one").expect("first write");
        write_private_atomic(&path, b"two").expect("second write");
        assert_eq!(fs::read(&path).expect("read"), b"two");
        assert_eq!(fs::metadata(&path).expect("meta").mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(path.parent().expect("parent"))
                .expect("meta")
                .mode()
                & 0o777,
            0o700
        );
        let leftovers = fs::read_dir(path.parent().expect("parent"))
            .expect("list")
            .count();
        assert_eq!(leftovers, 1);
    }

    #[test]
    fn append_refuses_symlinks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target");
        fs::write(&target, b"").expect("target");
        let link = dir.path().join("log");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(append_private(&link, "x").is_err());
        assert_eq!(fs::read(&target).expect("read"), b"");
    }

    #[test]
    fn append_adds_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("log");
        append_private(&path, "a").expect("a");
        append_private(&path, "b").expect("b");
        assert_eq!(fs::read_to_string(&path).expect("read"), "a\nb\n");
    }
}
