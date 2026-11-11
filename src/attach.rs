//! Files crossing the boundary between the mailbox and the disk.
//!
//! Reading (to attach): only regular files inside the folders the policy allows, never
//! hidden files, and opened in a way the kernel guarantees involves no symbolic link.
//!
//! Writing (saving attachments): only inside one private folder, with a cleaned-up file
//! name, never overwriting anything, and never executable.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};

use crate::error::{Error, IoContext, Result};
use crate::fsutil::ensure_private_dir;
use crate::sanitize::safe_filename;

/// A local file read for attaching to an outgoing message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFile {
    /// The real path that was read (symlinks resolved), shown to the user for approval.
    pub path: PathBuf,
    pub name: String,
    pub content_type: &'static str,
    pub data: Vec<u8>,
}

/// Read `requested` for attaching. `budget` is how many bytes may still be attached and is
/// reduced by the size of the file.
pub fn load(
    requested: &str,
    allowed: &[PathBuf],
    home: &Path,
    budget: &mut u64,
) -> Result<LocalFile> {
    let outside = || {
        let folders: Vec<String> = allowed.iter().map(|p| p.display().to_string()).collect();
        Error::denied(format!(
            "'{requested}' cannot be attached: files may only be attached from {}",
            if folders.is_empty() {
                "(no folders are allowed)".to_owned()
            } else {
                folders.join(", ")
            }
        ))
    };

    let expanded = match requested.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => PathBuf::from(requested),
    };
    if !expanded.is_absolute() {
        return Err(Error::invalid(format!(
            "Attachment path '{requested}' must be absolute or start with ~/"
        )));
    }
    // Resolve symlinks first, then judge the real location.
    let real = fs::canonicalize(&expanded)
        .map_err(|_| Error::invalid(format!("No such file: {requested}")))?;
    let root = allowed
        .iter()
        .find(|root| real.starts_with(root))
        .ok_or_else(outside)?;
    let inside = real.strip_prefix(root).map_err(|_| outside())?;
    let hidden = inside.components().any(|c| match c {
        Component::Normal(part) => part.to_string_lossy().starts_with('.'),
        _ => true,
    });
    if hidden || inside.as_os_str().is_empty() {
        return Err(Error::denied(format!(
            "Hidden files and folders cannot be attached: {requested}"
        )));
    }

    // Open the resolved path while forbidding symlinks in every component. If anything was
    // swapped for a link after the check above, the kernel refuses the open.
    let fd = openat2(
        CWD,
        &real,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|e| Error::invalid(format!("Cannot open {requested}: {e}")))?;
    let file = File::from(fd);
    let meta = file
        .metadata()
        .io_context(format!("checking {requested}"))?;
    if !meta.is_file() {
        return Err(Error::invalid(format!("Not a regular file: {requested}")));
    }
    if meta.len() > *budget {
        return Err(Error::invalid("Attachments are limited to 25 MB in total"));
    }
    // Read at most the remaining budget (+1 to notice a file that grew after the check).
    let mut data = Vec::with_capacity(meta.len() as usize);
    file.take(*budget + 1)
        .read_to_end(&mut data)
        .io_context(format!("reading {requested}"))?;
    if data.len() as u64 > *budget {
        return Err(Error::invalid("Attachments are limited to 25 MB in total"));
    }
    *budget -= data.len() as u64;

    let name = real
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(LocalFile {
        content_type: content_type_for(&name),
        name,
        path: real,
        data,
    })
}

/// A MIME type from the file extension. Unknown types are sent as generic binary.
pub fn content_type_for(name: &str) -> &'static str {
    let extension = name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "pdf" => "application/pdf",
        "txt" | "log" | "md" => "text/plain",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "json" => "application/json",
        "xml" => "application/xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "heic" => "image/heic",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "7z" => "application/x-7z-compressed",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "ics" => "text/calendar",
        "eml" => "message/rfc822",
        _ => "application/octet-stream",
    }
}

/// Save one attachment under `root` (optionally in a single sub-folder of it) and return
/// where it went. An existing file is never replaced; a numbered name is used instead.
pub fn save(root: &Path, subfolder: Option<&str>, filename: &str, data: &[u8]) -> Result<PathBuf> {
    ensure_private_dir(root)?;
    let real_root = fs::canonicalize(root).io_context(format!("resolving {}", root.display()))?;
    let dir = match subfolder.map(str::trim).filter(|s| !s.is_empty()) {
        Some(sub) => {
            let dir = real_root.join(safe_filename(sub));
            ensure_private_dir(&dir)?;
            dir
        }
        None => real_root.clone(),
    };
    // The sub-folder might already exist as a link to somewhere else: refuse to follow it.
    let real_dir = fs::canonicalize(&dir).io_context(format!("resolving {}", dir.display()))?;
    if !real_dir.starts_with(&real_root) {
        return Err(Error::denied(
            "The attachment folder points outside ~/Downloads/mail-attachments",
        ));
    }

    let safe = safe_filename(filename);
    let (stem, extension) = match safe.rfind('.') {
        Some(idx) if idx > 0 => (&safe[..idx], &safe[idx..]),
        _ => (safe.as_str(), ""),
    };
    for attempt in 0..1000 {
        let name = if attempt == 0 {
            safe.clone()
        } else {
            format!("{stem} ({attempt}){extension}")
        };
        let path = real_dir.join(name);
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
            .open(&path);
        match opened {
            Ok(mut file) => {
                file.write_all(data)
                    .io_context(format!("writing {}", path.display()))?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).io_context(format!("creating {}", path.display())),
        }
    }
    Err(Error::invalid(
        "Too many files with that name already exist",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};

    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
        allowed: Vec<PathBuf>,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = fs::canonicalize(dir.path()).expect("canon");
        let docs = home.join("Documents");
        fs::create_dir_all(docs.join("sub")).expect("mkdir");
        fs::create_dir_all(docs.join(".private")).expect("mkdir");
        fs::create_dir_all(home.join(".ssh")).expect("mkdir");
        fs::write(docs.join("report.pdf"), b"%PDF-1").expect("write");
        fs::write(docs.join("sub/notes.txt"), b"notes").expect("write");
        fs::write(docs.join(".env"), b"SECRET=1").expect("write");
        fs::write(docs.join(".private/x.txt"), b"x").expect("write");
        fs::write(home.join(".ssh/id_ed25519"), b"KEY").expect("write");
        Fixture {
            _dir: dir,
            allowed: vec![docs],
            home,
        }
    }

    #[test]
    fn allowed_files_load_with_type_and_real_path() {
        let f = fixture();
        let mut budget = 1000;
        let file = load("~/Documents/report.pdf", &f.allowed, &f.home, &mut budget).expect("load");
        assert_eq!(
            (file.name.as_str(), file.content_type, file.data.as_slice()),
            ("report.pdf", "application/pdf", &b"%PDF-1"[..])
        );
        assert_eq!(file.path, f.home.join("Documents/report.pdf"));
        assert_eq!(budget, 994);
        assert!(
            load(
                "~/Documents/sub/notes.txt",
                &f.allowed,
                &f.home,
                &mut budget
            )
            .is_ok()
        );
    }

    #[test]
    fn files_outside_the_allowed_folders_are_refused() {
        let f = fixture();
        let mut budget = 1000;
        for path in [
            "~/.ssh/id_ed25519",
            "/etc/passwd",
            "~/Documents/../.ssh/id_ed25519",
            "relative.txt",
        ] {
            assert!(
                load(path, &f.allowed, &f.home, &mut budget).is_err(),
                "{path}"
            );
        }
        assert_eq!(budget, 1000);
    }

    #[test]
    fn hidden_files_and_folders_are_refused() {
        let f = fixture();
        let mut budget = 1000;
        assert!(load("~/Documents/.env", &f.allowed, &f.home, &mut budget).is_err());
        assert!(
            load(
                "~/Documents/.private/x.txt",
                &f.allowed,
                &f.home,
                &mut budget
            )
            .is_err()
        );
    }

    #[test]
    fn symlinks_that_escape_are_refused() {
        let f = fixture();
        symlink(
            f.home.join(".ssh/id_ed25519"),
            f.home.join("Documents/innocent.txt"),
        )
        .expect("symlink");
        symlink(f.home.join(".ssh"), f.home.join("Documents/folder")).expect("symlink");
        let mut budget = 1000;
        assert!(load("~/Documents/innocent.txt", &f.allowed, &f.home, &mut budget).is_err());
        assert!(
            load(
                "~/Documents/folder/id_ed25519",
                &f.allowed,
                &f.home,
                &mut budget
            )
            .is_err()
        );
    }

    #[test]
    fn directories_and_oversized_files_are_refused() {
        let f = fixture();
        let mut budget = 1000;
        assert!(load("~/Documents/sub", &f.allowed, &f.home, &mut budget).is_err());
        let mut small = 3;
        assert!(load("~/Documents/report.pdf", &f.allowed, &f.home, &mut small).is_err());
        assert_eq!(small, 3);
    }

    #[test]
    fn saved_files_are_private_renamed_and_never_overwritten() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("mail-attachments");
        let first = save(&root, None, "../../evil.sh", b"one").expect("save");
        let second = save(&root, None, "evil.sh", b"two").expect("save");
        assert_eq!(first.file_name().and_then(|n| n.to_str()), Some("evil.sh"));
        assert_eq!(
            second.file_name().and_then(|n| n.to_str()),
            Some("evil (1).sh")
        );
        assert!(first.starts_with(fs::canonicalize(&root).expect("canon")));
        assert_eq!(fs::read(&first).expect("read"), b"one");
        assert_eq!(fs::metadata(&first).expect("meta").mode() & 0o777, 0o600);
    }

    #[test]
    fn subfolder_stays_inside_the_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("mail-attachments");
        let saved = save(&root, Some("../../outside"), "a.txt", b"x").expect("save");
        assert!(saved.starts_with(fs::canonicalize(&root).expect("canon")));
        assert_eq!(
            saved
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str()),
            Some("outside")
        );
    }

    #[test]
    fn subfolder_that_is_a_link_elsewhere_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("mail-attachments");
        let elsewhere = dir.path().join("elsewhere");
        fs::create_dir_all(&root).expect("mkdir");
        fs::create_dir_all(&elsewhere).expect("mkdir");
        symlink(&elsewhere, root.join("link")).expect("symlink");
        assert!(save(&root, Some("link"), "a.txt", b"x").is_err());
        assert_eq!(fs::read_dir(&elsewhere).expect("list").count(), 0);
    }
}
