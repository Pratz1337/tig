//! Directory-entry durability after metadata renames and removals.

use std::io;
use std::path::Path;

pub fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    #[cfg(windows)]
    let directory = {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_BACKUP_SEMANTICS opens a directory. FlushFileBuffers
        // requires a writable handle; read-only directory handles are denied.
        std::fs::OpenOptions::new().write(true).custom_flags(0x02000000).open(parent)?
    };
    #[cfg(not(windows))]
    let directory = std::fs::File::open(parent)?;
    directory.sync_all()
}
