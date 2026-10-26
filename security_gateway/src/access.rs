use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const PASSWD: &str = "/etc/passwd";
const GROUP: &str = "/etc/group";
const STICKY: u32 = 0o1000;
const GROUP_WRITE: u32 = 0o020;
const OTHER_WRITE: u32 = 0o002;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writer {
    User(u32),
    Group(u32),
    Everyone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Writable {
    pub path: PathBuf,
    pub writer: Writer,
}

// 檢查路徑上每一層目錄，也檢查跟著 symlink 之後的實際檔案和它的每一層目錄
pub fn non_root_writers(path: &Path) -> io::Result<Vec<Writable>> {
    let written = std::path::absolute(path)?;
    let real = fs::canonicalize(path)?;
    let mut found = Vec::new();
    for p in real.ancestors().chain(written.ancestors().skip(1)) {
        let metadata = fs::symlink_metadata(p)?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        for writer in writers(metadata.uid(), metadata.gid(), metadata.mode(), metadata.is_dir()) {
            let writable = Writable {
                path: p.to_path_buf(),
                writer,
            };
            if !found.contains(&writable) {
                found.push(writable);
            }
        }
    }
    Ok(found)
}

pub fn user_name(uid: u32) -> Option<String> {
    fs::read_to_string(PASSWD).ok().and_then(|text| name_of(&text, uid))
}

pub fn group_name(gid: u32) -> Option<String> {
    fs::read_to_string(GROUP).ok().and_then(|text| name_of(&text, gid))
}

fn writers(uid: u32, gid: u32, mode: u32, is_dir: bool) -> Vec<Writer> {
    let mut writers = Vec::new();
    if uid != 0 {
        writers.push(Writer::User(uid));
    }
    if is_dir && mode & STICKY != 0 {
        return writers;
    }
    if mode & GROUP_WRITE != 0 {
        writers.push(Writer::Group(gid));
    }
    if mode & OTHER_WRITE != 0 {
        writers.push(Writer::Everyone);
    }
    writers
}

fn name_of(text: &str, id: u32) -> Option<String> {
    text.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let found = fields.nth(1)?.parse::<u32>().ok()?;
        (found == id).then(|| name.to_owned())
    })
}

#[cfg(test)]
#[path = "../tests/unit/access.rs"]
mod tests;
