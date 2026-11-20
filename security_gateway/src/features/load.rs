use std::io;
use std::path::{Path, PathBuf};

use super::check::{Problem, check};
use super::definition::{Definition, DefinitionError};
use super::elf::{Elf, ElfError, inspect};
use super::hook::Hook;

pub const MAX_PROGRAM_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error(transparent)]
    Definition(#[from] DefinitionError),
    #[error("failed to read feature program {}: {source}", .path.display())]
    Read { path: PathBuf, source: io::Error },
    #[error("feature program {} is larger than {MAX_PROGRAM_BYTES} bytes", .path.display())]
    TooLarge { path: PathBuf },
    #[error("feature program {}: {source}", .path.display())]
    Elf { path: PathBuf, source: ElfError },
}

#[derive(Debug)]
pub struct Loaded {
    pub definition: Definition,
    pub bytes: Vec<u8>,
    pub elf: Elf,
    pub problems: Vec<Problem>,
}

pub fn load(program: &Path, definition: &Path, entry: &str, hook: Hook) -> Result<Loaded, LoadError> {
    let definition = Definition::load(definition)?;
    let read = |source| LoadError::Read { path: program.to_path_buf(), source };
    if std::fs::metadata(program).map_err(read)?.len() > MAX_PROGRAM_BYTES {
        return Err(LoadError::TooLarge { path: program.to_path_buf() });
    }
    let bytes = std::fs::read(program).map_err(read)?;
    let elf = inspect(&bytes).map_err(|source| LoadError::Elf { path: program.to_path_buf(), source })?;
    let problems = check(&definition, &elf, entry, hook);
    Ok(Loaded { definition, bytes, elf, problems })
}
