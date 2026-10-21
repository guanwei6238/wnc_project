use std::collections::HashSet;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

const OSRELEASE: &str = "/proc/sys/kernel/osrelease";
const PROC_MODULES: &str = "/proc/modules";
const MODULES_DIR: &str = "/lib/modules";
const MODULES_BUILTIN: &str = "modules.builtin";
const MODULES_DEP: &str = "modules.dep";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleState {
    Loaded,
    Builtin,
    Loadable,
    Missing,
    Unknown,
}

impl fmt::Display for ModuleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Loaded => "loaded",
            Self::Builtin => "built-in",
            Self::Loadable => "loadable",
            Self::Missing => "missing",
            Self::Unknown => "unknown",
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("failed to read {}: {source}", .path.display())]
pub struct ModulesError {
    path: PathBuf,
    source: io::Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleIndex {
    release: String,
    loaded: HashSet<String>,
    available: Option<Available>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Available {
    builtin: HashSet<String>,
    loadable: HashSet<String>,
}

impl ModuleIndex {
    pub fn load() -> Result<Self, ModulesError> {
        let release = read(Path::new(OSRELEASE))?;
        let proc_modules = read(Path::new(PROC_MODULES))?;
        let dir = Path::new(MODULES_DIR).join(release.trim());
        let builtin = std::fs::read_to_string(dir.join(MODULES_BUILTIN)).ok();
        let dep = std::fs::read_to_string(dir.join(MODULES_DEP)).ok();
        Ok(Self::from_parts(&release, &proc_modules, builtin.as_deref(), dep.as_deref()))
    }

    fn from_parts(release: &str, proc_modules: &str, builtin: Option<&str>, dep: Option<&str>) -> Self {
        let loaded = proc_modules
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .map(normalize)
            .collect();
        let available = match (builtin, dep) {
            (Some(builtin), Some(dep)) => Some(Available {
                builtin: builtin.lines().filter_map(module_name).collect(),
                loadable: dep
                    .lines()
                    .filter_map(|line| line.split(':').next())
                    .filter_map(module_name)
                    .collect(),
            }),
            _ => None,
        };
        Self {
            release: release.trim().to_owned(),
            loaded,
            available,
        }
    }

    pub fn release(&self) -> &str {
        &self.release
    }

    pub fn state(&self, name: &str) -> ModuleState {
        let name = normalize(name);
        if self.loaded.contains(&name) {
            return ModuleState::Loaded;
        }
        match &self.available {
            None => ModuleState::Unknown,
            Some(available) if available.builtin.contains(&name) => ModuleState::Builtin,
            Some(available) if available.loadable.contains(&name) => ModuleState::Loadable,
            Some(_) => ModuleState::Missing,
        }
    }
}

fn read(path: &Path) -> Result<String, ModulesError> {
    std::fs::read_to_string(path).map_err(|source| ModulesError {
        path: path.to_owned(),
        source,
    })
}

fn normalize(name: &str) -> String {
    name.replace('-', "_")
}

fn module_name(path: &str) -> Option<String> {
    let file = path.trim().rsplit('/').next()?;
    let (name, _) = file.split_once(".ko")?;
    (!name.is_empty()).then(|| normalize(name))
}

#[cfg(test)]
#[path = "../../tests/unit/kernel/modules.rs"]
mod tests;
