use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;

use crate::datapath::XdpPolicy;
use crate::forwarding::Mode;
use crate::ids::suricata;
use crate::kernel::nft;
use crate::ports::{PortSelector, PortSpec, Role};

pub const DEFAULT_PATH: &str = "/etc/wnc-gw/setting.toml";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    pub lan: Option<PortSelector>,
    pub wan: Option<PortSelector>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    CommandLine,
    File,
    Default,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CommandLine => "command line",
            Self::File => "config file",
            Self::Default => "default",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting<T> {
    pub value: T,
    pub source: Source,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbsolutePath(PathBuf);

impl AbsolutePath {
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl fmt::Display for AbsolutePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.display().fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid path {0:?} (expected an absolute path)")]
pub struct ParseAbsolutePathError(String);

impl FromStr for AbsolutePath {
    type Err = ParseAbsolutePathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with('/') {
            Ok(Self(PathBuf::from(s)))
        } else {
            Err(ParseAbsolutePathError(s.to_owned()))
        }
    }
}

impl<'de> Deserialize<'de> for AbsolutePath {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub file: Option<PathBuf>,
    pub mode: Setting<Mode>,
    pub xdp: Setting<XdpPolicy>,
    pub lan: Setting<PortSelector>,
    pub wan: Setting<PortSelector>,
    pub nftables: NftablesSettings,
    pub suricata: SuricataSettings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftablesSettings {
    pub path: Setting<AbsolutePath>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuricataSettings {
    pub path: Setting<AbsolutePath>,
    pub config: Setting<AbsolutePath>,
}

impl Config {
    pub fn ports(&self) -> [(Role, &Setting<PortSelector>); 2] {
        [(Role::Lan, &self.lan), (Role::Wan, &self.wan)]
    }

    pub fn port_specs(&self) -> Vec<PortSpec> {
        self.ports()
            .into_iter()
            .map(|(role, setting)| PortSpec {
                role,
                selector: setting.value.clone(),
            })
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {}: {source}", .path.display())]
    Read { path: PathBuf, source: io::Error },
    #[error("invalid config file {}: {message}", .path.display())]
    Parse { path: PathBuf, message: String },
    #[error("{role} port is not specified (set ports.{key} in the config file or pass --{key})", key = role_key(*.role))]
    Missing { role: Role },
}

fn role_key(role: Role) -> &'static str {
    match role {
        Role::Lan => "lan",
        Role::Wan => "wan",
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    mode: Option<Mode>,
    xdp: Option<XdpPolicy>,
    #[serde(default)]
    ports: FilePorts,
    #[serde(default)]
    nftables: FileNftables,
    #[serde(default)]
    suricata: FileSuricata,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilePorts {
    lan: Option<PortSelector>,
    wan: Option<PortSelector>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileNftables {
    path: Option<AbsolutePath>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSuricata {
    path: Option<AbsolutePath>,
    config: Option<AbsolutePath>,
}

pub fn load(path: Option<&Path>, overrides: Overrides) -> Result<Config, ConfigError> {
    match path {
        Some(path) => load_from(path.to_path_buf(), true, overrides),
        None => load_from(PathBuf::from(DEFAULT_PATH), false, overrides),
    }
}

fn load_from(path: PathBuf, required: bool, overrides: Overrides) -> Result<Config, ConfigError> {
    let (file, file_config) = match std::fs::read_to_string(&path) {
        Ok(text) => {
            let file_config = parse(&text).map_err(|message| ConfigError::Parse {
                path: path.clone(),
                message,
            })?;
            (Some(path), file_config)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound && !required => (None, FileConfig::default()),
        Err(source) => return Err(ConfigError::Read { path, source }),
    };
    merge(file, file_config, overrides)
}

fn parse(text: &str) -> Result<FileConfig, String> {
    toml::from_str(text).map_err(|e| e.to_string())
}

fn merge(file: Option<PathBuf>, file_config: FileConfig, overrides: Overrides) -> Result<Config, ConfigError> {
    let pick = |role, from_cli: Option<PortSelector>, from_file: Option<PortSelector>| {
        from_cli
            .map(|value| Setting {
                value,
                source: Source::CommandLine,
            })
            .or_else(|| {
                from_file.map(|value| Setting {
                    value,
                    source: Source::File,
                })
            })
            .ok_or(ConfigError::Missing { role })
    };
    Ok(Config {
        mode: file_or_default(file_config.mode),
        xdp: file_or_default(file_config.xdp),
        lan: pick(Role::Lan, overrides.lan, file_config.ports.lan)?,
        wan: pick(Role::Wan, overrides.wan, file_config.ports.wan)?,
        nftables: NftablesSettings {
            path: file_or_path(file_config.nftables.path, nft::DEFAULT_PATH),
        },
        suricata: SuricataSettings {
            path: file_or_path(file_config.suricata.path, suricata::DEFAULT_PATH),
            config: file_or_path(file_config.suricata.config, suricata::DEFAULT_CONFIG),
        },
        file,
    })
}

fn file_or_default<T: Default>(from_file: Option<T>) -> Setting<T> {
    match from_file {
        Some(value) => Setting {
            value,
            source: Source::File,
        },
        None => Setting {
            value: T::default(),
            source: Source::Default,
        },
    }
}

fn file_or_path(from_file: Option<AbsolutePath>, default: &str) -> Setting<AbsolutePath> {
    match from_file {
        Some(value) => Setting {
            value,
            source: Source::File,
        },
        None => Setting {
            value: AbsolutePath(PathBuf::from(default)),
            source: Source::Default,
        },
    }
}

#[cfg(test)]
#[path = "../tests/unit/config.rs"]
mod tests;
