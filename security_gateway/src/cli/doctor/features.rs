use security_gateway::config::{Config, FeatureSettings, ports::Port};
use security_gateway::features::{
    check::Problem,
    definition::{Definition, Derived, Layout, Op},
    hook::{Hook, XdpMode},
    load::{self, LoadError, Loaded},
};
use security_gateway::issue::Issue;
use security_gateway::kernel::netdev::Netdev;

use super::{Finding, Severity};

pub(super) async fn check_features(config: &Config, ports: &[Port]) -> Vec<Finding> {
    if config.features.is_empty() {
        out!("features: none");
        return Vec::new();
    }
    let mut findings = xdp_conflicts(&config.features, ports);
    for feature in &config.features {
        findings.extend(check_one(feature, ports).await);
    }
    findings
}

/// A port holds one XDP program at a time (native and generic cannot both be attached either),
/// so a second one fails with EEXIST when run attaches it.
fn xdp_conflicts(features: &[FeatureSettings], ports: &[Port]) -> Vec<Finding> {
    let xdp: Vec<&str> = features.iter().filter(|f| matches!(f.hook, Hook::Xdp(_))).map(|f| f.name.as_str()).collect();
    let mut findings = Vec::new();
    if xdp.len() > 1 {
        findings.push(Finding {
            severity: Severity::Error,
            issue: Issue::FeatureXdpConflict,
            message: format!(
                "features {} all use hook = \"xdp\", but a port holds only one XDP program; merge them into one \
                 program or move the others to tc-ingress or tc-egress",
                xdp.join(", ")
            ),
        });
    }
    if !xdp.is_empty() {
        for port in ports {
            if let Some(attached) = port.interface.xdp {
                let program = attached.prog_id.map_or("an XDP program".to_string(), |id| format!("XDP program {id}"));
                findings.push(Finding {
                    severity: Severity::Error,
                    issue: Issue::FeatureXdpConflict,
                    message: format!(
                        "feature {}: {} ({}) already has {program} attached, so another one cannot be attached",
                        xdp[0], port.role, port.interface.name
                    ),
                });
            }
        }
    }
    findings
}

async fn check_one(feature: &FeatureSettings, ports: &[Port]) -> Vec<Finding> {
    out!(
        "feature {}: {} (entry {}, hook {}), definition {}, read every {} s",
        feature.name,
        feature.program,
        feature.entry,
        feature.hook,
        feature.definition,
        feature.interval.as_secs()
    );
    let name = &feature.name;
    let mut findings = match load::load(feature.program.as_path(), feature.definition.as_path(), &feature.entry, feature.hook) {
        Ok(loaded) => {
            print_loaded(&loaded);
            problem_findings(name, &loaded.problems)
        }
        Err(e) => {
            let issue = match e {
                LoadError::Definition(_) => Issue::FeatureDefinitionInvalid,
                _ => Issue::FeatureProgramInvalid,
            };
            vec![Finding { severity: Severity::Error, issue, message: format!("feature {name}: {e}") }]
        }
    };
    findings.extend(xdp_findings(name, feature.hook, ports).await);
    findings
}

pub(super) fn problem_findings(name: &str, problems: &[Problem]) -> Vec<Finding> {
    problems
        .iter()
        .map(|problem| {
            let (severity, issue) = match problem {
                Problem::EntryMissing { .. } | Problem::EntryWrongKind { .. } => (Severity::Error, Issue::FeatureEntry),
                Problem::MapMissing { .. } | Problem::MapUnsupported { .. } => (Severity::Error, Issue::FeatureMap),
                Problem::Shape(_) => (Severity::Error, Issue::FeatureShape),
                Problem::BtfMismatch { .. } => (Severity::Error, Issue::FeatureBtfMismatch),
                Problem::NoBtf(_) => (Severity::Warning, Issue::FeatureNoBtf),
                Problem::Undescribed { .. } => (Severity::Note, Issue::FeatureUndescribed),
            };
            Finding { severity, issue, message: format!("feature {name}: {problem}") }
        })
        .collect()
}

async fn xdp_findings(name: &str, hook: Hook, ports: &[Port]) -> Vec<Finding> {
    match hook {
        Hook::Xdp(XdpMode::Generic) => vec![Finding {
            severity: Severity::Warning,
            issue: Issue::FeatureXdpGeneric,
            message: format!("feature {name}: xdp_mode = \"generic\" turns off GRO on every port it is attached to"),
        }],
        Hook::Xdp(XdpMode::Native) => {
            let netdev = Netdev::connect();
            let mut findings = Vec::new();
            for port in ports {
                let native = match &netdev {
                    Ok(netdev) => netdev.xdp_features(port.interface.index).await.map(|f| f.basic()).map_err(|e| e.to_string()),
                    Err(e) => Err(e.to_string()),
                };
                let (role, iface) = (port.role, &port.interface.name);
                let reason = match native {
                    Ok(true) => continue,
                    Ok(false) => "has no native XDP".to_string(),
                    Err(e) => format!("native XDP support cannot be detected ({e})"),
                };
                findings.push(Finding {
                    severity: Severity::Error,
                    issue: Issue::FeatureXdpNative,
                    message: format!(
                        "feature {name}: {role} ({iface}) {reason}; use a TC program or set xdp_mode = \"generic\""
                    ),
                });
            }
            findings
        }
        Hook::TcIngress | Hook::TcEgress => Vec::new(),
    }
}

fn print_loaded(loaded: &Loaded) {
    let def = &loaded.definition;
    match loaded.elf.maps.get(&def.map) {
        Some(info) if info.kind.is_events() => out!(
            "  map {}: ringbuf, {} bytes, {}",
            def.map,
            info.max_entries,
            match info.value_size {
                0 => "record type not declared (each record's length is checked when read)".to_string(),
                n => format!("records of {n} bytes"),
            }
        ),
        Some(info) => out!(
            "  map {}: {}, key {} bytes, value {} bytes, {} entries",
            def.map,
            info.kind,
            info.key_size,
            info.value_size,
            info.max_entries
        ),
        None => out!("  map {}: not in the program", def.map),
    }
    if let Some(key) = &def.key {
        print_layout("key", key);
    }
    print_layout("value", &def.value);
    for derived in &def.derived {
        out!("  derived {} = {}", derived.name, describe(def, derived));
    }
}

fn print_layout(part: &str, layout: &Layout) {
    let fields: Vec<String> = layout
        .fields
        .iter()
        .map(|f| {
            let ty = match f.len {
                Some(len) => format!("{:?}[{len}]", f.scalar).to_lowercase(),
                None => format!("{:?}", f.scalar).to_lowercase(),
            };
            format!("{}@{} {ty}", f.name, f.offset)
        })
        .collect();
    out!("  {part} ({} bytes): {}", layout.size, fields.join(", "));
}

fn describe(def: &Definition, derived: &Derived) -> String {
    let names: Vec<&str> = def.names().collect();
    let n = |i: &usize| names.get(*i).copied().unwrap_or("?");
    match &derived.op {
        Op::Add(a, b) => format!("{} + {}", n(a), n(b)),
        Op::Sub(a, b) => format!("{} - {}", n(a), n(b)),
        Op::Mul(a, b) => format!("{} * {}", n(a), n(b)),
        Op::Div(a, b) => format!("{} / {}", n(a), n(b)),
        Op::Mean { sum, count } => format!("mean({}, {})", n(sum), n(count)),
        Op::Var { sum, sumsq, count } => format!("var({}, {}, {})", n(sum), n(sumsq), n(count)),
        Op::Std { sum, sumsq, count } => format!("std({}, {}, {})", n(sum), n(sumsq), n(count)),
        Op::Delta(i) => format!("delta({})", n(i)),
        Op::Rate(i) => format!("rate({})", n(i)),
        Op::Scale { of, by } => format!("{} * {by}", n(of)),
        Op::Bucket { of, edges } => format!("bucket({}, {} edges)", n(of), edges.len()),
        Op::Percentile { of, p, .. } => format!("p{p}({})", n(of)),
        Op::Enum { of, values, .. } => format!("enum({}, {} values)", n(of), values.len()),
    }
}

#[cfg(test)]
mod tests;
