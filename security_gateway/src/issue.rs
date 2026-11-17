use std::fmt;
use std::str::FromStr;

macro_rules! issues {
    ($($variant:ident),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Issue {
            $($variant),*
        }

        impl Issue {
            pub const ALL: &[Issue] = &[$(Issue::$variant),*];
        }
    };
}

issues! {
    ConfigUnreadable,
    ConfigInvalid,
    PortUnspecified,
    ConfigInapplicable,
    PortNotFound,
    PortAmbiguous,
    PortShared,
    PortAdminDown,
    PortNoCarrier,
    PortStateUnreported,
    PortStateOther,
    InterfacesUnlisted,
    BridgeMembership,
    BridgeDown,
    BridgeNfCallIptables,
    BridgeNfCallIp6tables,
    RoutedNotBridged,
    RoutedIpForward,
    RoutedIpv6Forward,
    RoutedAddresses,
    RoutedOverlap,
    RoutedDefaultRoute,
    RoutedUpstream,
    XdpUndetected,
    XdpGenericAttached,
    XdpGenericConfigured,
    ModulesUnchecked,
    ModuleNotLoaded,
    ModuleMissing,
    ModuleUnverified,
    NftNotFound,
    NftNoJson,
    NftUnverified,
    SuricataNotFound,
    SuricataUnchecked,
    SuricataNoCapture,
    SuricataNoSystemd,
    SuricataSpawned,
    AcceptWhenUnavailable,
    IdsNoBlocking,
    IdsNoChecksum,
    IdsCopiesDropped,
    SuricataConfigUnloadable,
    NoRules,
    RuleFileProblem,
    NoAlertOutput,
    ProcessesHidden,
    OtherSuricataUnchecked,
    LeftoverSuricata,
    OtherSuricataOnQueue,
    OtherSuricataOnNflog,
    OtherSuricataInline,
    OtherSuricataLive,
    OtherSuricataPcap,
    OtherSuricataTest,
    OtherSuricataUnknown,
    SuricataServiceEnabled,
    SuricataServiceUnchecked,
    AutoTrust,
    AutoTrustNoAlerts,
    AutoTrustOff,
    AutoTrustNoFastPath,
    AutoTrustPaused,
    ConntrackAcct,
    TrustTtlTooShort,
    WritableByNonRoot,
    AccessUnchecked,
    AlreadyRunning,
    LockFailed,
    ChecksFailed,
    SignalsUnavailable,
    SupervisionEnded,
    ControlUnavailable,
    ControlRejected,
    TableInstallFailed,
    CoreProgramFailed,
    CoreProgramNotFirst,
    CoreProgramDetached,
    TcxUnchecked,
    TcxUnsupported,
    ForeignTcxPrograms,
    RoutesUnstable,
    NextHopsOff,
    TableRemoveFailed,
    TableRemoved,
    StartInspectionFailed,
    StopInspectionFailed,
    Uninspected,
    DroppedUninspected,
    SuricataStartFailed,
    SuricataExited,
    SuricataNotReady,
    SuricataStopSlow,
    QueueBusy,
    NflogBusy,
    RulesFailed,
    SuricataMessage,
    CopiesMissed,
    CopiesUncounted,
    AlertFileUnknown,
    EveSkipped,
    EveUnreadable,
    EveBehind,
    ConntrackNearlyFull,
    ConntrackDropped,
    ConntrackEvicted,
    ConntrackStatsUnreadable,
    ConntrackUnreadable,
    NoPacketCounters,
    TrustFailed,
    ExpireFailed,
    TrustRevoked,
    RevokeFailed,
}

pub struct Explanation {
    pub code: &'static str,
    pub title: &'static str,
    pub reported_by: &'static str,
    pub severity: &'static str,
    pub cause: &'static str,
    pub action: &'static str,
}

const DOCTOR: &str = "doctor";
const DOCTOR_BRIDGE: &str = "doctor, bridge mode";
const DOCTOR_ROUTED: &str = "doctor, routed mode";
const DOCTOR_AND_RUN: &str = "doctor and run";
const RUN: &str = "run log";

impl Issue {
    pub fn explanation(self) -> &'static Explanation {
        match self {
            Self::ConfigUnreadable => &Explanation {
                code: "C001",
                title: "the config file cannot be read",
                reported_by: DOCTOR_AND_RUN,
                severity: "error",
                cause: "The file given with -c/--config does not exist or cannot be read (for \
                        example, permission denied). Without -c, a missing \
                        /etc/wnc-gw/setting.toml is not an error: doctor then uses defaults and \
                        the ports given on the command line.",
                action: "Fix the path or the file's permissions, or run without -c.",
            },
            Self::ConfigInvalid => &Explanation {
                code: "C002",
                title: "the config file is invalid",
                reported_by: DOCTOR_AND_RUN,
                severity: "error",
                cause: "The config file is not valid TOML, has a field wnc-gw does not know (often \
                        a typo), or has a value it cannot accept, such as a relative path or an \
                        unknown mode. The message names the field.",
                action: "Fix the field the message names; setting.example.toml lists every field \
                         and its values.",
            },
            Self::PortUnspecified => &Explanation {
                code: "C003",
                title: "LAN or WAN port is not specified",
                reported_by: DOCTOR_AND_RUN,
                severity: "error",
                cause: "Neither the config file (ports.lan, ports.wan) nor the command line \
                        (--lan, --wan) says which interface is LAN or WAN. wnc-gw never guesses \
                        them.",
                action: "Set ports.lan and ports.wan to an interface name or MAC address; wnc-gw \
                         show interfaces lists them.",
            },
            Self::ConfigInapplicable => &Explanation {
                code: "C004",
                title: "the config file sets options that do not apply",
                reported_by: DOCTOR_AND_RUN,
                severity: "error",
                cause: "An option is set that the rest of the config makes unused, so it would silently do \
                        nothing: suricata.queue with protection = \"ids\" (the default), suricata.group with \
                        protection = \"ips\", or trust.min_packets, min_age, ttl or check_interval without \
                        trust.auto = true. The message lists each one.",
                action: "Remove the listed options, or change the option they depend on (protection or \
                         trust.auto).",
            },
            Self::PortNotFound => &Explanation {
                code: "P001",
                title: "no interface matches the LAN or WAN port",
                reported_by: DOCTOR,
                severity: "error",
                cause: "No interface has the configured name or MAC address. Interface names can \
                        change when the network card is plugged into another port or USB slot, or \
                        after a driver update; a MAC changes when the card is replaced.",
                action: "Check the names and MACs with wnc-gw show interfaces and update the \
                         setting; a MAC address survives renaming.",
            },
            Self::PortAmbiguous => &Explanation {
                code: "P002",
                title: "the LAN or WAN port matches more than one interface",
                reported_by: DOCTOR,
                severity: "error",
                cause: "The port is given as a MAC address and several interfaces have it, for \
                        example a VLAN, bond or bridge that copies the MAC of its member port.",
                action: "Specify the port by interface name instead.",
            },
            Self::PortShared => &Explanation {
                code: "P003",
                title: "LAN and WAN are the same interface",
                reported_by: DOCTOR,
                severity: "error",
                cause: "LAN and WAN resolve to the same interface, usually because both settings \
                        name the same interface or MAC.",
                action: "Point LAN and WAN at two different interfaces.",
            },
            Self::PortAdminDown => &Explanation {
                code: "P004",
                title: "a port is administratively down",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "The interface was not brought up (ip link set <port> down, or the network \
                        manager does not manage it). No traffic passes through it.",
                action: "Bring it up with: ip link set <port> up, and let the network manager \
                         bring it up at boot.",
            },
            Self::PortNoCarrier => &Explanation {
                code: "P005",
                title: "a port has no carrier",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "The interface is up but sees no link: the cable is unplugged or broken, or \
                        the device on the other end is off. It is only a warning because a cable \
                        may be plugged in after start.",
                action: "Check the cable and the device on the other end; ip link show <port> \
                         shows NO-CARRIER until the link comes up.",
            },
            Self::PortStateUnreported => &Explanation {
                code: "P006",
                title: "the driver does not report a port's link state",
                reported_by: DOCTOR,
                severity: "note",
                cause: "The kernel reports the link state as UNKNOWN, which is normal for virtual \
                        interfaces (dummy, tun) and some drivers. doctor cannot \
                        tell whether the link is up.",
                action: "Nothing to do unless traffic does not pass; then check the link by other \
                         means.",
            },
            Self::PortStateOther => &Explanation {
                code: "P007",
                title: "a port is in an unusual link state",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "The kernel reports a link state other than UP, DOWN or UNKNOWN, such as \
                        DORMANT (waiting for 802.1X or a supplicant), TESTING or NOTPRESENT. \
                        Traffic may not pass.",
                action: "Check the interface with ip link show <port> and whatever controls that \
                         state, such as 802.1X.",
            },
            Self::InterfacesUnlisted => &Explanation {
                code: "P008",
                title: "network interfaces cannot be listed",
                reported_by: DOCTOR,
                severity: "error",
                cause: "doctor could not open a netlink socket or list the interfaces over it, which only happens in \
                        a very restricted environment (for example a seccomp profile that blocks netlink). Nothing \
                        else is checked.",
                action: "Run doctor where netlink sockets are allowed, such as directly on the host.",
            },
            Self::BridgeMembership => &Explanation {
                code: "B001",
                title: "LAN and WAN are not in one bridge",
                reported_by: DOCTOR_BRIDGE,
                severity: "error or warning",
                cause: "In bridge mode, LAN and WAN must both be ports of the same Linux bridge, \
                        which the OS creates. This is an error when a port is in no bridge, in a \
                        different bridge, or in something that is not a bridge (a bond or VRF). It \
                        is a warning (cannot verify) when LAN or WAN could not be resolved.",
                action: "Create one bridge with both ports in your network manager, or set mode = \
                         \"routed\" if the gateway should route instead.",
            },
            Self::BridgeDown => &Explanation {
                code: "B002",
                title: "the bridge is administratively down",
                reported_by: DOCTOR_BRIDGE,
                severity: "warning",
                cause: "The bridge that holds LAN and WAN is down, so it forwards nothing.",
                action: "Bring it up with: ip link set <bridge> up, and let the network manager \
                         bring it up at boot.",
            },
            Self::BridgeNfCallIptables => &Explanation {
                code: "B003",
                title: "bridged IPv4 traffic bypasses nftables",
                reported_by: DOCTOR_BRIDGE,
                severity: "error or warning",
                cause: "net.bridge.bridge-nf-call-iptables is 0, so bridged IPv4 traffic skips \
                        wnc-gw's nftables rules and is never inspected. It is 1 by default once \
                        br_netfilter loads; a sysctl.d file may set it to 0. It is a warning \
                        (cannot verify) when br_netfilter is not loaded, because the key does not \
                        exist then.",
                action: "Load br_netfilter, then: sysctl -w net.bridge.bridge-nf-call-iptables=1, \
                         and persist it in /etc/sysctl.d/.",
            },
            Self::BridgeNfCallIp6tables => &Explanation {
                code: "B004",
                title: "bridged IPv6 traffic bypasses nftables",
                reported_by: DOCTOR_BRIDGE,
                severity: "error or warning",
                cause: "Same as B003 for IPv6: net.bridge.bridge-nf-call-ip6tables is 0, or cannot \
                        be read because br_netfilter is not loaded.",
                action: "Load br_netfilter, then: sysctl -w net.bridge.bridge-nf-call-ip6tables=1, \
                         and persist it in /etc/sysctl.d/.",
            },
            Self::RoutedNotBridged => &Explanation {
                code: "R001",
                title: "LAN or WAN is in a bridge",
                reported_by: DOCTOR_ROUTED,
                severity: "error or warning",
                cause: "In routed mode, LAN and WAN must be separate interfaces, but at least one \
                        is a port of a bridge, so its traffic is bridged instead of routed. It is \
                        a warning (cannot verify) when LAN or WAN could not be resolved.",
                action: "Remove the ports from the bridge, or set mode = \"bridge\".",
            },
            Self::RoutedIpForward => &Explanation {
                code: "R002",
                title: "IPv4 forwarding is off",
                reported_by: DOCTOR_ROUTED,
                severity: "error or warning",
                cause: "net.ipv4.ip_forward is 0, the default on Debian, so the kernel does not \
                        route IPv4 between LAN and WAN. It is a warning (cannot verify) when the \
                        key cannot be read.",
                action: "Set it with: sysctl -w net.ipv4.ip_forward=1, and persist it in \
                         /etc/sysctl.d/.",
            },
            Self::RoutedIpv6Forward => &Explanation {
                code: "R003",
                title: "IPv6 forwarding is off",
                reported_by: DOCTOR_ROUTED,
                severity: "warning",
                cause: "net.ipv6.conf.all.forwarding is 0, the default, so IPv6 is not routed \
                        between LAN and WAN; IPv4 is not affected. It cannot be verified when IPv6 \
                        is disabled in the kernel.",
                action: "If the network uses IPv6: sysctl -w net.ipv6.conf.all.forwarding=1, and \
                         persist it in /etc/sysctl.d/. Otherwise ignore it.",
            },
            Self::RoutedAddresses => &Explanation {
                code: "R004",
                title: "LAN or WAN has no IPv4 address",
                reported_by: DOCTOR_ROUTED,
                severity: "warning",
                cause: "A routed port needs an IPv4 address, but LAN or WAN has none \
                        (169.254.0.0/16 link-local addresses do not count). Usually the port uses \
                        DHCP and has no lease yet, or the network manager does not configure it. \
                        It is a warning so that run can start before DHCP finishes; it is also \
                        shown as \"cannot verify\" when LAN or WAN cannot be resolved (P001 to \
                        P003) or the addresses cannot be read.",
                action: "Give the port an address in your network manager (check with: ip -4 addr \
                         show <port>).",
            },
            Self::RoutedOverlap => &Explanation {
                code: "R005",
                title: "LAN and WAN subnets overlap",
                reported_by: DOCTOR_ROUTED,
                severity: "error or warning",
                cause: "The subnet of LAN or WAN overlaps the other one or the subnet of another \
                        interface, so the kernel cannot tell which interface the overlapping \
                        addresses are on. This usually happens when both sides got addresses from \
                        the same DHCP server or were given the same subnet by mistake. It is a \
                        warning (cannot verify) when LAN or WAN cannot be resolved (P001 to P003) \
                        or the addresses cannot be read.",
                action: "Give LAN and WAN their own subnets that no other interface uses.",
            },
            Self::RoutedDefaultRoute => &Explanation {
                code: "R006",
                title: "the IPv4 default route does not go through WAN",
                reported_by: DOCTOR_ROUTED,
                severity: "warning",
                cause: "There is no IPv4 default route (often WAN's DHCP has no lease yet), it is \
                        a blackhole or unreachable route, or it leaves through another interface, \
                        such as the management port or a lower-metric route there. Traffic is \
                        still inspected, but goes out the wrong way or not at all. It is \"cannot \
                        verify\" when routing rules other than the kernel's defaults exist (ip \
                        rule, for example from wg-quick or Tailscale), or when LAN or WAN cannot \
                        be resolved.",
                action: "Add the default route through WAN with your network manager (check with: \
                         ip -4 route show default). Ignore it if the gateway only needs explicit \
                         routes.",
            },
            Self::RoutedUpstream => &Explanation {
                code: "R007",
                title: "LAN hosts and the upstream router need routes through the gateway",
                reported_by: DOCTOR_ROUTED,
                severity: "note",
                cause: "Always shown in routed mode once both ports have addresses. wnc-gw routes \
                        without NAT, so LAN hosts must use the gateway's LAN address as their \
                        gateway, and the upstream router must route the LAN subnets back through \
                        the gateway's WAN address. doctor cannot check either from here.",
                action: "Set the gateway on LAN hosts (usually through DHCP) and add the route on \
                         the upstream router, or set up NAT yourself.",
            },
            Self::XdpUndetected => &Explanation {
                code: "X001",
                title: "native XDP support cannot be detected",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "With xdp = \"auto\", doctor asks the kernel's netdev netlink family which \
                        interfaces support native XDP, and the query failed; kernels older than \
                        6.3 do not have it. The core program will use TC.",
                action: "Nothing is required: TC works everywhere. Use a newer kernel if native \
                         XDP is wanted.",
            },
            Self::XdpGenericAttached => &Explanation {
                code: "X002",
                title: "a generic XDP program is attached to a port",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "Another program attached generic (SKB) XDP to a port. Generic XDP disables \
                        GRO on that interface, which makes forwarding slower than TC.",
                action: "Detach it if it is not needed: ip link set dev <port> xdpgeneric off.",
            },
            Self::XdpGenericConfigured => &Explanation {
                code: "X003",
                title: "xdp = \"generic\" is configured",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "The setting forces generic XDP, which disables GRO on the port and is \
                        slower than TC. \"auto\" never picks generic.",
                action: "Set xdp = \"auto\" unless generic XDP is needed for testing.",
            },
            Self::ModulesUnchecked => &Explanation {
                code: "K001",
                title: "kernel modules cannot be checked",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "doctor could not read /proc/sys/kernel/osrelease or /proc/modules, for \
                        example inside a restricted container. If only /lib/modules/<release> \
                        cannot be read, each module that is not loaded gets K004 instead.",
                action: "Run doctor on the host, or check the modules by hand with lsmod.",
            },
            Self::ModuleNotLoaded => &Explanation {
                code: "K002",
                title: "a kernel module that must be loaded in advance is not loaded",
                reported_by: DOCTOR,
                severity: "error",
                cause: "Some modules are not loaded by the kernel on demand; br_netfilter in \
                        bridge mode is one. It exists but is not loaded, so the feature it \
                        provides is missing.",
                action: "Load it with: modprobe <module>, and list it in /etc/modules-load.d/ so \
                         it loads at boot.",
            },
            Self::ModuleMissing => &Explanation {
                code: "K003",
                title: "a required kernel module is missing",
                reported_by: DOCTOR,
                severity: "error",
                cause: "The module is neither loaded, built in, nor present under \
                        /lib/modules/<release>. This happens with a kernel built without it, or \
                        when the module package for the running kernel is not installed (often \
                        right after a kernel update before reboot).",
                action: "Install the modules for the running kernel, or reboot into the kernel \
                         whose modules are installed.",
            },
            Self::ModuleUnverified => &Explanation {
                code: "K004",
                title: "a kernel module cannot be verified",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "The module is not loaded and /lib/modules/<release> cannot be read, so \
                        doctor cannot tell whether the kernel could load it.",
                action: "Check that /lib/modules/$(uname -r) exists and is readable.",
            },
            Self::NftNotFound => &Explanation {
                code: "N001",
                title: "nft is not found",
                reported_by: DOCTOR,
                severity: "error",
                cause: "The nft command ([nftables] path, default /usr/sbin/nft) does not exist, \
                        so wnc-gw cannot install its rules.",
                action: "Install nftables, or set [nftables] path to where nft is.",
            },
            Self::NftNoJson => &Explanation {
                code: "N002",
                title: "nft is built without JSON support",
                reported_by: DOCTOR,
                severity: "error",
                cause: "nft -V reports json: no. wnc-gw sends its rules to nft as JSON, so this \
                        nft cannot install them. Debian's package has JSON support; custom builds \
                        may not.",
                action: "Install an nftables build with JSON support.",
            },
            Self::NftUnverified => &Explanation {
                code: "N003",
                title: "nft cannot be checked",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "nft -V failed, timed out, or does not report whether JSON is supported \
                        (older nft versions).",
                action: "Run nft -V by hand and check for json: yes.",
            },
            Self::SuricataNotFound => &Explanation {
                code: "S001",
                title: "suricata is not found",
                reported_by: DOCTOR,
                severity: "error",
                cause: "The suricata command ([suricata] path, default /usr/bin/suricata) does not \
                        exist, so traffic cannot be inspected.",
                action: "Install suricata, or set [suricata] path to where it is.",
            },
            Self::SuricataUnchecked => &Explanation {
                code: "S002",
                title: "suricata cannot be checked",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "suricata --build-info failed or timed out, so its features and config \
                        cannot be checked.",
                action: "Run suricata --build-info by hand to see the error.",
            },
            Self::SuricataNoCapture => &Explanation {
                code: "S003",
                title: "suricata is built without NFQueue or NFLOG support",
                reported_by: DOCTOR,
                severity: "error or warning",
                cause: "protection = \"ips\" needs NFQueue and \"ids\" needs NFLOG, and suricata \
                        --build-info says the build lacks it. It is a warning (cannot verify) when \
                        --build-info does not mention it.",
                action: "Install a suricata build with that support (Debian's package has both), \
                         or change protection.",
            },
            Self::SuricataNoSystemd => &Explanation {
                code: "S004",
                title: "suricata is built without systemd support",
                reported_by: DOCTOR,
                severity: "error or warning",
                cause: "wnc-gw waits for suricata's readiness notification (sd_notify) before \
                        sending it traffic, and this build cannot send it. It is a warning (cannot \
                        verify) when --build-info does not report it; Suricata 8.0 and later do.",
                action: "Install a suricata build with systemd support (Debian's package has it).",
            },
            Self::SuricataSpawned => &Explanation {
                code: "S005",
                title: "suricata shares wnc-gw's account and privileges",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "Always shown: wnc-gw starts suricata itself, so suricata runs with \
                        wnc-gw's account and privileges, and a compromised suricata can do \
                        whatever the gateway can.",
                action: "Nothing to change in this version; keep suricata's rules and config from \
                         trusted sources.",
            },
            Self::AcceptWhenUnavailable => &Explanation {
                code: "S006",
                title: "traffic passes without inspection while suricata is unavailable",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "when_unavailable = \"accept\" (the default) lets forwarded traffic through \
                        uninspected while suricata starts or restarts, and in ips mode also when \
                        it falls behind. run logs each such period.",
                action: "Set when_unavailable = \"drop\" to drop that traffic instead, at the cost \
                         of connectivity during those periods.",
            },
            Self::IdsNoBlocking => &Explanation {
                code: "S007",
                title: "protection = \"ids\" does not block traffic",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "Always shown with protection = \"ids\" (the default): suricata only gets \
                        copies of packets, so its detections are logged but never block anything.",
                action: "Set protection = \"ips\" to make packets wait for suricata's verdict.",
            },
            Self::IdsNoChecksum => &Explanation {
                code: "S008",
                title: "protection = \"ids\" does not validate checksums",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "Always shown with protection = \"ids\": packets merged by GRO reach \
                        suricata with incomplete checksums, so checksum validation is turned off. \
                        Suricata then also inspects packets the receiving host drops for a bad \
                        checksum, which an attacker can use to hide data from inspection.",
                action: "Set protection = \"ips\" if this matters.",
            },
            Self::IdsCopiesDropped => &Explanation {
                code: "S009",
                title: "protection = \"ids\" forwards traffic uninspected when suricata falls \
                        behind",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "Always shown with protection = \"ids\": packets are forwarded right away \
                        and suricata gets copies; when it falls behind, the kernel discards the \
                        copies that do not fit, whatever when_unavailable says. While running, \
                        wnc-gw logs \"suricata missed packet copies\" with the count.",
                action: "Set protection = \"ips\" if traffic must not pass uninspected, or use \
                         more NFLOG groups (for example [suricata] group = \"10-12\") so several \
                         suricata threads share the copies.",
            },
            Self::SuricataConfigUnloadable => &Explanation {
                code: "S010",
                title: "suricata cannot load its config file",
                reported_by: DOCTOR,
                severity: "error or warning",
                cause: "suricata --dump-config with [suricata] config (default \
                        /etc/suricata/suricata.yaml) failed: the file is missing, is not valid \
                        YAML, or has an error suricata reports. It is a warning (cannot verify) \
                        when the command failed for another reason, such as a timeout.",
                action: "Fix the error the message quotes, or point [suricata] config at a working \
                         file.",
            },
            Self::NoRules => &Explanation {
                code: "S011",
                title: "suricata has no rules to load",
                reported_by: DOCTOR,
                severity: "error",
                cause: "rule-files in suricata's config is empty, or every listed file is missing \
                        or contains no rules. Usually rules were never downloaded: Debian's \
                        suricata package ships none.",
                action: "Run suricata-update (it writes /var/lib/suricata/rules/suricata.rules), \
                         or set default-rule-path and rule-files to existing rule files.",
            },
            Self::RuleFileProblem => &Explanation {
                code: "S012",
                title: "a rule file is missing, empty or cannot be checked",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "Some file in rule-files is missing, has no rules, cannot be read, is a \
                        wildcard, or cannot be located because default-rule-path is not set. If \
                        another file has rules, suricata runs without this one; if none is \
                        confirmed to have rules but some cannot be checked, this warning is all \
                        doctor reports, because those may still hold rules.",
                action: "Fix or remove that entry in rule-files.",
            },
            Self::NoAlertOutput => &Explanation {
                code: "S013",
                title: "suricata does not write alerts to a regular EVE file",
                reported_by: DOCTOR_AND_RUN,
                severity: "warning",
                cause: "Suricata's config has no enabled eve-log output with filetype: regular and \
                        alert in its types, so wnc-gw cannot read alerts (logging and automatic \
                        trust need them).",
                action: "Enable an eve-log output with filetype: regular and an alert type in \
                         suricata's config.",
            },
            Self::ProcessesHidden => &Explanation {
                code: "O001",
                title: "other users' processes are hidden",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "/proc is mounted with hidepid and doctor does not run as root, so it \
                        cannot see other users' suricata processes.",
                action: "Run doctor as root to check for other suricata processes.",
            },
            Self::OtherSuricataUnchecked => &Explanation {
                code: "O002",
                title: "other suricata processes cannot be checked",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "doctor could not list processes under /proc.",
                action: "Check by hand with: pgrep -a suricata.",
            },
            Self::LeftoverSuricata => &Explanation {
                code: "O003",
                title: "a suricata left by a previous wnc-gw is still running",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "A suricata started by an earlier wnc-gw (its command line has wnc-gw's \
                        control socket) is still running without that wnc-gw, for example after \
                        wnc-gw was killed with SIGKILL. It normally exits by itself shortly; until \
                        then it may hold the NFQUEUE (ips) or the NFLOG group (ids) that the new \
                        suricata needs.",
                action: "Wait a few seconds, or stop it with: kill <pid>.",
            },
            Self::OtherSuricataOnQueue => &Explanation {
                code: "O004",
                title: "another suricata uses wnc-gw's NFQUEUE",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "Another suricata runs inline on an NFQUEUE number wnc-gw is configured to \
                        use, in the same network namespace (or one doctor cannot tell). wnc-gw's \
                        suricata cannot bind that queue until it stops; wnc-gw keeps retrying.",
                action: "Stop the other suricata, or set [suricata] queue to numbers it does not \
                         use.",
            },
            Self::OtherSuricataOnNflog => &Explanation {
                code: "O005",
                title: "another suricata receives packet copies over NFLOG",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "Another suricata captures over NFLOG. If it binds the NFLOG group wnc-gw \
                        uses (doctor cannot tell which group it binds), wnc-gw's suricata cannot \
                        start (S019).",
                action: "Stop the other suricata, or set [suricata] group to a group it does not \
                         use.",
            },
            Self::OtherSuricataInline => &Explanation {
                code: "O006",
                title: "another suricata runs inline on other queues",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "Another suricata runs on NFQUEUE numbers wnc-gw does not use, or in \
                        another network namespace. It does not block wnc-gw, but competes for CPU \
                        and memory.",
                action: "Stop it if it is not needed.",
            },
            Self::OtherSuricataLive => &Explanation {
                code: "O007",
                title: "another suricata captures traffic",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "Another suricata captures traffic itself (af-packet, pcap, nflog in \
                        another namespace), often the suricata.service the Debian package enables. \
                        It inspects separately from wnc-gw and competes for CPU and memory.",
                action: "Stop it: systemctl disable --now suricata, or kill <pid>.",
            },
            Self::OtherSuricataPcap => &Explanation {
                code: "O008",
                title: "another suricata reads pcap files",
                reported_by: DOCTOR,
                severity: "note",
                cause: "Another suricata is reading pcap files (-r). It uses CPU while it runs and \
                        then exits.",
                action: "Nothing to do, unless the gateway is short of CPU.",
            },
            Self::OtherSuricataTest => &Explanation {
                code: "O009",
                title: "another suricata tests its configuration",
                reported_by: DOCTOR,
                severity: "note",
                cause: "Another suricata runs with -T, usually started by suricata-update to test \
                        new rules. It exits by itself.",
                action: "Nothing to do.",
            },
            Self::OtherSuricataUnknown => &Explanation {
                code: "O010",
                title: "another suricata runs and its capture method is unknown",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "Another suricata runs, but its command line does not show how it gets \
                        packets (for example, it comes from its config file). It may compete with \
                        wnc-gw's suricata.",
                action: "Check it with: cat /proc/<pid>/cmdline, and stop it if it is not needed.",
            },
            Self::SuricataServiceEnabled => &Explanation {
                code: "O011",
                title: "the suricata service starts at boot",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "suricata.service is enabled (the Debian package enables it on install), so \
                        another suricata will start at boot and compete with wnc-gw's.",
                action: "Disable it with: systemctl disable suricata.service; add --now to also \
                         stop the one running now.",
            },
            Self::SuricataServiceUnchecked => &Explanation {
                code: "O012",
                title: "whether the suricata service starts at boot cannot be checked",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "systemctl is missing (for example in a container) or failed, so doctor \
                        cannot tell whether suricata.service starts at boot.",
                action: "Check by hand with: systemctl is-enabled suricata.",
            },
            Self::AutoTrust => &Explanation {
                code: "T001",
                title: "automatic trust is on",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "Always shown with [trust] auto = true: a connection that reaches \
                        min_packets each way and min_age without an alert skips inspection, except \
                        syn/fin/rst, for ttl seconds. An attack sent after that point is not seen \
                        until the trust expires.",
                action: "Accept the risk, or set [trust] auto = false.",
            },
            Self::AutoTrustNoAlerts => &Explanation {
                code: "T002",
                title: "automatic trust has no alerts to rely on",
                reported_by: DOCTOR,
                severity: "error",
                cause: "[trust] auto = true, but suricata's config has no eve-log output that \
                        writes alerts to a regular file (S013), so connections that raise alerts \
                        would be trusted too. When the config cannot be checked at all, doctor \
                        reports T012 instead.",
                action: "Enable an eve-log output with alerts (see S013), or set [trust] auto = \
                         false.",
            },
            Self::AutoTrustOff => &Explanation {
                code: "T012",
                title: "automatic trust is turned off because alerts cannot be seen",
                reported_by: DOCTOR_AND_RUN,
                severity: "warning",
                cause: "[trust] auto = true, but suricata or its config could not be checked (S002, S010 in doctor; \
                        S024 in run), so wnc-gw cannot tell where suricata writes alerts. Without alerts every \
                        connection would be trusted, so run starts with automatic trust off: everything is inspected, \
                        only the CPU that trust saves is lost. If the config is known to have no alert output, doctor \
                        reports T002 instead and run does not start.",
                action: "Fix what S002, S010 or S024 reports, then restart run to turn automatic trust back on.",
            },
            Self::AutoTrustNoFastPath => &Explanation {
                code: "T014",
                title: "automatic trust is off because the core eBPF program is not attached",
                reported_by: RUN,
                severity: "warning",
                cause: "[trust] auto = true, but the core eBPF program could not be attached (D001). \
                        Trust is kept in that program's map and trusted packets are forwarded by it, \
                        so without it nothing can be trusted: every connection is inspected and only \
                        the CPU that trust saves is lost.",
                action: "Fix what D001 reports, then restart run.",
            },
            Self::AutoTrustPaused => &Explanation {
                code: "T013",
                title: "automatic trust is paused because alerts are not current",
                reported_by: RUN,
                severity: "warning",
                cause: "wnc-gw cannot read Suricata's EVE file (E002) or reads it late (E003), so an alert on a \
                        watched connection may not have reached it yet. To avoid trusting such a connection, no new \
                        connection is trusted and every watched one starts its observation again once alerts are \
                        current; already trusted connections keep their trust until it expires or an alert revokes \
                        it. INFO \"automatic trust resumed\" ends it.",
                action: "Fix what E002 or E003 reports.",
            },
            Self::ConntrackAcct => &Explanation {
                code: "T003",
                title: "conntrack does not count packets for automatic trust",
                reported_by: DOCTOR,
                severity: "error or warning",
                cause: "Automatic trust needs net.netfilter.nf_conntrack_acct = 1 to count each \
                        connection's packets, and it is 0 (the default). It is a warning (cannot \
                        verify) when nf_conntrack is not loaded yet or the key cannot be read.",
                action: "Set it with: sysctl -w net.netfilter.nf_conntrack_acct=1, and persist it \
                         in /etc/sysctl.d/.",
            },
            Self::TrustTtlTooShort => &Explanation {
                code: "T004",
                title: "trust ttl is not longer than suricata's TCP established timeout",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "With protection = \"ips\", [trust] ttl is not longer than suricata's \
                        flow-timeouts.tcp.established. When trust ends, suricata may still hold \
                        the connection's old state and drop its packets as out of sync.",
                action: "Set [trust] ttl above flow-timeouts.tcp.established (600 s by default).",
            },
            Self::WritableByNonRoot => &Explanation {
                code: "A001",
                title: "a file wnc-gw runs or reads can be modified without root",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "The wnc-gw config, the nft or suricata command, or suricata's config can \
                        be changed by a non-root account: its owner, a group or everyone can write \
                        to the file, a directory above it, or the target of a symlink. That \
                        account could make the gateway run code with its privileges.",
                action: "Make the file and its directories owned by root and not writable by group \
                         or others (chown root:root, chmod go-w).",
            },
            Self::AccessUnchecked => &Explanation {
                code: "A002",
                title: "who can modify a file cannot be checked",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "doctor could not read the file's or a parent directory's permissions, for \
                        example because of permission denied.",
                action: "Run doctor as root, or check with: ls -ld on the file and each directory \
                         above it.",
            },
            Self::AlreadyRunning => &Explanation {
                code: "L001",
                title: "another wnc-gw is already running",
                reported_by: RUN,
                severity: "error",
                cause: "run takes a lock on /run/wnc-gw/wnc-gw.lock so that only one wnc-gw runs \
                        on the machine, and another wnc-gw holds it (its pid is in the message). \
                        Two would fight over the same nft table and Suricata.",
                action: "Stop the other one first (check with: pgrep -a wnc-gw), or keep using it.",
            },
            Self::LockFailed => &Explanation {
                code: "L002",
                title: "the instance lock cannot be taken",
                reported_by: RUN,
                severity: "error",
                cause: "run could not create or lock /run/wnc-gw/wnc-gw.lock, usually because it \
                        does not run as root and cannot write to /run/wnc-gw.",
                action: "Run wnc-gw run as root.",
            },
            Self::ChecksFailed => &Explanation {
                code: "L003",
                title: "run does not start because doctor found errors",
                reported_by: RUN,
                severity: "error",
                cause: "run runs the same checks as doctor before it changes anything, and at \
                        least one of them is an error (printed above it with its own code). \
                        Nothing was installed.",
                action: "Fix the errors above (wnc-gw explain <code> for each), then start run \
                         again.",
            },
            Self::SignalsUnavailable => &Explanation {
                code: "L004",
                title: "run cannot listen for stop signals",
                reported_by: RUN,
                severity: "error",
                cause: "Registering the SIGINT, SIGTERM and SIGHUP handlers failed, which should \
                        not happen on Linux. run exits before installing anything.",
                action: "Start run again; if it repeats, report it with the log.",
            },
            Self::SupervisionEnded => &Explanation {
                code: "L005",
                title: "Suricata supervision ended unexpectedly",
                reported_by: RUN,
                severity: "error",
                cause: "The task that starts and watches Suricata stopped without being asked to, \
                        which points to a bug in wnc-gw. run stops Suricata, removes its table \
                        (F003) and exits with a failure.",
                action: "Start run again and report it with the log.",
            },
            Self::ControlUnavailable => &Explanation {
                code: "L006",
                title: "run cannot listen for trust requests",
                reported_by: RUN,
                severity: "warning",
                cause: "At start, run creates the socket that wnc-gw trust add, del and list talk to \
                        (control.sock in /run/wnc-gw) and that failed, for example because the \
                        directory is not writable. run keeps going; automatic trust is not affected.",
                action: "Check the error in the message and the permissions of /run/wnc-gw, then \
                         restart run.",
            },
            Self::ControlRejected => &Explanation {
                code: "L007",
                title: "a trust request from another account was rejected",
                reported_by: RUN,
                severity: "warning",
                cause: "Something connected to run's trust socket from an account that is neither \
                        root nor the one run uses. The socket is only accessible to that account \
                        (mode 0600), so this needs a process that already has its privileges or \
                        an unusual setup. The request is not carried out.",
                action: "Find out which program it was (uid in the log); use wnc-gw trust as root.",
            },
            Self::TableInstallFailed => &Explanation {
                code: "F001",
                title: "the nft table cannot be installed",
                reported_by: RUN,
                severity: "error",
                cause: "nft rejected wnc-gw's table (inet wnc_gw) at start: run lacks \
                        CAP_NET_ADMIN (not root), a kernel module nftables needs is missing, or \
                        nft failed for another reason in the message. run exits; nothing is \
                        inspected.",
                action: "Run as root and run wnc-gw doctor; the nft error in the message says what \
                         is missing.",
            },
            Self::CoreProgramFailed => &Explanation {
                code: "D001",
                title: "the core eBPF program cannot be attached",
                reported_by: RUN,
                severity: "error",
                cause: "At start, run loads its eBPF program and attaches it first on TCX ingress of \
                        both ports, and that failed: run lacks CAP_BPF or CAP_NET_ADMIN, the kernel \
                        has no TCX (it needs Linux 6.6 or later) or rejected the program, or a port \
                        went away. run keeps running without it: trust lives in the program's \
                        map, so no connection is trusted and every packet is inspected (more CPU, \
                        nothing skips inspection); automatic trust is turned off (T014).",
                action: "Run as root on Linux 6.6 or later; the message has the kernel's error. See \
                         what is attached with: bpftool net show.",
            },
            Self::CoreProgramNotFirst => &Explanation {
                code: "D002",
                title: "other eBPF programs run before the core eBPF program",
                reported_by: DOCTOR_AND_RUN,
                severity: "warning",
                cause: "On a port's TCX ingress, programs that are not wnc-gw's run before its core \
                        program, which wnc-gw attached first: a loader attached them afterwards \
                        with BPF_F_BEFORE, which puts a program first. They see \
                        every packet first and can drop, redirect or change it, or its mark, \
                        before wnc-gw does. run checks every 10 seconds and logs each change.",
                action: "Find them with: bpftool net show dev <port>, and detach them, or attach \
                         them after wnc-gw's program; restart run to put the core program first \
                         again.",
            },
            Self::CoreProgramDetached => &Explanation {
                code: "D003",
                title: "the core eBPF program is no longer attached",
                reported_by: RUN,
                severity: "warning",
                cause: "run checks every 10 seconds that its core program is still on each port's \
                        TCX ingress, and it is gone: the interface was removed (a USB adapter \
                        unplugged; the attachment does not come back when it is plugged in again) \
                        or someone detached it (bpftool link detach). run does not attach it \
                        again, so the connections trusted on that port are inspected again (more \
                        CPU, nothing skips inspection).",
                action: "Restart run once the port is back (wnc-gw doctor shows the port and its \
                         TCX programs).",
            },
            Self::TcxUnchecked => &Explanation {
                code: "D004",
                title: "the TCX programs on a port cannot be listed",
                reported_by: DOCTOR_AND_RUN,
                severity: "warning",
                cause: "Listing a port's TCX ingress programs (bpf BPF_PROG_QUERY) failed, usually \
                        because doctor runs without CAP_NET_ADMIN (not root); the table shows \
                        not checked. In run it is logged when the check starts failing.",
                action: "Run doctor as root to see the programs; otherwise the message has the \
                         kernel's error.",
            },
            Self::TcxUnsupported => &Explanation {
                code: "D005",
                title: "the kernel has no TCX",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "The kernel rejected the query for TCX ingress programs, so it has no TCX \
                        (added in Linux 6.6) and run cannot attach its core eBPF program (D001), \
                        which holds trust: every connection is inspected.",
                action: "Use Linux 6.6 or later.",
            },
            Self::ForeignTcxPrograms => &Explanation {
                code: "D006",
                title: "a port has TCX programs that wnc-gw did not load",
                reported_by: DOCTOR,
                severity: "warning",
                cause: "A port's TCX ingress has eBPF programs other than wnc-gw's core program \
                        (wnc_gw_ingress). run attaches its program before them, so they see only \
                        the packets it passes on; they can still drop, redirect or change those \
                        packets. Without CAP_SYS_ADMIN doctor sees only program ids and cannot \
                        tell which one is wnc-gw's.",
                action: "Check that you know what they are: bpftool net show dev <port>, and \
                         bpftool prog show id <id>.",
            },
            Self::RoutesUnstable => &Explanation {
                code: "D007",
                title: "routes keep changing, so trusted connections use the kernel's route lookup",
                reported_by: RUN,
                severity: "warning",
                cause: "In routed mode the core eBPF program sends trusted packets to a next hop that \
                        run looked up; every route change makes all of them invalid at once, and run \
                        looks them up again only after routes have been quiet for 10 seconds. Routes \
                        changed again and again for 60 seconds (a routing daemon, IPv6 router \
                        advertisements with accept_ra = 2, a flapping link), so trusted packets have the \
                        kernel look up the route for each of them: correct, about 0.7 us slower on the \
                        Pi. Logged once; an INFO follows when routes are stable again.",
                action: "Find what keeps changing the routes with: ip monitor route.",
            },
            Self::NextHopsOff => &Explanation {
                code: "D008",
                title: "next hops are not used",
                reported_by: RUN,
                severity: "warning",
                cause: "In routed mode run could not follow route changes (subscribing to them failed, \
                        or the subscription ended), or could not invalidate the next hops. Without \
                        that, a stored next hop could go stale, so run stops using them: trusted packets \
                        have the kernel look up the route for each of them, correct but slower.",
                action: "Check the error in the message; restart run to use next hops again.",
            },
            Self::TableRemoveFailed => &Explanation {
                code: "F002",
                title: "the nft table cannot be removed at exit",
                reported_by: RUN,
                severity: "error",
                cause: "When run stopped, deleting its table failed, so the rules stay in the \
                        kernel without wnc-gw: depending on when_unavailable, forwarded traffic \
                        keeps passing uninspected or keeps being dropped.",
                action: "Remove it by hand: nft delete table inet wnc_gw (check with: nft list \
                         tables).",
            },
            Self::TableRemoved => &Explanation {
                code: "F003",
                title: "the nft table was removed and traffic passes uninspected",
                reported_by: RUN,
                severity: "warning",
                cause: "Always logged when run stops normally (SIGINT, SIGTERM, SIGHUP) or fails: \
                        its table is gone, so the kernel forwards traffic without sending it to \
                        Suricata until run starts again.",
                action: "Nothing to do if run was stopped on purpose; otherwise start it again.",
            },
            Self::StartInspectionFailed => &Explanation {
                code: "F004",
                title: "traffic cannot be switched to Suricata",
                reported_by: RUN,
                severity: "error",
                cause: "Suricata became ready, but replacing the ids chain so that traffic goes to \
                        Suricata failed in nft. run exits and removes its table.",
                action: "Check the nft error in the message, then start run again.",
            },
            Self::StopInspectionFailed => &Explanation {
                code: "F005",
                title: "traffic cannot be switched away from Suricata",
                reported_by: RUN,
                severity: "error",
                cause: "Suricata stopped (or run is shutting down), but replacing the ids chain \
                        with the not-ready rules failed in nft. With protection = \"ips\" traffic \
                        may wait for a Suricata that is gone. run does not restart Suricata and \
                        exits; on the way out it tries once more (logging I001 or I002 if that \
                        works) and then removes its table.",
                action: "Check the nft error in the message; if the table is still there after run \
                         exits, remove it with: nft delete table inet wnc_gw.",
            },
            Self::Uninspected => &Explanation {
                code: "I001",
                title: "forwarded traffic passes without inspection",
                reported_by: RUN,
                severity: "warning",
                cause: "Suricata is not ready (starting, or restarting after S015) and \
                        when_unavailable = \"accept\", so traffic is forwarded uninspected; it \
                        ends with INFO \"forwarded traffic is inspected\", which carries \
                        uninspected_ms. It is also logged once at every stop, just before F003, \
                        with no INFO after it.",
                action: "Usually nothing: it ends when Suricata is ready. If it repeats, look at \
                         S015 and S016; set when_unavailable = \"drop\" to drop that traffic \
                         instead.",
            },
            Self::DroppedUninspected => &Explanation {
                code: "I002",
                title: "forwarded traffic is dropped without inspection",
                reported_by: RUN,
                severity: "warning",
                cause: "Same as I001 with when_unavailable = \"drop\": while Suricata is not \
                        ready, forwarded traffic is dropped, so connections through the gateway \
                        fail until INFO \"forwarded traffic is inspected\". It is also logged once \
                        at every stop, just before F003.",
                action: "Usually nothing: it ends when Suricata is ready. If it repeats, look at \
                         S015 and S016.",
            },
            Self::SuricataStartFailed => &Explanation {
                code: "S014",
                title: "Suricata cannot be started",
                reported_by: RUN,
                severity: "error",
                cause: "wnc-gw could not prepare what Suricata needs (its log and runtime \
                        directories, its readiness socket), so run exits; or it could not start \
                        the Suricata process (for example the file exists but is not executable, \
                        or the NFLOG settings file in /run/wnc-gw cannot be written), which is \
                        retried with a delay that grows from 1 s to 60 s.",
                action: "Check the error in the message, for example the permissions of the \
                         Suricata binary or of /run/wnc-gw.",
            },
            Self::SuricataExited => &Explanation {
                code: "S015",
                title: "Suricata exited",
                reported_by: RUN,
                severity: "warning",
                cause: "Suricata stopped without run being asked to stop: it crashed, was killed \
                        (for example by the OOM killer or kill), failed on its config or rules, or \
                        was stopped by wnc-gw after S016. exit, uptime_s and was_ready tell which. \
                        wnc-gw starts it again after a delay that grows from 1 s to 60 s and \
                        resets once Suricata has been ready for 300 s; I001 or I002 covers the \
                        gap.",
                action: "Read the Suricata lines logged just before it (S021); for a kill by \
                         signal 9, check dmesg for the OOM killer.",
            },
            Self::SuricataNotReady => &Explanation {
                code: "S016",
                title: "Suricata did not become ready in time",
                reported_by: RUN,
                severity: "warning",
                cause: "Suricata did not report ready within [suricata] ready_timeout (default 300 \
                        s), usually because loading a large rule set on a slow CPU takes longer, \
                        or it is stuck. wnc-gw stops it and starts it again.",
                action: "Raise [suricata] ready_timeout, or load fewer rules.",
            },
            Self::SuricataStopSlow => &Explanation {
                code: "S017",
                title: "Suricata did not stop in time",
                reported_by: RUN,
                severity: "warning",
                cause: "After SIGTERM, Suricata did not exit within [suricata] stop_timeout \
                        (default 90 s), so wnc-gw killed it with SIGKILL. This can happen when it \
                        is still flushing work under heavy load.",
                action: "Raise [suricata] stop_timeout if Suricata needs longer to stop.",
            },
            Self::QueueBusy => &Explanation {
                code: "S018",
                title: "Suricata cannot bind its NFQUEUE",
                reported_by: RUN,
                severity: "error",
                cause: "With protection = \"ips\", Suricata failed to bind the NFQUEUE number \
                        wnc-gw uses, because another program (often another Suricata, see O004) \
                        already holds it. Suricata exits and wnc-gw keeps restarting it.",
                action: "Stop the other program (check with: cat \
                         /proc/net/netfilter/nfnetlink_queue), or set [suricata] queue to free \
                         numbers.",
            },
            Self::NflogBusy => &Explanation {
                code: "S019",
                title: "Suricata cannot bind its NFLOG group",
                reported_by: RUN,
                severity: "error",
                cause: "With protection = \"ids\", Suricata failed to bind the NFLOG group wnc-gw \
                        uses, because another program (often another Suricata, see O005) already \
                        holds it. Suricata exits and wnc-gw keeps restarting it.",
                action: "Stop the other program, or set [suricata] group to a free group.",
            },
            Self::RulesFailed => &Explanation {
                code: "S020",
                title: "Suricata could not load some rules",
                reported_by: RUN,
                severity: "warning",
                cause: "Suricata reported that some rules failed to load, usually because they use \
                        keywords this Suricata version does not support or have syntax errors. \
                        Those rules detect nothing; the rest work.",
                action: "Find them with: suricata -T -c /etc/suricata/suricata.yaml -v, and update \
                         or remove them (suricata-update fetches rules for the installed version).",
            },
            Self::SuricataMessage => &Explanation {
                code: "S021",
                title: "Suricata logged a warning or error",
                reported_by: RUN,
                severity: "error or warning",
                cause: "A line Suricata itself printed at warning or error level, forwarded with \
                        source=suricata and its pid. The text is Suricata's own; wnc-gw adds a \
                        code of its own only for the lines it recognizes (S018, S019, S020).",
                action: "Read the text; Suricata's documentation explains its messages.",
            },
            Self::CopiesMissed => &Explanation {
                code: "S022",
                title: "Suricata missed packet copies",
                reported_by: RUN,
                severity: "warning",
                cause: "With protection = \"ids\", the kernel discarded copies that did not fit \
                        into Suricata's NFLOG socket buffer during the last 10 s (missed is the \
                        count), so that traffic was forwarded uninspected (see S009). Bursts, \
                        scans and large untrusted transfers cause it.",
                action: "Use more NFLOG groups (for example [suricata] group = \"10-12\"), or set \
                         protection = \"ips\".",
            },
            Self::CopiesUncounted => &Explanation {
                code: "S023",
                title: "missed packet copies cannot be counted",
                reported_by: RUN,
                severity: "warning",
                cause: "wnc-gw cannot read Suricata's NFLOG sockets from /proc (only root can read \
                        them), or cannot find them for the current Suricata, so S022 cannot be \
                        reported. A read failure is logged once, with INFO when it works again; a \
                        missing socket is logged once per Suricata start.",
                action: "Run wnc-gw run as root.",
            },
            Self::AlertFileUnknown => &Explanation {
                code: "S024",
                title: "Suricata's config cannot be read at start",
                reported_by: RUN,
                severity: "warning",
                cause: "run asks Suricata (--dump-config) where it writes alerts, and that failed, \
                        so wnc-gw does not read alerts: they are not logged and automatic trust is \
                        not revoked by them.",
                action: "Check suricata --dump-config -c <config> by hand; wnc-gw doctor shows the \
                         same problem as S010.",
            },
            Self::EveSkipped => &Explanation {
                code: "E001",
                title: "EVE lines were skipped",
                reported_by: RUN,
                severity: "warning",
                cause: "Some alert lines in Suricata's EVE file (lines with \
                        \"event_type\":\"alert\") were not valid JSON or lacked the alert object \
                        (malformed), or a line was longer than 1 MiB (too_long), so wnc-gw skipped \
                        them and missed those alerts. Other event types are not parsed, so their \
                        broken lines are not counted.",
                action: "Check the EVE file around that time; another writer to the same file can \
                         cause malformed lines.",
            },
            Self::EveUnreadable => &Explanation {
                code: "E002",
                title: "the EVE file cannot be read",
                reported_by: RUN,
                severity: "warning",
                cause: "Reading Suricata's EVE file failed, for example because of its permissions \
                        or because its directory was removed. Until it can be read again (INFO), \
                        alerts are not logged and do not revoke trust. Logged once.",
                action: "Check the path in the message and its permissions.",
            },
            Self::EveBehind => &Explanation {
                code: "E003",
                title: "wnc-gw reads the EVE file late",
                reported_by: RUN,
                severity: "warning",
                cause: "Suricata wrote more than wnc-gw reads per eve_interval (at most 32 MiB), \
                        usually because the EVE output has many event types besides alert. Alerts \
                        reach wnc-gw late, so trust is revoked late. INFO when it catches up.",
                action: "Keep only the alert type in the eve-log output wnc-gw reads, or lower \
                         [suricata] eve_interval.",
            },
            Self::ConntrackNearlyFull => &Explanation {
                code: "M001",
                title: "the conntrack table is nearly full",
                reported_by: RUN,
                severity: "warning",
                cause: "The number of tracked connections reached 90% of \
                        net.netfilter.nf_conntrack_max. When it is full, new connections are \
                        dropped. Scans and floods cause it. INFO when it falls below 80%.",
                action: "Raise net.netfilter.nf_conntrack_max, or find the source of the \
                         connections (conntrack -L).",
            },
            Self::ConntrackDropped => &Explanation {
                code: "M002",
                title: "conntrack dropped packets",
                reported_by: RUN,
                severity: "warning",
                cause: "conntrack's drop or insert_failed counters grew during the last 10 s: \
                        packets of new connections were dropped, usually because the table was \
                        full (M001).",
                action: "Same as M001.",
            },
            Self::ConntrackEvicted => &Explanation {
                code: "M003",
                title: "conntrack evicted connections to make room",
                reported_by: RUN,
                severity: "warning",
                cause: "conntrack's early_drop counter grew during the last 10 s: the table was \
                        full and the kernel removed unanswered (unassured) connections to fit new \
                        ones.",
                action: "Same as M001.",
            },
            Self::ConntrackStatsUnreadable => &Explanation {
                code: "M004",
                title: "conntrack statistics cannot be read",
                reported_by: RUN,
                severity: "warning",
                cause: "Reading conntrack's statistics over ctnetlink failed, usually because run \
                        lacks CAP_NET_ADMIN or nf_conntrack_netlink is missing. M001 to M003 \
                        cannot be reported. Logged once; INFO when it works again.",
                action: "Run wnc-gw run as root and check the kernel modules with wnc-gw doctor.",
            },
            Self::ConntrackUnreadable => &Explanation {
                code: "T006",
                title: "the conntrack table cannot be read; automatic trust is paused",
                reported_by: RUN,
                severity: "warning",
                cause: "Automatic trust reads the conntrack table every check_interval and that \
                        failed, usually because ctnetlink is unavailable. No connection is trusted \
                        until it works again. Logged once.",
                action: "Run as root and check with: conntrack -L.",
            },
            Self::NoPacketCounters => &Explanation {
                code: "T007",
                title: "conntrack keeps no packet counters",
                reported_by: RUN,
                severity: "warning",
                cause: "Automatic trust needs each connection's packet counts, but conntrack keeps \
                        none: net.netfilter.nf_conntrack_acct is 0, or was set to 1 after these \
                        connections started. None of them can be trusted. Logged once.",
                action: "Set it with: sysctl -w net.netfilter.nf_conntrack_acct=1; it applies to \
                         connections that start after that.",
            },
            Self::TrustFailed => &Explanation {
                code: "T008",
                title: "a connection cannot be trusted",
                reported_by: RUN,
                severity: "warning",
                cause: "Writing a connection into the core eBPF program's trust map failed, \
                        usually because the map is full (32768 entries: 16384 connections, one \
                        entry per direction). The connection simply stays inspected.",
                action: "Nothing is needed for that connection; if it repeats, see how many are \
                         trusted with: wnc-gw trust list.",
            },
            Self::ExpireFailed => &Explanation {
                code: "T009",
                title: "trust cannot be ended",
                reported_by: RUN,
                severity: "error",
                cause: "A trusted connection reached its ttl, but removing it from the trust map \
                        failed, so it keeps skipping inspection until run stops or the same TCP \
                        connection starts again (a new SYN).",
                action: "Remove it with: wnc-gw trust del.",
            },
            Self::TrustRevoked => &Explanation {
                code: "T010",
                title: "Suricata alerted on a trusted connection",
                reported_by: RUN,
                severity: "warning",
                cause: "A connection was already trusted when an alert for it arrived, so its \
                        trust was removed and it is inspected again. With protection = \"ids\", an \
                        alert on a quiet connection can arrive after it was trusted.",
                action: "Look at the alert (sid, signature) and the connection; the traffic sent \
                         while it was trusted was not inspected.",
            },
            Self::RevokeFailed => &Explanation {
                code: "T011",
                title: "trust cannot be revoked after an alert",
                reported_by: RUN,
                severity: "error",
                cause: "Suricata alerted on a trusted connection, but removing it from the trust \
                        map failed, so the connection keeps skipping inspection until run stops or \
                        the same TCP connection starts again (a new SYN).",
                action: "Remove it with wnc-gw trust del, and look at the alert.",
            },
        }
    }

    pub fn code(self) -> &'static str {
        self.explanation().code
    }
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown code {0:?} (run wnc-gw explain to list them)")]
pub struct ParseIssueError(String);

impl FromStr for Issue {
    type Err = ParseIssueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Issue::ALL
            .iter()
            .copied()
            .find(|issue| issue.code().eq_ignore_ascii_case(s))
            .ok_or_else(|| ParseIssueError(s.to_owned()))
    }
}

#[cfg(test)]
mod tests;
