use super::*;

const PROC_MODULES: &str = "\
nf_tables 389120 1 nft_compat, Live 0x0000000000000000
nf_conntrack 196608 4 xt_conntrack,nf_nat,xt_MASQUERADE,xt_nat, Live 0x0000000000000000
";

const BUILTIN: &str = "\
kernel/net/netfilter/nft_ct.ko
kernel/drivers/net/dummy.ko
";

const DEP: &str = "\
kernel/net/netfilter/nft_queue.ko.zst: kernel/net/netfilter/nfnetlink_queue.ko.zst
kernel/net/netfilter/nfnetlink_queue.ko.zst:
kernel/net/netfilter/nf_tables.ko.zst: kernel/net/netfilter/nfnetlink.ko.zst
kernel/drivers/net/usb/ax88179_178a.ko.xz:
";

fn index() -> ModuleIndex {
    ModuleIndex::from_parts("7.0.0-38-generic\n", PROC_MODULES, Some(BUILTIN), Some(DEP))
}

#[test]
fn release_is_trimmed() {
    assert_eq!(index().release(), "7.0.0-38-generic");
}

#[test]
fn states() {
    let index = index();
    assert_eq!(index.state("nf_tables"), ModuleState::Loaded);
    assert_eq!(index.state("nft_ct"), ModuleState::Builtin);
    assert_eq!(index.state("nft_queue"), ModuleState::Loadable);
    assert_eq!(index.state("nfnetlink_queue"), ModuleState::Loadable);
    assert_eq!(index.state("nft_fib"), ModuleState::Missing);
}

#[test]
fn loaded_takes_precedence_over_module_file() {
    assert_eq!(index().state("nf_tables"), ModuleState::Loaded);
}

#[test]
fn dash_and_underscore_are_the_same() {
    let index = index();
    assert_eq!(index.state("nf-tables"), ModuleState::Loaded);
    assert_eq!(index.state("ax88179-178a"), ModuleState::Loadable);
}

#[test]
fn unknown_without_module_tree() {
    let index = ModuleIndex::from_parts("6.12.47", PROC_MODULES, None, Some(DEP));
    assert_eq!(index.state("nf_tables"), ModuleState::Loaded);
    assert_eq!(index.state("nft_queue"), ModuleState::Unknown);
}

#[test]
fn module_name_from_path() {
    assert_eq!(module_name("kernel/net/netfilter/nft_ct.ko").as_deref(), Some("nft_ct"));
    assert_eq!(module_name("kernel/net/netfilter/nft_queue.ko.zst").as_deref(), Some("nft_queue"));
    assert_eq!(module_name("  kernel/x/ax88179_178a.ko.xz ").as_deref(), Some("ax88179_178a"));
    assert_eq!(module_name("kernel/x/not-a-module.txt"), None);
    assert_eq!(module_name(""), None);
}
