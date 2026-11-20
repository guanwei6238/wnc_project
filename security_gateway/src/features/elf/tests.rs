use super::*;

#[repr(C, align(8))]
struct Aligned<T: ?Sized>(T);

static CORE: &Aligned<[u8]> = &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/gw-ebpf")));

#[test]
fn reads_programs_and_maps_of_the_core_program() {
    let elf = inspect(&CORE.0).unwrap();
    assert_eq!(elf.programs.get("wnc_gw_ingress"), Some(&ProgramKind::Classifier));
    let trust = elf.maps["TRUST"];
    assert_eq!(trust.kind, MapKind::Hash);
    assert_eq!(trust.key_size as usize, size_of::<gw_common::FlowKey>());
    assert_eq!(trust.value_size as usize, size_of::<gw_common::FlowStats>());
    assert_eq!(elf.maps["COUNTERS"].kind, MapKind::PerCpuArray);
    assert!(matches!(elf.btf, Some(Ok(_))), "the core program is built with BTF");
    let Some(Ok(btf)) = &elf.btf else { unreachable!() };
    assert_eq!(btf.map_types("TRUST"), None, "aya's legacy maps section has no BTF map definition");
}

#[test]
fn garbage_is_an_error() {
    assert!(inspect(b"not an elf").is_err());
}
