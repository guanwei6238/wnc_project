use super::*;

const EM_BPF: u16 = 247;

#[test]
fn embedded_object_is_a_bpf_elf() {
    let elf = &ELF.0;
    assert_eq!(&elf[..4], b"\x7fELF", "embedded object is not an ELF file");
    assert_eq!(u16::from_le_bytes([elf[18], elf[19]]), EM_BPF, "embedded object is not for the BPF machine");
}

#[test]
fn embedded_object_has_the_program_map_and_license() {
    let elf = &ELF.0;
    for name in [CORE_PROGRAM_NAME, PACKETS, "Dual MIT/GPL"] {
        assert!(
            elf.windows(name.len()).any(|w| w == name.as_bytes()),
            "embedded object has no {name:?}"
        );
    }
}
