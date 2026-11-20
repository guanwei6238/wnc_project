use super::*;

#[derive(Default)]
pub(crate) struct Builder {
    types: Vec<u32>,
    strings: Vec<u8>,
    count: u32,
}

impl Builder {
    pub(crate) fn new() -> Self {
        Self { strings: vec![0], ..Self::default() }
    }

    fn name(&mut self, name: &str) -> u32 {
        if name.is_empty() {
            return 0;
        }
        let at = self.strings.len() as u32;
        self.strings.extend(name.as_bytes());
        self.strings.push(0);
        at
    }

    fn push(&mut self, words: &[u32]) -> u32 {
        self.types.extend(words);
        self.count += 1;
        self.count
    }

    pub(crate) fn int(&mut self, name: &str, size: u32, signed: bool) -> u32 {
        let n = self.name(name);
        self.push(&[n, KIND_INT << 24, size, (u32::from(signed) << 24) | (size * 8)])
    }

    pub(crate) fn typedef(&mut self, name: &str, ty: u32) -> u32 {
        let n = self.name(name);
        self.push(&[n, KIND_TYPEDEF << 24, ty])
    }

    pub(crate) fn ptr(&mut self, ty: u32) -> u32 {
        self.push(&[0, KIND_PTR << 24, ty])
    }

    pub(crate) fn array(&mut self, elem: u32, index: u32, len: u32) -> u32 {
        self.push(&[0, KIND_ARRAY << 24, 0, elem, index, len])
    }

    pub(crate) fn structure(&mut self, name: &str, size: u32, members: &[(&str, u32, u32)]) -> u32 {
        let n = self.name(name);
        let mut words = vec![n, (KIND_STRUCT << 24) | members.len() as u32, size];
        for (member, ty, bit_offset) in members {
            let m = self.name(member);
            words.extend([m, *ty, *bit_offset]);
        }
        self.push(&words)
    }

    pub(crate) fn bitfield_struct(&mut self, name: &str, size: u32, member: &str, ty: u32) -> u32 {
        let n = self.name(name);
        let m = self.name(member);
        self.push(&[n, (1 << 31) | (KIND_STRUCT << 24) | 1, size, m, ty, 3 << 24])
    }

    pub(crate) fn map(&mut self, name: &str, key: u32, value: u32) -> u32 {
        let def = self.structure("", 16, &[("key", 0, 0), ("value", 0, 64)]);
        let at = self.types.len() - 6;
        let key_ptr = self.ptr(key);
        let value_ptr = self.ptr(value);
        self.types[at + 1] = key_ptr;
        self.types[at + 4] = value_ptr;
        let n = self.name(name);
        let var = self.push(&[n, KIND_VAR << 24, def, 1]);
        let sec = self.name(".maps");
        self.push(&[sec, (KIND_DATASEC << 24) | 1, 16, var, 0, 16])
    }

    pub(crate) fn bytes(&self) -> Vec<u8> {
        let types: Vec<u8> = self.types.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut out = Vec::new();
        out.extend(MAGIC.to_le_bytes());
        out.extend([1, 0]);
        for word in [24u32, 0, types.len() as u32, types.len() as u32, self.strings.len() as u32] {
            out.extend(word.to_le_bytes());
        }
        out.extend(types);
        out.extend(&self.strings);
        out
    }
}

#[test]
fn reads_a_libbpf_style_map() {
    let mut b = Builder::new();
    let u32_ = b.int("unsigned int", 4, false);
    let be32 = b.typedef("__be32", u32_);
    let u16_ = b.int("unsigned short", 2, false);
    let key = b.structure("flow_key", 8, &[("saddr", be32, 0), ("sport", u16_, 32)]);
    let value = b.structure("flow_val", 4, &[("packets", u32_, 0)]);
    b.map("FLOWS", key, value);
    let btf = Btf::parse(&b.bytes()).unwrap();
    let types = btf.map_types("FLOWS").unwrap();
    assert_eq!(types, MapTypes { key: Some(key), value: Some(value) });
    assert_eq!(btf.map_types("OTHER"), None);
    let Shape::Struct { size: 8, members } = btf.shape(key) else { panic!("not a struct") };
    assert_eq!(members[0].1, Shape::Int { size: 4, signed: false });
    assert_eq!(members[1].0.bit_offset, 32);
}

#[test]
fn arrays_and_bitfields() {
    let mut b = Builder::new();
    let u32_ = b.int("unsigned int", 4, false);
    let arr = b.array(u32_, u32_, 8);
    assert_eq!(Btf::parse(&b.bytes()).unwrap().shape(arr).size(), Some(32));
    let bits = b.bitfield_struct("b", 4, "x", u32_);
    let Shape::Struct { members, .. } = Btf::parse(&b.bytes()).unwrap().shape(bits) else { panic!() };
    assert!(members[0].0.bitfield);
}

#[test]
fn bad_input() {
    assert_eq!(Btf::parse(&[0; 10]).unwrap_err(), BtfError::Truncated);
    let mut bytes = Builder::new().bytes();
    bytes[0] = 0;
    assert_eq!(Btf::parse(&bytes).unwrap_err(), BtfError::Magic);
    let mut b = Builder::new();
    b.push(&[0, 31 << 24, 0]);
    assert_eq!(Btf::parse(&b.bytes()).unwrap_err(), BtfError::UnknownKind(31));
    let mut b = Builder::new();
    let a = b.typedef("a", 2);
    b.typedef("b", a);
    assert!(matches!(Btf::parse(&b.bytes()).unwrap().shape(a), Shape::Other { .. }), "a typedef loop is not followed forever");
}
