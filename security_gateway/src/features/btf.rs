const MAGIC: u16 = 0xeb9f;
const KIND_INT: u32 = 1;
const KIND_PTR: u32 = 2;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_FWD: u32 = 7;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC: u32 = 12;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_FLOAT: u32 = 16;
const KIND_DECL_TAG: u32 = 17;
const KIND_TYPE_TAG: u32 = 18;
const KIND_ENUM64: u32 = 19;
const MAX_DEPTH: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BtfError {
    #[error("BTF is truncated")]
    Truncated,
    #[error("BTF has the wrong magic number (not little-endian BTF)")]
    Magic,
    #[error("BTF has a type of unknown kind {0}")]
    UnknownKind(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    Int { name: String, size: u32, signed: bool },
    Ptr(u32),
    Array { elem: u32, len: u32 },
    Struct { name: String, size: u32, members: Vec<Member> },
    Union { size: u32 },
    Enum { size: u32 },
    Alias(u32),
    Var { name: String, ty: u32 },
    Datasec { name: String, vars: Vec<u32> },
    Float { size: u32 },
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    pub ty: u32,
    pub bit_offset: u32,
    pub bitfield: bool,
}

/// What a type looks like once typedefs and qualifiers are removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shape {
    Int { size: u32, signed: bool },
    Array { elem: Box<Shape>, len: u32 },
    Struct { size: u32, members: Vec<(Member, Shape)> },
    Other { size: Option<u32>, what: &'static str },
}

impl Shape {
    pub fn size(&self) -> Option<u32> {
        match self {
            Self::Int { size, .. } | Self::Struct { size, .. } => Some(*size),
            Self::Array { elem, len } => elem.size().map(|s| s * len),
            Self::Other { size, .. } => *size,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Btf {
    types: Vec<Type>,
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn u32(&mut self) -> Result<u32, BtfError> {
        let bytes = self.data.get(self.at..self.at + 4).ok_or(BtfError::Truncated)?;
        self.at += 4;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }
}

impl Btf {
    pub fn parse(data: &[u8]) -> Result<Self, BtfError> {
        let header = data.get(..24).ok_or(BtfError::Truncated)?;
        if u16::from_le_bytes([header[0], header[1]]) != MAGIC {
            return Err(BtfError::Magic);
        }
        let word = |i: usize| u32::from_le_bytes(header[i..i + 4].try_into().unwrap()) as usize;
        let (hdr_len, type_off, type_len, str_off, str_len) = (word(4), word(8), word(12), word(16), word(20));
        let types = data
            .get(hdr_len + type_off..hdr_len + type_off + type_len)
            .ok_or(BtfError::Truncated)?;
        let strings = data.get(hdr_len + str_off..hdr_len + str_off + str_len).ok_or(BtfError::Truncated)?;
        let name = |offset: u32| -> String {
            let rest = strings.get(offset as usize..).unwrap_or_default();
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            String::from_utf8_lossy(&rest[..end]).into_owned()
        };
        let mut r = Reader { data: types, at: 0 };
        let mut out = vec![Type::Other];
        while r.at < types.len() {
            let name_off = r.u32()?;
            let info = r.u32()?;
            let size_or_type = r.u32()?;
            let vlen = info & 0xffff;
            let kind = (info >> 24) & 0x1f;
            let kind_flag = info >> 31 == 1;
            let ty = match kind {
                KIND_INT => {
                    let encoding = r.u32()?;
                    Type::Int { name: name(name_off), size: size_or_type, signed: (encoding >> 24) & 1 == 1 }
                }
                KIND_PTR => Type::Ptr(size_or_type),
                KIND_ARRAY => {
                    let elem = r.u32()?;
                    let _index = r.u32()?;
                    Type::Array { elem, len: r.u32()? }
                }
                KIND_STRUCT | KIND_UNION => {
                    let mut members = Vec::with_capacity(vlen as usize);
                    for _ in 0..vlen {
                        let member_name = r.u32()?;
                        let ty = r.u32()?;
                        let offset = r.u32()?;
                        members.push(Member {
                            name: name(member_name),
                            ty,
                            bit_offset: if kind_flag { offset & 0xff_ffff } else { offset },
                            bitfield: kind_flag && offset >> 24 != 0,
                        });
                    }
                    if kind == KIND_STRUCT {
                        Type::Struct { name: name(name_off), size: size_or_type, members }
                    } else {
                        Type::Union { size: size_or_type }
                    }
                }
                KIND_ENUM | KIND_ENUM64 => {
                    let words = if kind == KIND_ENUM { 2 } else { 3 };
                    for _ in 0..vlen * words {
                        r.u32()?;
                    }
                    Type::Enum { size: size_or_type }
                }
                KIND_FWD | KIND_FUNC => Type::Other,
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => Type::Alias(size_or_type),
                KIND_FUNC_PROTO => {
                    for _ in 0..vlen * 2 {
                        r.u32()?;
                    }
                    Type::Other
                }
                KIND_VAR => {
                    r.u32()?;
                    Type::Var { name: name(name_off), ty: size_or_type }
                }
                KIND_DATASEC => {
                    let mut vars = Vec::with_capacity(vlen as usize);
                    for _ in 0..vlen {
                        vars.push(r.u32()?);
                        r.u32()?;
                        r.u32()?;
                    }
                    Type::Datasec { name: name(name_off), vars }
                }
                KIND_FLOAT => Type::Float { size: size_or_type },
                KIND_DECL_TAG => {
                    r.u32()?;
                    Type::Other
                }
                other => return Err(BtfError::UnknownKind(other)),
            };
            out.push(ty);
        }
        Ok(Self { types: out })
    }

    fn get(&self, id: u32) -> Option<&Type> {
        self.types.get(id as usize)
    }

    fn strip(&self, mut id: u32) -> Option<u32> {
        for _ in 0..MAX_DEPTH {
            match self.get(id)? {
                Type::Alias(next) => id = *next,
                _ => return Some(id),
            }
        }
        None
    }

    pub fn shape(&self, id: u32) -> Shape {
        self.shape_at(id, 0)
    }

    fn shape_at(&self, id: u32, depth: usize) -> Shape {
        let unknown = Shape::Other { size: None, what: "a type that cannot be resolved" };
        if depth > MAX_DEPTH {
            return unknown;
        }
        let Some(ty) = self.strip(id).and_then(|id| self.get(id)) else { return unknown };
        match ty {
            Type::Int { size, signed, .. } => Shape::Int { size: *size, signed: *signed },
            Type::Enum { size } => Shape::Int { size: *size, signed: false },
            Type::Array { elem, len } => Shape::Array { elem: Box::new(self.shape_at(*elem, depth + 1)), len: *len },
            Type::Struct { size, members, .. } => Shape::Struct {
                size: *size,
                members: members.iter().map(|m| (m.clone(), self.shape_at(m.ty, depth + 1))).collect(),
            },
            Type::Union { size } => Shape::Other { size: Some(*size), what: "a union" },
            Type::Ptr(_) => Shape::Other { size: Some(8), what: "a pointer" },
            Type::Float { size } => Shape::Other { size: Some(*size), what: "a float" },
            _ => unknown,
        }
    }

    /// Key and value types of a map declared the libbpf way (a variable in the `.maps` section
    /// whose struct has `key` and `value` members pointing at the types). Maps declared in the
    /// legacy `maps` section (aya-ebpf's default) have no BTF, so this returns None for them.
    pub fn map_types(&self, map: &str) -> Option<MapTypes> {
        let vars = self.types.iter().find_map(|t| match t {
            Type::Datasec { name, vars } if name == ".maps" => Some(vars),
            _ => None,
        })?;
        let def = vars.iter().find_map(|&v| match self.get(v)? {
            Type::Var { name, ty } if name == map => Some(*ty),
            _ => None,
        })?;
        let Type::Struct { members, .. } = self.get(self.strip(def)?)? else { return None };
        let pointee = |field: &str| -> Option<u32> {
            let member = members.iter().find(|m| m.name == field)?;
            match self.get(self.strip(member.ty)?)? {
                Type::Ptr(target) => Some(*target),
                _ => None,
            }
        };
        Some(MapTypes { key: pointee("key"), value: pointee("value") })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapTypes {
    pub key: Option<u32>,
    pub value: Option<u32>,
}

#[cfg(test)]
pub(crate) mod tests;
