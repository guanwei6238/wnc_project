use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use netlink_packet_core::{
    NLA_F_NESTED, NLA_TYPE_MASK, NLMSG_DONE, NLMSG_ERROR, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkBuffer,
    NlasIterator, parse_i32, parse_ip, parse_u16_be, parse_u32_be, parse_u64_be, parse_u8,
};
use netlink_sys::{Socket, SocketAddr as NetlinkAddr};
use netlink_sys::protocols::NETLINK_NETFILTER;

const RECV_BUF: usize = 64 * 1024;
const BATCH: usize = 100;
const MSG_NEW: u16 = 1 << 8;
const MSG_GET: u16 = (1 << 8) | 1;
const MSG_GET_STATS_CPU: u16 = (1 << 8) | 4;
const MSG_GET_STATS: u16 = (1 << 8) | 5;
const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_PROTOINFO: u16 = 4;
const CTA_TIMEOUT: u16 = 7;
const CTA_MARK: u16 = 8;
const CTA_COUNTERS_ORIG: u16 = 9;
const CTA_COUNTERS_REPLY: u16 = 10;
const CTA_ID: u16 = 12;
const CTA_MARK_MASK: u16 = 21;
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;
const CTA_COUNTERS_PACKETS: u16 = 1;
const CTA_COUNTERS_BYTES: u16 = 2;
const CTA_PROTOINFO_TCP: u16 = 1;
const CTA_PROTOINFO_TCP_STATE: u16 = 1;
const CTA_STATS_INSERT_FAILED: u16 = 9;
const CTA_STATS_DROP: u16 = 10;
const CTA_STATS_EARLY_DROP: u16 = 11;
const CTA_STATS_GLOBAL_ENTRIES: u16 = 1;
const CTA_STATS_GLOBAL_MAX_ENTRIES: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Other(u8),
}

impl Protocol {
    fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Other(n) => n,
        }
    }

    fn from_number(n: u8) -> Self {
        match n {
            6 => Self::Tcp,
            17 => Self::Udp,
            n => Self::Other(n),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
            Self::Other(n) => write!(f, "{n}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid protocol {0:?} (expected \"tcp\", \"udp\" or a protocol number)")]
pub struct ParseProtocolError(String);

impl FromStr for Protocol {
    type Err = ParseProtocolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ if s.bytes().all(|b| b.is_ascii_digit()) => {
                s.parse().map(Self::from_number).map_err(|_| ParseProtocolError(s.to_owned()))
            }
            _ => Err(ParseProtocolError(s.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    protocol: Protocol,
    src: SocketAddr,
    dst: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("source {src} and destination {dst} are not the same IP version")]
pub struct MixedFamilyError {
    src: IpAddr,
    dst: IpAddr,
}

impl FiveTuple {
    pub fn new(protocol: Protocol, src: SocketAddr, dst: SocketAddr) -> Result<Self, MixedFamilyError> {
        if src.is_ipv4() != dst.is_ipv4() {
            return Err(MixedFamilyError { src: src.ip(), dst: dst.ip() });
        }
        Ok(Self { protocol, src, dst })
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn src(&self) -> SocketAddr {
        self.src
    }

    pub fn dst(&self) -> SocketAddr {
        self.dst
    }

    fn family(&self) -> u8 {
        if self.src.is_ipv4() { AF_INET } else { AF_INET6 }
    }
}

impl fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} -> {}", self.protocol, self.src, self.dst)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    None,
    SynSent,
    SynRecv,
    Established,
    FinWait,
    CloseWait,
    LastAck,
    TimeWait,
    Close,
    SynSent2,
    Unknown(u8),
}

impl From<u8> for TcpState {
    fn from(n: u8) -> Self {
        match n {
            0 => Self::None,
            1 => Self::SynSent,
            2 => Self::SynRecv,
            3 => Self::Established,
            4 => Self::FinWait,
            5 => Self::CloseWait,
            6 => Self::LastAck,
            7 => Self::TimeWait,
            8 => Self::Close,
            9 => Self::SynSent2,
            n => Self::Unknown(n),
        }
    }
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "NONE",
            Self::SynSent => "SYN_SENT",
            Self::SynRecv => "SYN_RECV",
            Self::Established => "ESTABLISHED",
            Self::FinWait => "FIN_WAIT",
            Self::CloseWait => "CLOSE_WAIT",
            Self::LastAck => "LAST_ACK",
            Self::TimeWait => "TIME_WAIT",
            Self::Close => "CLOSE",
            Self::SynSent2 => "SYN_SENT2",
            Self::Unknown(n) => return write!(f, "UNKNOWN({n})"),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub id: u32,
    pub original: FiveTuple,
    pub reply: FiveTuple,
    pub tcp_state: Option<TcpState>,
    pub timeout_s: Option<u32>,
    pub mark: u32,
    pub original_counters: Option<Counters>,
    pub reply_counters: Option<Counters>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stats {
    pub entries: u32,
    pub max: u32,
    pub cpus: Vec<CpuStats>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuStats {
    pub cpu: u16,
    pub drop: u32,
    pub early_drop: u32,
    pub insert_failed: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum ConntrackError {
    #[error("failed to open a ctnetlink socket: {0}")]
    Connect(io::Error),
    #[error("connection not found")]
    NotFound,
    #[error("operation not permitted (ctnetlink needs CAP_NET_ADMIN)")]
    PermissionDenied,
    #[error("ctnetlink request failed: {0}")]
    Kernel(io::Error),
    #[error("ctnetlink socket error: {0}")]
    Socket(io::Error),
    #[error("no reply from ctnetlink")]
    NoReply,
    #[error("malformed ctnetlink reply: {0}")]
    Malformed(String),
}

pub struct Conntrack {
    socket: Socket,
    seq: u32,
    buf: Vec<u8>,
}

impl Conntrack {
    pub fn connect() -> Result<Self, ConntrackError> {
        let mut socket = Socket::new(NETLINK_NETFILTER).map_err(ConntrackError::Connect)?;
        socket.bind_auto().map_err(ConntrackError::Connect)?;
        socket.connect(&NetlinkAddr::new(0, 0)).map_err(ConntrackError::Connect)?;
        socket.set_non_blocking(true).map_err(ConntrackError::Connect)?;
        Ok(Self { socket, seq: 0, buf: Vec::with_capacity(RECV_BUF) })
    }

    pub fn set_mark(&mut self, tuple: &FiveTuple, value: u32, mask: u32) -> Result<(), ConntrackError> {
        let seq = self.next_seq();
        self.send(&set_mark_request(seq, tuple, value, mask))?;
        loop {
            if self.receive(seq)?.contains(&Reply::Ack) {
                return Ok(());
            }
        }
    }

    pub fn get(&mut self, tuple: &FiveTuple) -> Result<Connection, ConntrackError> {
        let seq = self.next_seq();
        self.send(&get_request(seq, tuple))?;
        loop {
            for reply in self.receive(seq)? {
                if let Reply::Connection(c) = reply {
                    return Ok(c);
                }
            }
        }
    }

    pub fn list(&mut self, mark: u32, mask: u32) -> Result<Vec<Connection>, ConntrackError> {
        let seq = self.next_seq();
        self.send(&list_request(seq, mark, mask))?;
        let mut connections = Vec::new();
        loop {
            for reply in self.receive(seq)? {
                match reply {
                    Reply::Connection(c) => connections.push(c),
                    Reply::Done => return Ok(connections),
                    _ => {}
                }
            }
        }
    }

    pub fn stats(&mut self) -> Result<Stats, ConntrackError> {
        let seq = self.next_seq();
        self.send(&stats_request(seq))?;
        let (entries, max) = 'global: loop {
            for reply in self.receive(seq)? {
                if let Reply::Global { entries, max } = reply {
                    break 'global (entries, max);
                }
            }
        };
        let seq = self.next_seq();
        self.send(&cpu_stats_request(seq))?;
        let mut cpus = Vec::new();
        loop {
            for reply in self.receive(seq)? {
                match reply {
                    Reply::Cpu(c) => cpus.push(c),
                    Reply::Done => return Ok(Stats { entries, max, cpus }),
                    _ => {}
                }
            }
        }
    }

    pub fn set_marks(
        &mut self,
        tuples: &[FiveTuple],
        value: u32,
        mask: u32,
    ) -> Result<Vec<(FiveTuple, ConntrackError)>, ConntrackError> {
        let mut failed = Vec::new();
        for chunk in tuples.chunks(BATCH) {
            let first = self.seq.wrapping_add(1);
            self.seq = self.seq.wrapping_add(chunk.len() as u32);
            self.send(&set_marks_request(first, chunk, value, mask))?;
            loop {
                self.recv()?;
                let (errors, done) = parse_batch_replies(&self.buf, first, self.seq)?;
                failed.extend(errors.into_iter().map(|(seq, e)| (chunk[seq.wrapping_sub(first) as usize], e)));
                if done {
                    break;
                }
            }
        }
        Ok(failed)
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    fn send(&self, request: &[u8]) -> Result<(), ConntrackError> {
        self.socket.send(request, 0).map(drop).map_err(ConntrackError::Socket)
    }

    fn receive(&mut self, seq: u32) -> Result<Vec<Reply>, ConntrackError> {
        self.recv()?;
        parse_replies(&self.buf, seq)
    }

    fn recv(&mut self) -> Result<(), ConntrackError> {
        self.buf.clear();
        match self.socket.recv(&mut self.buf, 0) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(ConntrackError::NoReply),
            Err(e) => Err(ConntrackError::Socket(e)),
        }
    }
}

fn set_mark_request(seq: u32, tuple: &FiveTuple, value: u32, mask: u32) -> Vec<u8> {
    let mut r = Request::new(MSG_NEW, NLM_F_REQUEST | NLM_F_ACK, seq, tuple.family());
    r.tuple(CTA_TUPLE_ORIG, tuple);
    r.attr(CTA_MARK, &(value & mask).to_be_bytes());
    r.attr(CTA_MARK_MASK, &mask.to_be_bytes());
    r.finish()
}

fn set_marks_request(first: u32, tuples: &[FiveTuple], value: u32, mask: u32) -> Vec<u8> {
    let mut request = Vec::with_capacity(tuples.len() * 112);
    for (i, tuple) in tuples.iter().enumerate() {
        let ack = if i + 1 == tuples.len() { NLM_F_ACK } else { 0 };
        let mut r = Request::new(MSG_NEW, NLM_F_REQUEST | ack, first.wrapping_add(i as u32), tuple.family());
        r.tuple(CTA_TUPLE_ORIG, tuple);
        r.attr(CTA_MARK, &(value & mask).to_be_bytes());
        r.attr(CTA_MARK_MASK, &mask.to_be_bytes());
        request.extend_from_slice(&r.finish());
    }
    request
}

fn get_request(seq: u32, tuple: &FiveTuple) -> Vec<u8> {
    let mut r = Request::new(MSG_GET, NLM_F_REQUEST, seq, tuple.family());
    r.tuple(CTA_TUPLE_ORIG, tuple);
    r.finish()
}

fn list_request(seq: u32, mark: u32, mask: u32) -> Vec<u8> {
    let mut r = Request::new(MSG_GET, NLM_F_REQUEST | NLM_F_DUMP, seq, AF_UNSPEC);
    r.attr(CTA_MARK, &(mark & mask).to_be_bytes());
    r.attr(CTA_MARK_MASK, &mask.to_be_bytes());
    r.finish()
}

fn stats_request(seq: u32) -> Vec<u8> {
    Request::new(MSG_GET_STATS, NLM_F_REQUEST, seq, AF_UNSPEC).finish()
}

fn cpu_stats_request(seq: u32) -> Vec<u8> {
    Request::new(MSG_GET_STATS_CPU, NLM_F_REQUEST | NLM_F_DUMP, seq, AF_UNSPEC).finish()
}

struct Request(Vec<u8>);

impl Request {
    fn new(kind: u16, flags: u16, seq: u32, family: u8) -> Self {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&kind.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&[family, 0, 0, 0]);
        Self(buf)
    }

    fn attr(&mut self, kind: u16, value: &[u8]) {
        self.0.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
        self.0.extend_from_slice(&kind.to_ne_bytes());
        self.0.extend_from_slice(value);
        self.0.resize(self.0.len().next_multiple_of(4), 0);
    }

    fn nested(&mut self, kind: u16, body: impl FnOnce(&mut Self)) {
        let start = self.0.len();
        self.0.extend_from_slice(&[0, 0]);
        self.0.extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
        body(self);
        let len = (self.0.len() - start) as u16;
        self.0[start..start + 2].copy_from_slice(&len.to_ne_bytes());
    }

    fn tuple(&mut self, kind: u16, t: &FiveTuple) {
        self.nested(kind, |r| {
            r.nested(CTA_TUPLE_IP, |r| match (t.src.ip(), t.dst.ip()) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => {
                    r.attr(CTA_IP_V4_SRC, &src.octets());
                    r.attr(CTA_IP_V4_DST, &dst.octets());
                }
                (IpAddr::V6(src), IpAddr::V6(dst)) => {
                    r.attr(CTA_IP_V6_SRC, &src.octets());
                    r.attr(CTA_IP_V6_DST, &dst.octets());
                }
                _ => unreachable!("FiveTuple::new rejects mixed families"),
            });
            r.nested(CTA_TUPLE_PROTO, |r| {
                r.attr(CTA_PROTO_NUM, &[t.protocol.number()]);
                r.attr(CTA_PROTO_SRC_PORT, &t.src.port().to_be_bytes());
                r.attr(CTA_PROTO_DST_PORT, &t.dst.port().to_be_bytes());
            });
        });
    }

    fn finish(mut self) -> Vec<u8> {
        let len = self.0.len() as u32;
        self.0[0..4].copy_from_slice(&len.to_ne_bytes());
        self.0
    }
}

#[derive(Debug, PartialEq)]
enum Reply {
    Ack,
    Done,
    Connection(Connection),
    Global { entries: u32, max: u32 },
    Cpu(CpuStats),
}

fn parse_replies(datagram: &[u8], seq: u32) -> Result<Vec<Reply>, ConntrackError> {
    let mut replies = Vec::new();
    let mut rest = datagram;
    while !rest.is_empty() {
        let msg = NetlinkBuffer::new_checked(rest).map_err(malformed)?;
        if msg.sequence_number() == seq {
            match msg.message_type() {
                NLMSG_ERROR => match parse_i32(msg.payload().get(..4).unwrap_or_default()).map_err(malformed)? {
                    0 => replies.push(Reply::Ack),
                    code => return Err(kernel_error(code)),
                },
                NLMSG_DONE => replies.push(Reply::Done),
                MSG_NEW => replies.push(Reply::Connection(parse_connection(msg.payload())?)),
                MSG_GET_STATS => replies.push(parse_global_stats(msg.payload())?),
                MSG_GET_STATS_CPU => replies.push(Reply::Cpu(parse_cpu_stats(msg.payload())?)),
                _ => {}
            }
        }
        let len = (msg.length() as usize).next_multiple_of(4);
        rest = rest.get(len..).unwrap_or_default();
    }
    Ok(replies)
}

fn parse_batch_replies(
    datagram: &[u8],
    first: u32,
    last: u32,
) -> Result<(Vec<(u32, ConntrackError)>, bool), ConntrackError> {
    let mut failed = Vec::new();
    let mut done = false;
    let mut rest = datagram;
    while !rest.is_empty() {
        let msg = NetlinkBuffer::new_checked(rest).map_err(malformed)?;
        let seq = msg.sequence_number();
        if msg.message_type() == NLMSG_ERROR && seq.wrapping_sub(first) <= last.wrapping_sub(first) {
            match parse_i32(msg.payload().get(..4).unwrap_or_default()).map_err(malformed)? {
                0 => {}
                code => failed.push((seq, kernel_error(code))),
            }
            done |= seq == last;
        }
        let len = (msg.length() as usize).next_multiple_of(4);
        rest = rest.get(len..).unwrap_or_default();
    }
    Ok((failed, done))
}

fn kernel_error(code: i32) -> ConntrackError {
    match -code {
        libc::ENOENT => ConntrackError::NotFound,
        libc::EPERM => ConntrackError::PermissionDenied,
        errno => ConntrackError::Kernel(io::Error::from_raw_os_error(errno)),
    }
}

fn parse_connection(payload: &[u8]) -> Result<Connection, ConntrackError> {
    let attrs = payload.get(4..).ok_or_else(|| ConntrackError::Malformed("message too short".to_owned()))?;
    let (mut id, mut original, mut reply, mut tcp_state, mut timeout_s, mut mark) = (None, None, None, None, None, 0);
    let (mut original_counters, mut reply_counters) = (None, None);
    for nla in NlasIterator::new(attrs) {
        let nla = nla.map_err(malformed)?;
        let value = nla.value();
        match nla.kind() & NLA_TYPE_MASK {
            CTA_TUPLE_ORIG => original = Some(parse_tuple(value)?),
            CTA_TUPLE_REPLY => reply = Some(parse_tuple(value)?),
            CTA_PROTOINFO => tcp_state = parse_tcp_state(value)?,
            CTA_TIMEOUT => timeout_s = Some(parse_u32_be(value).map_err(malformed)?),
            CTA_MARK => mark = parse_u32_be(value).map_err(malformed)?,
            CTA_ID => id = Some(parse_u32_be(value).map_err(malformed)?),
            CTA_COUNTERS_ORIG => original_counters = Some(parse_counters(value)?),
            CTA_COUNTERS_REPLY => reply_counters = Some(parse_counters(value)?),
            _ => {}
        }
    }
    let missing = |what: &str| ConntrackError::Malformed(format!("connection has no {what}"));
    Ok(Connection {
        id: id.ok_or_else(|| missing("id"))?,
        original: original.ok_or_else(|| missing("original tuple"))?,
        reply: reply.ok_or_else(|| missing("reply tuple"))?,
        tcp_state,
        timeout_s,
        mark,
        original_counters,
        reply_counters,
    })
}

fn parse_counters(buf: &[u8]) -> Result<Counters, ConntrackError> {
    let mut counters = Counters::default();
    for nla in NlasIterator::new(buf) {
        let nla = nla.map_err(malformed)?;
        match nla.kind() & NLA_TYPE_MASK {
            CTA_COUNTERS_PACKETS => counters.packets = parse_u64_be(nla.value()).map_err(malformed)?,
            CTA_COUNTERS_BYTES => counters.bytes = parse_u64_be(nla.value()).map_err(malformed)?,
            _ => {}
        }
    }
    Ok(counters)
}

fn parse_tuple(buf: &[u8]) -> Result<FiveTuple, ConntrackError> {
    let (mut src, mut dst, mut protocol, mut src_port, mut dst_port) = (None, None, None, 0, 0);
    for nla in NlasIterator::new(buf) {
        let nla = nla.map_err(malformed)?;
        match nla.kind() & NLA_TYPE_MASK {
            CTA_TUPLE_IP => {
                for ip in NlasIterator::new(nla.value()) {
                    let ip = ip.map_err(malformed)?;
                    match ip.kind() & NLA_TYPE_MASK {
                        CTA_IP_V4_SRC | CTA_IP_V6_SRC => src = Some(parse_ip(ip.value()).map_err(malformed)?),
                        CTA_IP_V4_DST | CTA_IP_V6_DST => dst = Some(parse_ip(ip.value()).map_err(malformed)?),
                        _ => {}
                    }
                }
            }
            CTA_TUPLE_PROTO => {
                for p in NlasIterator::new(nla.value()) {
                    let p = p.map_err(malformed)?;
                    match p.kind() & NLA_TYPE_MASK {
                        CTA_PROTO_NUM => protocol = Some(parse_u8(p.value()).map_err(malformed)?),
                        CTA_PROTO_SRC_PORT => src_port = parse_u16_be(p.value()).map_err(malformed)?,
                        CTA_PROTO_DST_PORT => dst_port = parse_u16_be(p.value()).map_err(malformed)?,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    let missing = |what: &str| ConntrackError::Malformed(format!("tuple has no {what}"));
    let src = src.ok_or_else(|| missing("source address"))?;
    let dst = dst.ok_or_else(|| missing("destination address"))?;
    let protocol = Protocol::from_number(protocol.ok_or_else(|| missing("protocol"))?);
    FiveTuple::new(protocol, SocketAddr::new(src, src_port), SocketAddr::new(dst, dst_port)).map_err(malformed)
}

fn parse_tcp_state(buf: &[u8]) -> Result<Option<TcpState>, ConntrackError> {
    for info in NlasIterator::new(buf) {
        let info = info.map_err(malformed)?;
        if info.kind() & NLA_TYPE_MASK != CTA_PROTOINFO_TCP {
            continue;
        }
        for tcp in NlasIterator::new(info.value()) {
            let tcp = tcp.map_err(malformed)?;
            if tcp.kind() & NLA_TYPE_MASK == CTA_PROTOINFO_TCP_STATE {
                return Ok(Some(parse_u8(tcp.value()).map_err(malformed)?.into()));
            }
        }
    }
    Ok(None)
}

fn parse_global_stats(payload: &[u8]) -> Result<Reply, ConntrackError> {
    let attrs = payload.get(4..).ok_or_else(|| ConntrackError::Malformed("message too short".to_owned()))?;
    let (mut entries, mut max) = (None, None);
    for nla in NlasIterator::new(attrs) {
        let nla = nla.map_err(malformed)?;
        match nla.kind() & NLA_TYPE_MASK {
            CTA_STATS_GLOBAL_ENTRIES => entries = Some(parse_u32_be(nla.value()).map_err(malformed)?),
            CTA_STATS_GLOBAL_MAX_ENTRIES => max = Some(parse_u32_be(nla.value()).map_err(malformed)?),
            _ => {}
        }
    }
    let missing = |what: &str| ConntrackError::Malformed(format!("statistics have no {what}"));
    Ok(Reply::Global {
        entries: entries.ok_or_else(|| missing("entry count"))?,
        max: max.ok_or_else(|| missing("maximum"))?,
    })
}

fn parse_cpu_stats(payload: &[u8]) -> Result<CpuStats, ConntrackError> {
    let (header, attrs) = payload
        .split_at_checked(4)
        .ok_or_else(|| ConntrackError::Malformed("message too short".to_owned()))?;
    let mut stats = CpuStats { cpu: u16::from_be_bytes([header[2], header[3]]), ..CpuStats::default() };
    for nla in NlasIterator::new(attrs) {
        let nla = nla.map_err(malformed)?;
        let counter = match nla.kind() & NLA_TYPE_MASK {
            CTA_STATS_DROP => &mut stats.drop,
            CTA_STATS_EARLY_DROP => &mut stats.early_drop,
            CTA_STATS_INSERT_FAILED => &mut stats.insert_failed,
            _ => continue,
        };
        *counter = parse_u32_be(nla.value()).map_err(malformed)?;
    }
    Ok(stats)
}

fn malformed(e: impl fmt::Display) -> ConntrackError {
    ConntrackError::Malformed(e.to_string())
}

#[cfg(test)]
#[path = "../../tests/unit/kernel/conntrack.rs"]
mod tests;
