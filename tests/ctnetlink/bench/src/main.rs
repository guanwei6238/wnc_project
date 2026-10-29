// ctnetlink 的成本（3c 選實作方式，2026-10-28）
//   A   = netlink-packet-netfilter 編碼 + netlink-proto
//   A'  = netlink-packet-netfilter 編碼 + netlink-sys Socket（同步 / TokioSocket）
//   B   = 手寫位元組 + netlink-sys Socket
//   W   = wnc-gw 的 kernel::conntrack（B 的做法）；最後量 list 和 firewall::untrust_all（3c-2 啟動時清舊信任）
// 自己用 ctnetlink 建 entries 筆 TCP entry（前 1000 筆輪流設／清 bit 0x80000000），結束時刪掉；要 root。
// 用法：ctnetlink-bench [ops] [rounds] [entries]，預設 20000 3 60000
// Docker：cargo build --release --target x86_64-unknown-linux-musl，docker cp 進 wnc-gw 容器執行（容器有自己的 conntrack 表）
// Pi：CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld cargo build --release --target aarch64-unknown-linux-musl；
//     pi_lab_mode.sh up 1000、停 suricata，在獨立 netns 裡執行：sudo ip netns exec ctb taskset -c 2 ./ctnetlink-bench
use std::io;
use std::net::{Ipv4Addr, SocketAddr as InetAddr};
use std::time::Instant;

use futures::StreamExt;
use netlink_packet_core::{
    DefaultNla, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, Nla, NetlinkHeader, NetlinkMessage,
    NetlinkPayload,
};
use netlink_packet_netfilter::conntrack::{
    ConntrackAttribute as A, ConntrackMessage, IPTuple, ProtoInfo, ProtoInfoTCP, ProtoTuple, Protocol, Tuple,
};
use netlink_packet_netfilter::{NetfilterHeader, NetfilterMessage, NetfilterMessageInner, NetfilterProtoFamily};
use netlink_sys::{AsyncSocket, AsyncSocketExt, Socket, SocketAddr, TokioSocket, protocols::NETLINK_NETFILTER};
use security_gateway::kernel::conntrack as wc;

const N: usize = 1000;
const BATCH: usize = 100;
const MARK_INIT: u32 = 0x1234;
const TRUST: u32 = 0x8000_0000;
const CTA_ID: u16 = 12;
const CTA_MARK_MASK: u16 = 21;
const TCP_ESTABLISHED: u8 = 3;

type Msg = NetlinkMessage<NetfilterMessage>;

#[derive(Clone, Copy, Debug)]
struct Flow {
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
}

impl Flow {
    fn reversed(self) -> Flow {
        Flow { src: self.dst, sport: self.dport, dst: self.src, dport: self.sport }
    }
}

fn flow(i: usize) -> Flow {
    Flow {
        src: Ipv4Addr::new(10, 99, (i / 250) as u8, (i % 250 + 1) as u8),
        sport: 40000,
        dst: Ipv4Addr::new(10, 98, 0, 1),
        dport: 443,
    }
}

// 第 k 次操作：輪流走過 N 筆，偶數輪設 bit、奇數輪清 bit，每次都真的改到值
fn target(k: usize) -> (Flow, bool) {
    (flow(k % N), (k / N) % 2 == 0)
}

#[derive(Clone, Copy, PartialEq)]
enum Dir {
    Orig,
    Reply,
}

// ---------- crate 編碼 ----------

fn tuple(f: Flow) -> Vec<Tuple> {
    vec![
        Tuple::Ip(vec![IPTuple::SourceAddress(f.src.into()), IPTuple::DestinationAddress(f.dst.into())]),
        Tuple::Proto(vec![
            ProtoTuple::Protocol(Protocol::Tcp),
            ProtoTuple::SourcePort(f.sport),
            ProtoTuple::DestinationPort(f.dport),
        ]),
    ]
}

fn nl(msg: ConntrackMessage, flags: u16, seq: u32) -> Msg {
    let mut header = NetlinkHeader::default();
    header.flags = flags;
    header.sequence_number = seq;
    let nf = NetfilterMessage::new(NetfilterHeader::new(NetfilterProtoFamily::IPv4, 0, 0), msg);
    let mut m = NetlinkMessage::new(header, NetlinkPayload::from(nf));
    m.finalize();
    m
}

fn create_msg(f: Flow, seq: u32) -> Msg {
    nl(
        ConntrackMessage::New(vec![
            A::CtaTupleOrig(tuple(f)),
            A::CtaTupleReply(tuple(f.reversed())),
            A::CtaProtoInfo(vec![ProtoInfo::TCP(vec![ProtoInfoTCP::State(TCP_ESTABLISHED)])]),
            A::CtaTimeout(600),
            A::CtaMark(MARK_INIT),
        ]),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        seq,
    )
}

fn mark_msg(t: Flow, dir: Dir, set: bool, ack: bool, seq: u32) -> Msg {
    let tuple = match dir {
        Dir::Orig => A::CtaTupleOrig(tuple(t)),
        Dir::Reply => A::CtaTupleReply(tuple(t)),
    };
    nl(
        ConntrackMessage::New(vec![
            tuple,
            A::CtaMark(if set { TRUST } else { 0 }),
            A::Other(DefaultNla::new(CTA_MARK_MASK, TRUST.to_be_bytes().to_vec())),
        ]),
        NLM_F_REQUEST | if ack { NLM_F_ACK } else { 0 },
        seq,
    )
}

fn get_msg(f: Flow) -> Msg {
    nl(ConntrackMessage::Get(vec![A::CtaTupleOrig(tuple(f))]), NLM_F_REQUEST, 0)
}

fn delete_msg(f: Flow, seq: u32) -> Msg {
    nl(ConntrackMessage::Delete(vec![A::CtaTupleOrig(tuple(f))]), NLM_F_REQUEST | NLM_F_ACK, seq)
}

fn put(buf: &mut Vec<u8>, m: &Msg) {
    let start = buf.len();
    buf.resize(start + m.buffer_len(), 0);
    m.serialize(&mut buf[start..]);
}

// ---------- 手寫編碼（B） ----------

fn raw_nla(buf: &mut Vec<u8>, kind: u16, value: &[u8]) {
    buf.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(value);
    buf.resize(buf.len().next_multiple_of(4), 0);
}

fn raw_nest(buf: &mut Vec<u8>, kind: u16, body: impl FnOnce(&mut Vec<u8>)) {
    let at = buf.len();
    buf.extend_from_slice(&[0, 0]);
    buf.extend_from_slice(&(kind | 0x8000).to_ne_bytes());
    body(buf);
    let len = (buf.len() - at) as u16;
    buf[at..at + 2].copy_from_slice(&len.to_ne_bytes());
}

fn raw_mark(buf: &mut Vec<u8>, t: Flow, set: bool, ack: bool, seq: u32) {
    let start = buf.len();
    buf.extend_from_slice(&[0; 16]);
    buf.extend_from_slice(&[libc_af_inet(), 0, 0, 0]);
    raw_nest(buf, 1, |b| {
        raw_nest(b, 1, |b| {
            raw_nla(b, 1, &t.src.octets());
            raw_nla(b, 2, &t.dst.octets());
        });
        raw_nest(b, 2, |b| {
            raw_nla(b, 1, &[6]);
            raw_nla(b, 2, &t.sport.to_be_bytes());
            raw_nla(b, 3, &t.dport.to_be_bytes());
        });
    });
    raw_nla(buf, 8, &(if set { TRUST } else { 0 }).to_be_bytes());
    raw_nla(buf, CTA_MARK_MASK, &TRUST.to_be_bytes());
    let len = (buf.len() - start) as u32;
    let flags = NLM_F_REQUEST | if ack { NLM_F_ACK } else { 0 };
    let h = &mut buf[start..start + 16];
    h[0..4].copy_from_slice(&len.to_ne_bytes());
    h[4..6].copy_from_slice(&(1u16 << 8).to_ne_bytes());
    h[6..8].copy_from_slice(&flags.to_ne_bytes());
    h[8..12].copy_from_slice(&seq.to_ne_bytes());
}

fn libc_af_inet() -> u8 {
    2
}

fn raw_get_msg(buf: &mut Vec<u8>, t: Flow) {
    let start = buf.len();
    buf.extend_from_slice(&[0; 16]);
    buf.extend_from_slice(&[libc_af_inet(), 0, 0, 0]);
    raw_nest(buf, 1, |b| {
        raw_nest(b, 1, |b| {
            raw_nla(b, 1, &t.src.octets());
            raw_nla(b, 2, &t.dst.octets());
        });
        raw_nest(b, 2, |b| {
            raw_nla(b, 1, &[6]);
            raw_nla(b, 2, &t.sport.to_be_bytes());
            raw_nla(b, 3, &t.dport.to_be_bytes());
        });
    });
    let len = (buf.len() - start) as u32;
    let h = &mut buf[start..start + 16];
    h[0..4].copy_from_slice(&len.to_ne_bytes());
    h[4..6].copy_from_slice(&((1u16 << 8) | 1).to_ne_bytes());
    h[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
}

fn raw_attrs(mut b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        if b.len() < 4 {
            return None;
        }
        let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
        let kind = u16::from_ne_bytes([b[2], b[3]]) & 0x3fff;
        if len < 4 || len > b.len() {
            return None;
        }
        let v = &b[4..len];
        b = &b[len.next_multiple_of(4).min(b.len())..];
        Some((kind, v))
    })
}

fn raw_entry(m: &[u8]) -> Entry {
    let mut e = Entry { id: None, mark: None, tcp_state: None };
    for (kind, v) in raw_attrs(&m[20..]) {
        match kind {
            12 if v.len() == 4 => e.id = Some(u32::from_be_bytes(v.try_into().unwrap())),
            8 if v.len() == 4 => e.mark = Some(u32::from_be_bytes(v.try_into().unwrap())),
            4 => {
                for (k, tcp) in raw_attrs(v) {
                    if k == 1 {
                        for (k, s) in raw_attrs(tcp) {
                            if k == 1 && !s.is_empty() {
                                e.tcp_state = Some(s[0]);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    e
}

// ---------- 收訊息 ----------

fn split(d: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = d;
    std::iter::from_fn(move || {
        if rest.len() < 16 {
            return None;
        }
        let len = u32::from_ne_bytes(rest[0..4].try_into().unwrap()) as usize;
        let (m, r) = rest.split_at(len.min(rest.len()));
        rest = &r[len.next_multiple_of(4).saturating_sub(len).min(r.len())..];
        Some(m)
    })
}

fn errno(code: i32) -> io::Error {
    io::Error::from_raw_os_error(-code)
}

enum Seen {
    Ack(u32),
    Nack(u32, i32),
    Other(Box<Msg>),
}

fn decode(m: &[u8]) -> io::Result<Seen> {
    let msg = Msg::deserialize(m).map_err(|e| io::Error::other(e.to_string()))?;
    let seq = msg.header.sequence_number;
    Ok(match msg.payload {
        NetlinkPayload::Error(e) => match e.code {
            None => Seen::Ack(seq),
            Some(c) => Seen::Nack(seq, c.get()),
        },
        _ => Seen::Other(Box::new(msg)),
    })
}

fn raw_decode(m: &[u8]) -> Seen {
    let seq = u32::from_ne_bytes(m[8..12].try_into().unwrap());
    let ty = u16::from_ne_bytes(m[4..6].try_into().unwrap());
    if ty != 2 {
        return Seen::Nack(seq, -9999);
    }
    match i32::from_ne_bytes(m[16..20].try_into().unwrap()) {
        0 => Seen::Ack(seq),
        c => Seen::Nack(seq, c),
    }
}

struct Sync {
    sock: Socket,
    rx: Vec<u8>,
}

impl Sync {
    fn new() -> io::Result<Self> {
        let mut sock = Socket::new(NETLINK_NETFILTER)?;
        sock.bind_auto()?;
        sock.connect(&SocketAddr::new(0, 0))?;
        Ok(Self { sock, rx: Vec::with_capacity(1 << 16) })
    }

    fn send(&self, buf: &[u8]) -> io::Result<()> {
        let n = self.sock.send(buf, 0)?;
        assert_eq!(n, buf.len());
        Ok(())
    }

    fn recv(&mut self) -> io::Result<&[u8]> {
        self.rx.clear();
        let n = self.sock.recv(&mut self.rx, 0)?;
        Ok(&self.rx[..n])
    }

    // 收到 n 個 ACK 為止；有 NACK 就回錯
    fn acks(&mut self, mut n: usize, raw: bool) -> io::Result<()> {
        while n > 0 {
            let d = self.recv()?.to_vec();
            for m in split(&d) {
                match if raw { raw_decode(m) } else { decode(m)? } {
                    Seen::Ack(_) => n -= 1,
                    Seen::Nack(seq, c) => return Err(io::Error::other(format!("seq {seq}: {}", errno(c)))),
                    Seen::Other(_) => {}
                }
            }
        }
        Ok(())
    }

    // 不帶 ACK 的訊息只有失敗才回；等到最後那筆（barrier）的 ACK
    fn barrier(&mut self, seq: u32, raw: bool) -> io::Result<()> {
        loop {
            let d = self.recv()?.to_vec();
            for m in split(&d) {
                match if raw { raw_decode(m) } else { decode(m)? } {
                    Seen::Ack(s) if s == seq => return Ok(()),
                    Seen::Ack(_) | Seen::Other(_) => {}
                    Seen::Nack(s, c) => return Err(io::Error::other(format!("seq {s}: {}", errno(c)))),
                }
            }
        }
    }

    fn request_one(&mut self, m: &Msg) -> io::Result<()> {
        let mut buf = Vec::with_capacity(128);
        put(&mut buf, m);
        self.send(&buf)?;
        self.acks(1, false)
    }

    fn get(&mut self, f: Flow) -> io::Result<Entry> {
        let mut buf = Vec::with_capacity(128);
        put(&mut buf, &get_msg(f));
        self.send(&buf)?;
        let d = self.recv()?.to_vec();
        for m in split(&d) {
            match decode(m)? {
                Seen::Other(msg) => return Ok(entry(&msg)),
                Seen::Nack(_, c) => return Err(errno(c)),
                Seen::Ack(_) => {}
            }
        }
        Err(io::Error::other("no reply"))
    }

    fn raw_get(&mut self, f: Flow) -> io::Result<Entry> {
        let mut buf = Vec::with_capacity(128);
        raw_get_msg(&mut buf, f);
        self.send(&buf)?;
        let d = self.recv()?;
        let m = split(d).next().ok_or_else(|| io::Error::other("no reply"))?;
        match raw_decode_type(m) {
            2 => Err(errno(i32::from_ne_bytes(m[16..20].try_into().unwrap()))),
            _ => Ok(raw_entry(m)),
        }
    }
}

fn raw_decode_type(m: &[u8]) -> u16 {
    u16::from_ne_bytes(m[4..6].try_into().unwrap())
}

#[derive(Debug, PartialEq)]
struct Entry {
    id: Option<u32>,
    mark: Option<u32>,
    tcp_state: Option<u8>,
}

fn entry(msg: &Msg) -> Entry {
    let mut e = Entry { id: None, mark: None, tcp_state: None };
    let NetlinkPayload::InnerMessage(nf) = &msg.payload else { return e };
    let NetfilterMessageInner::Conntrack(ConntrackMessage::New(attrs)) = &nf.inner else { return e };
    for a in attrs {
        match a {
            A::CtaMark(m) => e.mark = Some(*m),
            A::Other(nla) if nla.kind() == CTA_ID && nla.value_len() == 4 => {
                let mut v = [0u8; 4];
                nla.emit_value(&mut v);
                e.id = Some(u32::from_be_bytes(v));
            }
            A::CtaProtoInfo(infos) => {
                for i in infos {
                    if let ProtoInfo::TCP(tcp) = i {
                        for t in tcp {
                            if let ProtoInfoTCP::State(s) = t {
                                e.tcp_state = Some(*s);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    e
}

// ---------- 統計 ----------

struct Stat {
    name: &'static str,
    ops: usize,
    total_ns: u128,
    per_call: Vec<u64>,
    per_call_ops: usize,
}

impl Stat {
    fn print(mut self, round: &str) {
        self.per_call.sort_unstable();
        let q = |p: f64| {
            let i = ((self.per_call.len() as f64 - 1.0) * p).round() as usize;
            self.per_call[i] as f64 / self.per_call_ops as f64 / 1000.0
        };
        println!(
            "{round:>5} {:<16} ops={:<6} mean={:>7.2} p50={:>7.2} p99={:>7.2} us/op",
            self.name,
            self.ops,
            self.total_ns as f64 / self.ops as f64 / 1000.0,
            q(0.5),
            q(0.99),
        );
    }
}

fn timed(name: &'static str, ops: usize, per_call_ops: usize, mut call: impl FnMut(usize) -> io::Result<()>) -> io::Result<Stat> {
    let calls = ops / per_call_ops;
    let mut per_call = Vec::with_capacity(calls);
    let start = Instant::now();
    for c in 0..calls {
        let t = Instant::now();
        call(c * per_call_ops)?;
        per_call.push(t.elapsed().as_nanos() as u64);
    }
    Ok(Stat { name, ops, total_ns: start.elapsed().as_nanos(), per_call, per_call_ops })
}

async fn timed_async<F, Fut>(name: &'static str, ops: usize, per_call_ops: usize, mut call: F) -> io::Result<Stat>
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = io::Result<()>>,
{
    let calls = ops / per_call_ops;
    let mut per_call = Vec::with_capacity(calls);
    let start = Instant::now();
    for c in 0..calls {
        let t = Instant::now();
        call(c * per_call_ops).await?;
        per_call.push(t.elapsed().as_nanos() as u64);
    }
    Ok(Stat { name, ops, total_ns: start.elapsed().as_nanos(), per_call, per_call_ops })
}

// ---------- 各做法 ----------

async fn proto_one(handle: &netlink_proto::ConnectionHandle<NetfilterMessage>, msgs: Vec<Msg>) -> io::Result<()> {
    let n = msgs.len();
    let mut resp = if n == 1 {
        handle.request(msgs.into_iter().next().unwrap(), SocketAddr::new(0, 0)).map_err(|e| io::Error::other(e.to_string()))?.boxed()
    } else {
        handle.request_batch(msgs, SocketAddr::new(0, 0)).map_err(|e| io::Error::other(e.to_string()))?.boxed()
    };
    // ACK 預設不轉給 handle；stream 結束且沒有錯誤 = 每筆都 ACK 了
    while let Some(m) = resp.next().await {
        if let NetlinkPayload::Error(e) = m.payload
            && let Some(c) = e.code
        {
            return Err(errno(c.get()));
        }
    }
    Ok(())
}

async fn tokio_one(sock: &TokioSocket, m: &Msg, rx: &mut Vec<u8>) -> io::Result<()> {
    let mut buf = Vec::with_capacity(128);
    put(&mut buf, m);
    sock.send(&buf).await?;
    rx.clear();
    sock.recv(rx).await?;
    for msg in split(rx) {
        match decode(msg)? {
            Seen::Ack(_) => return Ok(()),
            Seen::Nack(_, c) => return Err(errno(c)),
            Seen::Other(_) => {}
        }
    }
    Err(io::Error::other("no ack"))
}

fn check(what: &str, ok: bool) {
    println!("check {:<44} {}", what, if ok { "ok" } else { "FAIL" });
    if !ok {
        std::process::exit(1);
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let args: Vec<usize> = std::env::args().skip(1).map(|a| a.parse().expect("number")).collect();
    let ops = args.first().copied().unwrap_or(20_000);
    let rounds = args.get(1).copied().unwrap_or(3);
    let entries = args.get(2).copied().unwrap_or(60_000);
    assert!(ops % (2 * N) == 0 && ops % BATCH == 0 && (N..=62_500).contains(&entries));

    let mut s = Sync::new()?;

    let leftover = delete_all(&mut s, entries)?;
    println!("deleted {leftover} leftover entries, creating {entries}");
    for chunk in (0..entries).collect::<Vec<_>>().chunks(BATCH) {
        let mut buf = Vec::new();
        for &i in chunk {
            put(&mut buf, &create_msg(flow(i), i as u32));
        }
        s.send(&buf)?;
        s.acks(chunk.len(), false)?;
    }

    // ---------- 正確性 ----------
    let f = flow(0);
    let e0 = s.get(f)?;
    println!("entry0 {e0:?}");
    check("created: mark 0x1234, ESTABLISHED, has id", e0.mark == Some(MARK_INIT) && e0.tcp_state == Some(TCP_ESTABLISHED) && e0.id.is_some());
    s.request_one(&mark_msg(f, Dir::Orig, true, true, 1))?;
    let e = s.get(f)?;
    check("set via orig keeps other bits", e.mark == Some(MARK_INIT | TRUST));
    check("id unchanged after update", e.id == e0.id);
    s.request_one(&mark_msg(f, Dir::Orig, true, true, 1))?;
    check("set twice is idempotent", s.get(f)?.mark == Some(MARK_INIT | TRUST));
    s.request_one(&mark_msg(f, Dir::Orig, false, true, 1))?;
    check("clear via orig keeps other bits", s.get(f)?.mark == Some(MARK_INIT));
    s.request_one(&mark_msg(f.reversed(), Dir::Orig, true, true, 1))?;
    check("reversed tuple as orig finds the same entry", s.get(f)?.mark == Some(MARK_INIT | TRUST));
    check("get with reversed tuple finds it too", s.get(f.reversed())?.id == e0.id);
    s.request_one(&mark_msg(f.reversed(), Dir::Orig, false, true, 1))?;
    s.request_one(&mark_msg(f.reversed(), Dir::Reply, true, true, 1))?;
    check("reversed tuple as reply sets the same entry", s.get(f)?.mark == Some(MARK_INIT | TRUST));
    s.request_one(&mark_msg(f.reversed(), Dir::Reply, false, true, 1))?;
    check("clear via reply", s.get(f)?.mark == Some(MARK_INIT));
    let r = s.request_one(&mark_msg(flow(entries + 5), Dir::Orig, true, true, 1));
    check("unknown tuple -> ENOENT", r.is_err());
    let mut buf = Vec::new();
    raw_mark(&mut buf, f, true, true, 7);
    s.send(&buf)?;
    s.acks(1, true)?;
    check("hand-encoded set", s.get(f)?.mark == Some(MARK_INIT | TRUST));
    buf.clear();
    raw_mark(&mut buf, f, false, true, 7);
    s.send(&buf)?;
    s.acks(1, true)?;
    check("hand-encoded clear", s.get(f)?.mark == Some(MARK_INIT));
    buf.clear();
    put(&mut buf, &mark_msg(flow(entries + 5), Dir::Orig, true, false, 1));
    put(&mut buf, &mark_msg(f, Dir::Orig, true, true, 2));
    s.send(&buf)?;
    let r = s.barrier(2, false);
    check("no-ack batch still reports failures", r.is_err_and(|e| e.to_string().starts_with("seq 1:")));
    s.barrier(2, false)?;
    s.request_one(&mark_msg(f, Dir::Orig, false, true, 1))?;
    {
        let mut crate_buf = Vec::new();
        put(&mut crate_buf, &mark_msg(f, Dir::Orig, true, true, 7));
        let mut raw_buf = Vec::new();
        raw_mark(&mut raw_buf, f, true, true, 7);
        check("crate and hand encodings are identical", crate_buf == raw_buf);
        let mut crate_get = Vec::new();
        put(&mut crate_get, &get_msg(f));
        let mut raw_get = Vec::new();
        raw_get_msg(&mut raw_get, f);
        check("crate and hand get encodings are identical", crate_get == raw_get);
    }
    check("hand-decoded get matches crate", s.raw_get(f)? == s.get(f)?);
    check("hand get unknown tuple -> error", s.raw_get(flow(entries + 5)).is_err());

    // ---------- 量測 ----------
    let (conn, handle, _) = netlink_proto::new_connection::<NetfilterMessage>(NETLINK_NETFILTER)?;
    tokio::spawn(conn);
    let mut ts = TokioSocket::new(NETLINK_NETFILTER)?;
    ts.socket_mut().bind_auto()?;
    ts.socket_mut().connect(&SocketAddr::new(0, 0))?;
    let mut trx = Vec::with_capacity(1 << 16);

    proto_one(&handle, vec![mark_msg(f, Dir::Orig, true, true, 0)]).await?;
    check("proto set", s.get(f)?.mark == Some(MARK_INIT | TRUST));
    check("proto unknown tuple -> error", proto_one(&handle, vec![mark_msg(flow(entries + 5), Dir::Orig, true, true, 0)]).await.is_err());
    proto_one(&handle, (0..3).map(|_| mark_msg(f, Dir::Orig, false, true, 0)).collect()).await?;
    check("proto batch clear", s.get(f)?.mark == Some(MARK_INIT));
    tokio_one(&ts, &mark_msg(f, Dir::Orig, true, true, 0), &mut trx).await?;
    check("tokio set", s.get(f)?.mark == Some(MARK_INIT | TRUST));
    tokio_one(&ts, &mark_msg(f, Dir::Orig, false, true, 0), &mut trx).await?;
    check("tokio clear", s.get(f)?.mark == Some(MARK_INIT));
    let mut w = wc::Conntrack::connect().map_err(io::Error::other)?;
    let wg = w.get(&wt(f)).map_err(io::Error::other)?;
    check("W get matches crate get", Some(wg.id) == e0.id && wg.mark == MARK_INIT && wg.tcp_state == Some(wc::TcpState::Established));
    check("W get reversed tuple", w.get(&wt(f.reversed())).map_err(io::Error::other)?.original == wt(f));
    w.set_mark(&wt(f), TRUST, TRUST).map_err(io::Error::other)?;
    check("W set keeps other bits", s.get(f)?.mark == Some(MARK_INIT | TRUST));
    w.set_mark(&wt(f.reversed()), 0, TRUST).map_err(io::Error::other)?;
    check("W clear via reversed tuple", s.get(f)?.mark == Some(MARK_INIT));
    check("W unknown tuple -> NotFound", matches!(w.set_mark(&wt(flow(entries + 5)), TRUST, TRUST), Err(wc::ConntrackError::NotFound)));
    check("W get unknown tuple -> NotFound", matches!(w.get(&wt(flow(entries + 5))), Err(wc::ConntrackError::NotFound)));
    let st = w.stats().map_err(io::Error::other)?;
    println!("W stats entries={} max={} cpus={}", st.entries, st.max, st.cpus.len());
    check("W stats counts the created entries", st.entries as usize >= entries && st.max > 0 && !st.cpus.is_empty());

    for round in 0..=rounds {
        let tag = if round == 0 { "warm".to_owned() } else { format!("r{round}") };
        let ops = if round == 0 { 2 * N } else { ops };
        let mut out = Vec::new();

        out.push(
            timed_async("A proto x1", ops, 1, |k| {
                let (t, set) = target(k);
                proto_one(&handle, vec![mark_msg(t, Dir::Orig, set, true, 0)])
            })
            .await?,
        );
        out.push(
            timed_async("A proto x100", ops, BATCH, |k| {
                let msgs = (k..k + BATCH)
                    .map(|j| {
                        let (t, set) = target(j);
                        mark_msg(t, Dir::Orig, set, true, 0)
                    })
                    .collect();
                proto_one(&handle, msgs)
            })
            .await?,
        );
        out.push(timed("A' sync x1", ops, 1, |k| {
            let (t, set) = target(k);
            s.request_one(&mark_msg(t, Dir::Orig, set, true, 0))
        })?);
        out.push(timed("A' sync x100 ack", ops, BATCH, |k| {
            let mut buf = Vec::with_capacity(BATCH * 96);
            for j in k..k + BATCH {
                let (t, set) = target(j);
                put(&mut buf, &mark_msg(t, Dir::Orig, set, true, j as u32));
            }
            s.send(&buf)?;
            s.acks(BATCH, false)
        })?);
        out.push(timed("A' sync x100", ops, BATCH, |k| {
            let mut buf = Vec::with_capacity(BATCH * 96);
            for j in k..k + BATCH {
                let (t, set) = target(j);
                put(&mut buf, &mark_msg(t, Dir::Orig, set, j == k + BATCH - 1, j as u32));
            }
            s.send(&buf)?;
            s.barrier((k + BATCH - 1) as u32, false)
        })?);
        {
            let mut per_call = Vec::with_capacity(ops);
            let start = Instant::now();
            for k in 0..ops {
                let t0 = Instant::now();
                let (t, set) = target(k);
                tokio_one(&ts, &mark_msg(t, Dir::Orig, set, true, 0), &mut trx).await?;
                per_call.push(t0.elapsed().as_nanos() as u64);
            }
            out.push(Stat { name: "A' tokio x1", ops, total_ns: start.elapsed().as_nanos(), per_call, per_call_ops: 1 });
        }
        out.push(timed("B sync x1", ops, 1, |k| {
            let (t, set) = target(k);
            let mut buf = Vec::with_capacity(128);
            raw_mark(&mut buf, t, set, true, 0);
            s.send(&buf)?;
            s.acks(1, true)
        })?);
        out.push(timed("B sync x100", ops, BATCH, |k| {
            let mut buf = Vec::with_capacity(BATCH * 96);
            for j in k..k + BATCH {
                let (t, set) = target(j);
                raw_mark(&mut buf, t, set, j == k + BATCH - 1, j as u32);
            }
            s.send(&buf)?;
            s.barrier((k + BATCH - 1) as u32, true)
        })?);
        out.push(timed("A' get x1", ops, 1, |k| {
            let (t, _) = target(k);
            s.get(t).map(drop)
        })?);
        out.push(timed("B get x1", ops, 1, |k| {
            let (t, _) = target(k);
            s.raw_get(t).map(drop)
        })?);
        out.push(timed("W x1", ops, 1, |k| {
            let (t, set) = target(k);
            w.set_mark(&wt(t), if set { TRUST } else { 0 }, TRUST).map_err(io::Error::other)
        })?);
        out.push(timed("W get x1", ops, 1, |k| {
            let (t, _) = target(k);
            w.get(&wt(t)).map(drop).map_err(io::Error::other)
        })?);
        out.push(timed("W stats", ops / 20, 1, |_| w.stats().map(drop).map_err(io::Error::other))?);
        out.push(timed("W connect+stats", ops / 20, 1, |_| {
            wc::Conntrack::connect().and_then(|mut c| c.stats()).map(drop).map_err(io::Error::other)
        })?);

        for st in out {
            st.print(&tag);
        }
        check("all marks cleared after round", s.get(flow(N - 1))?.mark == Some(MARK_INIT));
    }

    // ---------- list：表裡有 entries 筆，其中 k 筆有信任 bit ----------
    for k in [0, 100, 10_000, entries] {
        set_bits(&mut s, 0..k, true)?;
        let mut total = std::time::Duration::ZERO;
        let runs = 5;
        for _ in 0..runs {
            let t = Instant::now();
            let got = w.list(TRUST, TRUST).map_err(io::Error::other)?;
            total += t.elapsed();
            check(&format!("W list returns the {k} trusted entries"), got.len() == k);
        }
        let ms = total.as_secs_f64() * 1000.0 / runs as f64;
        println!(
            "  list entries={entries:<6} trusted={k:<6} mean={ms:>8.2} ms  per_entry={:>6.3} us  per_trusted={}",
            ms * 1000.0 / entries as f64,
            if k == 0 { "-".to_owned() } else { format!("{:.2} us", ms * 1000.0 / k as f64) },
        );
        let t = Instant::now();
        let u = security_gateway::firewall::untrust_all(&mut w).map_err(io::Error::other)?;
        let clear_ms = t.elapsed().as_secs_f64() * 1000.0;
        let left = w.list(TRUST, TRUST).map_err(io::Error::other)?.len();
        check(
            &format!("untrust_all clears the {k} trusted entries"),
            u.cleared == k && u.gone == 0 && u.failed.is_empty() && left == 0,
        );
        println!("  untrust_all entries={entries:<6} trusted={k:<6} {clear_ms:>8.2} ms (list + clear)");
    }

    println!("deleted {} entries", delete_all(&mut s, entries)?);
    Ok(())
}

fn set_bits(s: &mut Sync, range: std::ops::Range<usize>, set: bool) -> io::Result<()> {
    for chunk in range.collect::<Vec<_>>().chunks(BATCH) {
        let last = *chunk.last().unwrap();
        let mut buf = Vec::with_capacity(BATCH * 96);
        for &j in chunk {
            raw_mark(&mut buf, flow(j), set, j == last, j as u32);
        }
        s.send(&buf)?;
        s.barrier(last as u32, true)?;
    }
    Ok(())
}

// 不存在的（ENOENT）不算錯
fn delete_all(s: &mut Sync, entries: usize) -> io::Result<usize> {
    let mut deleted = 0;
    for chunk in (0..entries).collect::<Vec<_>>().chunks(BATCH) {
        let mut buf = Vec::new();
        for &i in chunk {
            put(&mut buf, &delete_msg(flow(i), i as u32));
        }
        s.send(&buf)?;
        let mut pending = chunk.len();
        while pending > 0 {
            let d = s.recv()?.to_vec();
            for m in split(&d) {
                match decode(m)? {
                    Seen::Ack(_) => {
                        deleted += 1;
                        pending -= 1;
                    }
                    Seen::Nack(..) => pending -= 1,
                    Seen::Other(_) => {}
                }
            }
        }
    }
    Ok(deleted)
}

fn wt(f: Flow) -> wc::FiveTuple {
    wc::FiveTuple::new(wc::Protocol::Tcp, InetAddr::new(f.src.into(), f.sport), InetAddr::new(f.dst.into(), f.dport)).unwrap()
}
