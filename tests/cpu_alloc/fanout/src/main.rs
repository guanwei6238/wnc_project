use std::cell::UnsafeCell;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

const NFNL_SUBSYS_ULOG: u16 = 4;
const NFULNL_MSG_PACKET: u16 = 0;
const NFULNL_MSG_CONFIG: u16 = 1;
const NFULA_CFG_CMD: u16 = 1;
const NFULA_CFG_MODE: u16 = 2;
const NFULNL_CFG_CMD_BIND: u8 = 1;
const NFULNL_COPY_PACKET: u8 = 2;
const NFULA_PAYLOAD: u16 = 9;
const RING: usize = 8 << 20;
const STATS: &str = "/dev/shm/fanout.stats";

struct Ring {
    buf: UnsafeCell<Box<[u8]>>,
    head: AtomicU64,
    tail: AtomicU64,
    drops: AtomicU64,
    out: AtomicU64,
}

unsafe impl Sync for Ring {}

impl Ring {
    fn new() -> Self {
        Self {
            buf: UnsafeCell::new(vec![0; RING].into_boxed_slice()),
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            drops: AtomicU64::new(0),
            out: AtomicU64::new(0),
        }
    }

    fn copy_in(&self, pos: u64, data: &[u8]) {
        let buf = unsafe { &mut *self.buf.get() };
        let at = pos as usize % RING;
        let first = data.len().min(RING - at);
        buf[at..at + first].copy_from_slice(&data[..first]);
        buf[..data.len() - first].copy_from_slice(&data[first..]);
    }

    fn copy_out(&self, pos: u64, out: &mut [u8]) {
        let buf = unsafe { &*self.buf.get() };
        let at = pos as usize % RING;
        let first = out.len().min(RING - at);
        out[..first].copy_from_slice(&buf[at..at + first]);
        let rest = out.len() - first;
        out[first..].copy_from_slice(&buf[..rest]);
    }

    fn push(&self, packet: &[u8]) {
        let need = (4 + packet.len()).next_multiple_of(4) as u64;
        let head = self.head.load(Ordering::Relaxed);
        if RING as u64 - (head - self.tail.load(Ordering::Acquire)) < need {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.copy_in(head, &(packet.len() as u32).to_ne_bytes());
        self.copy_in(head + 4, packet);
        self.head.store(head + need, Ordering::Release);
    }

    fn drain(&self, scratch: &mut [u8]) -> u64 {
        let head = self.head.load(Ordering::Acquire);
        let mut tail = self.tail.load(Ordering::Relaxed);
        let mut sum = 0u64;
        while tail < head {
            let mut len = [0u8; 4];
            self.copy_out(tail, &mut len);
            let len = u32::from_ne_bytes(len) as usize;
            self.copy_out(tail + 4, &mut scratch[..len]);
            sum = sum.wrapping_add(scratch[len / 2] as u64);
            tail += (4 + len).next_multiple_of(4) as u64;
            self.out.fetch_add(1, Ordering::Relaxed);
        }
        self.tail.store(tail, Ordering::Release);
        sum
    }
}

fn nlmsg(seq: u32, group: u16, attr_type: u16, attr: &[u8]) -> Vec<u8> {
    let attr_len = 4 + attr.len();
    let len = 16 + 4 + attr_len.next_multiple_of(4);
    let mut m = Vec::with_capacity(len);
    m.extend_from_slice(&(len as u32).to_ne_bytes());
    m.extend_from_slice(&((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG).to_ne_bytes());
    m.extend_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16).to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes());
    m.extend_from_slice(&[libc::AF_UNSPEC as u8, 0]);
    m.extend_from_slice(&group.to_be_bytes());
    m.extend_from_slice(&(attr_len as u16).to_ne_bytes());
    m.extend_from_slice(&attr_type.to_ne_bytes());
    m.extend_from_slice(attr);
    m.resize(len, 0);
    m
}

fn check(r: libc::c_int, what: &str) -> io::Result<libc::c_int> {
    if r < 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("{what}: {e}")));
    }
    Ok(r)
}

fn open(group: u16, snaplen: u32) -> io::Result<libc::c_int> {
    unsafe {
        let fd = check(libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_NETFILTER), "socket")?;
        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as u16;
        check(
            libc::bind(fd, &addr as *const _ as *const libc::sockaddr, size_of::<libc::sockaddr_nl>() as u32),
            "bind",
        )?;
        let size: libc::c_int = 1 << 20;
        check(
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &size as *const _ as *const libc::c_void, 4),
            "SO_RCVBUF",
        )?;
        let mut mode = (if snaplen == 0 { 0xffff } else { snaplen }).to_be_bytes().to_vec();
        mode.extend_from_slice(&[NFULNL_COPY_PACKET, 0]);
        for (seq, (t, a)) in [(NFULA_CFG_CMD, vec![NFULNL_CFG_CMD_BIND]), (NFULA_CFG_MODE, mode)].into_iter().enumerate() {
            let m = nlmsg(seq as u32 + 1, group, t, &a);
            check(libc::send(fd, m.as_ptr() as *const libc::c_void, m.len(), 0) as libc::c_int, "send config")?;
            let mut ack = [0u8; 256];
            let n = check(libc::recv(fd, ack.as_mut_ptr() as *mut libc::c_void, ack.len(), 0) as libc::c_int, "recv ack")?;
            if n >= 20 && u16::from_ne_bytes([ack[4], ack[5]]) == libc::NLMSG_ERROR as u16 {
                let err = i32::from_ne_bytes([ack[16], ack[17], ack[18], ack[19]]);
                if err != 0 {
                    return Err(io::Error::from_raw_os_error(-err));
                }
            }
        }
        Ok(fd)
    }
}

fn payloads(buf: &[u8], mut each: impl FnMut(&[u8])) {
    let mut off = 0;
    while off + 16 <= buf.len() {
        let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
        if len < 16 || off + len > buf.len() {
            break;
        }
        if kind == (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET {
            let mut a = off + 20;
            while a + 4 <= off + len {
                let alen = u16::from_ne_bytes([buf[a], buf[a + 1]]) as usize;
                let atype = u16::from_ne_bytes([buf[a + 2], buf[a + 3]]) & 0x3fff;
                if alen < 4 || a + alen > off + len {
                    break;
                }
                if atype == NFULA_PAYLOAD {
                    each(&buf[a + 4..a + alen]);
                }
                a += alen.next_multiple_of(4);
            }
        }
        off += len.next_multiple_of(4);
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: fanout <group> <readers> [snaplen]");
        std::process::exit(2);
    }
    let group: u16 = args[1].parse().expect("group");
    let readers: usize = args[2].parse().expect("readers");
    let snaplen: u32 = args.get(3).map_or(0, |s| s.parse().expect("snaplen"));
    let fd = open(group, snaplen)?;
    let rings: Vec<Arc<Ring>> = (0..readers).map(|_| Arc::new(Ring::new())).collect();
    for (i, ring) in rings.iter().enumerate() {
        let ring = Arc::clone(ring);
        thread::Builder::new().name(format!("fanout-rd{i}")).spawn(move || {
            let mut scratch = vec![0u8; 1 << 16];
            let mut sum = 0u64;
            loop {
                sum = sum.wrapping_add(ring.drain(&mut scratch));
                std::hint::black_box(sum);
                thread::sleep(Duration::from_millis(1));
            }
        })?;
    }
    let received = Arc::new(AtomicU64::new(0));
    let enobufs = Arc::new(AtomicU64::new(0));
    {
        let (rings, received, enobufs) = (rings.clone(), Arc::clone(&received), Arc::clone(&enobufs));
        thread::Builder::new().name("fanout-stats".into()).spawn(move || loop {
            let drop: u64 = rings.iter().map(|r| r.drops.load(Ordering::Relaxed)).sum();
            let out: u64 = rings.iter().map(|r| r.out.load(Ordering::Relaxed)).sum();
            let line = format!(
                "fo_in={} fo_drop={drop} fo_out={out} fo_readers={readers} fo_enobufs={}\n",
                received.load(Ordering::Relaxed),
                enobufs.load(Ordering::Relaxed)
            );
            let _ = std::fs::write(STATS, line);
            thread::sleep(Duration::from_millis(200));
        })?;
    }
    let mut buf = vec![0u8; 1 << 18];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::ENOBUFS) => {
                    enobufs.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                Some(libc::EINTR) => continue,
                _ => return Err(e),
            }
        }
        payloads(&buf[..n as usize], |p| {
            received.fetch_add(1, Ordering::Relaxed);
            for ring in &rings {
                ring.push(p);
            }
        });
    }
}
