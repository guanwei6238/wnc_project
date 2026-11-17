use std::io::{self, BufRead, Lines};
use std::net::{IpAddr, SocketAddr};

use serde::Deserialize;

use crate::packet::{Alert, Key, Protocol};

#[derive(Debug, Deserialize)]
struct Line {
    event_type: String,
    pcap_cnt: Option<u64>,
    src_ip: Option<IpAddr>,
    src_port: Option<u16>,
    dest_ip: Option<IpAddr>,
    dest_port: Option<u16>,
    proto: Option<String>,
    alert: Option<Signature>,
}

#[derive(Debug, Deserialize)]
struct Signature {
    signature_id: u64,
}

pub struct Alerts<R> {
    lines: Lines<R>,
    next: Option<(u64, Alert)>,
    done: bool,
    pub unplaced: u64,
    pub out_of_order: u64,
}

impl<R: BufRead> Alerts<R> {
    pub fn new(input: R) -> Self {
        Self {
            lines: input.lines(),
            next: None,
            done: false,
            unplaced: 0,
            out_of_order: 0,
        }
    }

    pub fn take(&mut self, packet: u64, out: &mut Vec<Alert>) -> io::Result<()> {
        out.clear();
        loop {
            self.fill()?;
            match self.next {
                Some((n, _)) if n < packet => self.out_of_order += 1,
                Some((n, alert)) if n == packet => out.push(alert),
                _ => return Ok(()),
            }
            self.next = None;
        }
    }

    pub fn remaining(&mut self) -> io::Result<u64> {
        let mut n = 0;
        loop {
            self.fill()?;
            if self.next.take().is_none() {
                return Ok(n);
            }
            n += 1;
        }
    }

    fn fill(&mut self) -> io::Result<()> {
        while self.next.is_none() && !self.done {
            let Some(line) = self.lines.next() else {
                self.done = true;
                break;
            };
            match parse(&line?)? {
                Some((Some(n), alert)) => self.next = Some((n, alert)),
                Some((None, _)) => self.unplaced += 1,
                None => {}
            }
        }
        Ok(())
    }
}

fn parse(line: &str) -> io::Result<Option<(Option<u64>, Alert)>> {
    if !line.contains("\"alert\"") {
        return Ok(None);
    }
    let line: Line = serde_json::from_str(line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let (Some(signature), "alert") = (line.alert, line.event_type.as_str()) else {
        return Ok(None);
    };
    let protocol = match line.proto.as_deref() {
        Some("TCP") => Some(Protocol::Tcp),
        Some("UDP") => Some(Protocol::Udp),
        _ => None,
    };
    let key = match (protocol, line.src_ip, line.src_port, line.dest_ip, line.dest_port) {
        (Some(protocol), Some(src), Some(sport), Some(dst), Some(dport)) => {
            Some(Key::new(protocol, SocketAddr::new(src, sport), SocketAddr::new(dst, dport)))
        }
        _ => None,
    };
    let alert = Alert {
        key,
        sid: signature.signature_id,
    };
    Ok(Some((line.pcap_cnt, alert)))
}

#[cfg(test)]
mod tests;
