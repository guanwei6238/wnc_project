#!/usr/bin/env python3
"""pcap_stats.py -- read a classic pcap with the standard library and print one JSON line of stats (no Scapy/capinfos, runs on the Pi too).

Usage:  python3 -I pcap_stats.py <file.pcap>

Why custom: we need just packet count, bytes, duration and payload share,
and they must reconcile with the engine's self-reported decoded packet count; computing them ourselves makes the definitions explicit.

Definitions (cited in the report):
  packets        number of packet records in the pcap (a truncated last record is not counted; flagged with truncated_tail=true)
  bytes_wire     sum(orig_len)  on-the-wire packet length
  bytes_cap      sum(incl_len)  length actually stored in the pcap (= what the engine sees; equal to bytes_wire when not cut by snaplen)
  duration       last packet time - first packet time (seconds)
  avg_pkt_size   bytes_cap / packets
  payload packet TCP or UDP with L4 payload length > 0 (ICMP, ARP, bare ACK/SYN do not count)
  payload_pkt_share   payload packets / packets
  payload_byte_share  sum(L4 payload length) / bytes_cap   (denominator includes Ethernet/IP/TCP headers, so always < 1)
  L4 payload length = IP total length - IP header - TCP/UDP header (uses the IP header length, so Ethernet padding is excluded)
"""
import struct, sys, json

def main(path):
    f = open(path, 'rb')
    gh = f.read(24)
    if len(gh) < 24:
        sys.exit("not a pcap (too short)")
    magic = gh[:4]
    if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
        e = '<'
    elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        e = '>'
    else:
        sys.exit("unsupported magic %r (pcapng?)" % magic)
    nano = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    snaplen, linktype = struct.unpack(e + '8xII', gh[8:24])
    rec = struct.Struct(e + 'IIII')
    read = f.read
    n = bytes_wire = bytes_cap = 0
    t_first = t_last = None
    cnt = dict(tcp=0, udp=0, icmp=0, other_ip=0, non_ip=0, l4_unparsed=0)
    pl_pkts = pl_bytes = 0
    truncated = False
    while True:
        h = read(16)
        if not h:
            break
        if len(h) < 16:
            truncated = True; break
        sec, frac, incl, orig = rec.unpack(h)
        data = read(incl)
        if len(data) < incl:
            truncated = True; break
        t = sec + frac / (1e9 if nano else 1e6)
        if t_first is None: t_first = t
        t_last = t
        n += 1; bytes_wire += orig; bytes_cap += incl
        # --- find the start of the IP header ---
        if linktype == 1:           # Ethernet
            off = 14
            et = (data[12] << 8 | data[13]) if incl >= 14 else 0
            while et in (0x8100, 0x88a8) and incl >= off + 4:   # VLAN tag
                et = data[off + 2] << 8 | data[off + 3]; off += 4
        elif linktype == 101:       # raw IP
            off = 0
            et = 0x0800 if data[:1] and data[0] >> 4 == 4 else 0x86dd
        elif linktype == 113:       # Linux cooked
            off = 16; et = data[14] << 8 | data[15] if incl >= 16 else 0
        else:
            et = 0; off = 0
        proto = None; l4 = None; ip_end = None
        if et == 0x0800 and incl >= off + 20:
            ihl = (data[off] & 0x0f) * 4
            tot = data[off + 2] << 8 | data[off + 3]
            fragoff = (data[off + 6] & 0x1f) << 8 | data[off + 7]
            proto = data[off + 9]
            ip_end = min(off + tot, incl)
            l4 = off + ihl
            if fragoff: proto = -1          # not the first fragment, no L4 header
        elif et == 0x86dd and incl >= off + 40:
            plen = data[off + 4] << 8 | data[off + 5]
            proto = data[off + 6]
            ip_end = min(off + 40 + plen, incl)
            l4 = off + 40
        else:
            cnt['non_ip'] += 1
            continue
        pl = 0
        if proto == 6 and incl >= l4 + 13:
            cnt['tcp'] += 1
            pl = ip_end - (l4 + ((data[l4 + 12] >> 4) * 4))
        elif proto == 17 and incl >= l4 + 8:
            cnt['udp'] += 1
            pl = ip_end - (l4 + 8)
        elif proto in (1, 58):
            cnt['icmp'] += 1
        elif proto == -1 or proto in (6, 17):
            cnt['l4_unparsed'] += 1
        else:
            cnt['other_ip'] += 1
        if pl > 0:
            pl_pkts += 1; pl_bytes += pl
    dur = (t_last - t_first) if n else 0.0
    out = dict(file=path.split('/')[-1], packets=n, bytes_wire=bytes_wire, bytes_cap=bytes_cap,
               t_first=t_first, t_last=t_last, duration_s=round(dur, 6),
               avg_pkt_size=round(bytes_cap / n, 2) if n else 0,
               linktype=linktype, snaplen=snaplen, truncated_tail=truncated, **cnt,
               payload_pkts=pl_pkts, payload_bytes=pl_bytes,
               payload_pkt_share=round(pl_pkts / n, 6) if n else 0,
               payload_byte_share=round(pl_bytes / bytes_cap, 6) if bytes_cap else 0)
    print(json.dumps(out))

if __name__ == '__main__':
    main(sys.argv[1])
