use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use nfq::{Queue, Verdict};

const QUEUE_NUM: u16 = 0;

fn main() -> std::io::Result<()> {
    let mut queue = Queue::open()?;

    // 順序很重要：必須先 bind 才能對這個佇列做設定。
    // 反過來寫會得到 ENODEV（"No such device"），因為佇列還不存在。
    queue.bind(QUEUE_NUM)?;

    // 讓 kernel 連 conntrack 資訊一起送過來（flow id、連線狀態）。
    // 這在「同一條 flow 不要重複問雲端」時會用到 —— 現在只是印出來看。
    queue.set_recv_conntrack(QUEUE_NUM, true)?;

    println!("已綁定 NFQUEUE #{QUEUE_NUM}。等待封包…（Ctrl-C 結束）");
    println!("（規則用了 `flags bypass`，所以這支程式沒跑的時候封包會直接放行，網路不會斷）\n");

    let mut n: u64 = 0;
    loop {
        // 收一個封包。沒有封包時會阻塞在這裡。
        let mut msg = queue.recv()?;
        n += 1;

        // ---- 印出 kernel 附帶的中介資訊（不是封包內容）----
        print!(
            "#{n}  packet_id={}  hook={}  原始長度={} bytes",
            msg.get_packet_id(),
            msg.get_hook(),
            msg.get_original_len()
        );
        if let Some(ct) = msg.get_conntrack() {
            print!("  ct_id={} ct_state={:?}", ct.get_id(), ct.get_state());
        }
        println!();

        // ---- 解析封包本身 ----
        // 注意 from_ip_slice：NFQUEUE 給的 payload 從 IP header 開始，
        // 沒有 Ethernet header（netfilter 的 hook 在 L3）。
        describe(msg.get_payload());

        // ---- 回 verdict。這一版一律放行 ----
        // 之後這裡會變成：本地判斷 → 判不出來就問雲端 → 再決定 Accept/Drop
        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg)?;
    }
}

/// 把一個 IP 封包拆開印出來。
fn describe(raw: &[u8]) {
    let pkt = match PacketHeaders::from_ip_slice(raw) {
        Ok(p) => p,
        Err(e) => {
            println!("    解析失敗: {e:?}（前 16 bytes: {:02x?}）", &raw[..raw.len().min(16)]);
            return;
        }
    };

    // ---------- L3：網路層 ----------
    match &pkt.net {
        Some(NetHeaders::Ipv4(ip, _ext)) => {
            println!(
                "    L3  IPv4  {} -> {}   protocol={:?}  ttl={}  總長={}  {}",
                fmt_v4(ip.source),
                fmt_v4(ip.destination),
                ip.protocol,
                ip.time_to_live,
                ip.total_len,
                // 分片是安全設備的經典攻擊面：惡意內容切在兩個分片裡
                if ip.more_fragments || ip.fragment_offset.value() > 0 {
                    "[已分片!]"
                } else {
                    ""
                },
            );
        }
        Some(NetHeaders::Ipv6(ip, _ext)) => {
            println!(
                "    L3  IPv6  {:x?} -> {:x?}  hop_limit={}",
                ip.source, ip.destination, ip.hop_limit
            );
        }
        other => println!("    L3  非 IP 或無法解析: {other:?}"),
    }

    // ---------- L4：傳輸層 ----------
    match &pkt.transport {
        Some(TransportHeader::Tcp(tcp)) => {
            // TCP flags 就是連線狀態機的全部依據。
            // 只有 SYN 沒有 ACK = 有人在開新連線。
            let mut flags = Vec::new();
            if tcp.syn { flags.push("SYN") }
            if tcp.ack { flags.push("ACK") }
            if tcp.fin { flags.push("FIN") }
            if tcp.rst { flags.push("RST") }
            if tcp.psh { flags.push("PSH") }
            if tcp.urg { flags.push("URG") }
            println!(
                "    L4  TCP   {} -> {}   flags=[{}]  seq={}  window={}",
                tcp.source_port,
                tcp.destination_port,
                flags.join(","),
                tcp.sequence_number,
                tcp.window_size
            );
        }
        Some(TransportHeader::Udp(udp)) => {
            println!(
                "    L4  UDP   {} -> {}   長度={}",
                udp.source_port, udp.destination_port, udp.length
            );
        }
        Some(TransportHeader::Icmpv4(icmp)) => {
            println!("    L4  ICMP  {:?}", icmp.icmp_type);
        }
        Some(TransportHeader::Icmpv6(icmp)) => {
            println!("    L4  ICMPv6 {:?}", icmp.icmp_type);
        }
        Some(TransportHeader::Igmp(igmp)) => {
            println!("    L4  IGMP  {igmp:?}");
        }
        None => println!("    L4  （無傳輸層）"),
    }

    // ---------- L7：應用層 payload ----------
    // 這是「本地看不看得懂」的關鍵。HTTP 是明文，HTTPS 是加密的。
    let body = pkt.payload.slice();
    if body.is_empty() {
        println!("    L7  （無 payload —— 這通常是連線建立階段的封包）");
    } else {
        let head = &body[..body.len().min(32)];
        println!("    L7  {} bytes  前 32 bytes hex: {:02x?}", body.len(), head);
        println!("        可列印字元: {}", printable(head));
    }
    println!();
}

fn fmt_v4(a: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

/// 把 bytes 轉成可讀字串，非可列印字元顯示成 '.'（就像 tcpdump -X 的右半邊）
fn printable(b: &[u8]) -> String {
    b.iter()
        .map(|&c| if c.is_ascii_graphic() || c == b' ' { c as char } else { '.' })
        .collect()
}
