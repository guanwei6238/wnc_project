#!/usr/bin/env python3
"""cases.py — generate the pcaps for exp 3: one complete connection (ground truth), then slice out "the subset Suricata gets to see"

Usage: python3 -I cases.py <output dir>
  One pcap per case, plus manifest.tsv (case, packet count, description). Maps to E1–E9 in research/literature/fastpath-methods/C-partial-inspection.md §2 C7.
Rules (rules.txt): R1 http.uri /evil (established), R2 same without established, R3 stream content EVIL, R4 packet content EVIL (depth),
R5 http.request_body EVIL, R6 mqtt publish EVIL, R7 est_invalid_ack, R8 content EVIL without established, R9 http.response_body BADRESP, R10 reassembly_seq_gap
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tcpgen import Session, http_req, http_resp, write_pcap

RULES = """alert http any any -> any any (msg:"R1 uri est"; flow:established,to_server; http.uri; content:"/evil"; sid:1; rev:1;)
alert http any any -> any any (msg:"R2 uri"; flow:to_server; http.uri; content:"/evil"; sid:2; rev:1;)
alert tcp any any -> any any (msg:"R3 stream est"; flow:established,to_server; content:"EVIL"; sid:3; rev:1;)
alert tcp any any -> any any (msg:"R4 packet est"; flow:established,to_server; content:"EVIL"; depth:1500; sid:4; rev:1;)
alert http any any -> any any (msg:"R5 req body"; flow:established,to_server; http.request_body; content:"EVIL"; sid:5; rev:1;)
alert mqtt any any -> any any (msg:"R6 mqtt"; flow:established,to_server; mqtt.publish.message; content:"EVIL"; sid:6; rev:1;)
alert tcp any any -> any any (msg:"R7 est_invalid_ack"; stream-event:est_invalid_ack; sid:7; rev:1;)
alert tcp any any -> any any (msg:"R8 stream"; flow:to_server; content:"EVIL"; sid:8; rev:1;)
alert http any any -> any any (msg:"R9 resp body"; flow:established,to_client; http.response_body; content:"BADRESP"; sid:9; rev:1;)
alert tcp any any -> any any (msg:"R10 seq gap"; stream-event:reassembly_seq_gap; sid:10; rev:1;)
"""


def http_conn(n_tx=20, resp=6000, evil_tx=15, post_tx=16, badresp_tx=17, evil2_tx=18, port=40001, emit=None, gap_s=None, wscale=None):
    """keep-alive HTTP. emit(tx) decides whether this transaction produces packets (if not, only seq advances); gap_s(tx) is the idle seconds before this transaction."""
    s = Session("10.0.1.2", port, "10.0.2.2", 80, wscale=wscale)
    s.handshake()
    for tx in range(1, n_tx + 1):
        s.tx = tx
        e = emit(tx) if emit else True
        if gap_s:
            s.idle(gap_s(tx))
        body = b""
        path = f"/page{tx}"
        if tx == evil_tx:
            path = "/evil?q=EVIL"
        elif tx == evil2_tx:
            path = "/evil2"
        elif tx == post_tx:
            body = b"a" * 200 + b"EVIL" + b"b" * 3796
            path = "/upload"
        s.send("c2s", http_req(path, body), "req", emit=e)
        r = http_resp(resp)
        if tx == badresp_tx:
            r = http_resp(resp, fill=b"x" * 60 + b"BADRESP" + b"y" * 40)
        s.send("s2c", r, "resp", emit=e)
    s.fin()
    return s.pkts


def mqtt_conn(n_pub=100, evil_pub=60, emit=None, gap_s=None):
    s = Session("10.0.1.2", 40100, "10.0.2.2", 1883)
    s.handshake()
    cid = b"tcpgen"
    var = b"\x00\x04MQTT\x04\x02\x00\x3c" + struct.pack("!H", len(cid)) + cid
    s.tx = 0
    s.send("c2s", bytes([0x10, len(var)]) + var, "connect")
    s.send("s2c", b"\x20\x02\x00\x00", "connack")
    topic = b"sensors/t"
    for i in range(1, n_pub + 1):
        s.tx = i
        e = emit(i) if emit else True
        if gap_s:
            s.idle(gap_s(i))
        msg = (b"EVIL-" if i == evil_pub else b"hello-") + str(i).encode()
        body = struct.pack("!H", len(topic)) + topic + msg
        s.send("c2s", bytes([0x30, len(body)]) + body, "publish", emit=e, ack_every=1)
    s.fin()
    return s.pkts


def first_index(pkts, **cond):
    for i, (_, _, m) in enumerate(pkts):
        if all(m.get(k) == v for k, v in cond.items()):
            return i
    raise KeyError(cond)


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, "rules.txt"), "w").write(RULES)
    cases = []

    def add(name, pkts, note):
        write_pcap(os.path.join(out, name + ".pcap"), pkts)
        cases.append((name, len(pkts), note))

    H = http_conn()
    add("h_full", H, "HTTP keep-alive 20 個交易（tx15 GET /evil?q=EVIL、tx16 POST body offset 200 有 EVIL、tx17 response 有 BADRESP、tx18 GET /evil2），全部封包")
    # E1/E9: start watching at different packets, then give everything after
    i15 = first_index(H, tx=15, msg="req", seg=0)
    add("e1_i_req_start", H[i15:], "從 tx15 request 的第一個封包開始")
    add("e1_ii_srv_ack", H[first_index(H, tx=14, msg="req_ack"):], "從 server 對 tx14 request 的純 ACK 開始（方向可能顛倒）")
    add("e1_iii_resp_start", H[first_index(H, tx=14, msg="resp", seg=0):], "從 tx14 response（HTTP/1.1 200）開始")
    add("e1_iv_resp_mid", H[first_index(H, tx=14, msg="resp", seg=2):], "從 tx14 response 中間開始")
    add("e1_v_post_mid", H[first_index(H, tx=16, msg="req", seg=2):], "從 tx16 POST body 中間開始（之後還有 tx18 GET /evil2）")
    # E2/E8: only a single packet, or a few more
    add("e2_one", H[i15:i15 + 1], "只有 tx15 request 一個封包")
    add("e2_two", H[i15:i15 + 2], "tx15 request + server 的 ACK")
    add("e2_three", H[i15:i15 + 3], "tx15 request + server ACK + response 第一段")
    j = first_index(H, tx=16, msg="req", seg=0)
    add("e2_tx15_all", H[i15:j], "tx15 整個交易（request、response、ACK）")
    # E3/E4: client→server only
    hs = H[:3]
    c2s = [p for p in H[3:] if p[2]["dir"] == "c2s"]
    c2s_data = [p for p in c2s if p[2]["kind"] in ("data", "fin")]
    add("e3_c2s_hs", hs + c2s, "握手完整，之後只有 client→server（含純 ACK）；response 總共約 120 KB")
    add("e3_c2s_hs_dataonly", hs + c2s_data, "握手完整，之後只有 client→server 的資料封包")
    k = first_index(H, tx=10, msg="req", seg=0)
    add("e3_c2s_mid", [p for p in H[k:] if p[2]["dir"] == "c2s"], "從 tx10 起只有 client→server（含純 ACK），沒有握手")
    B = http_conn(n_tx=3, resp=2_000_000, evil_tx=3, post_tx=0, badresp_tx=0, evil2_tx=0, port=40002)
    add("e3_bulk_full", B, "3 個交易、每個 response 2 MB，tx3 GET /evil")
    add("e3_bulk_c2s", B[:3] + [p for p in B[3:] if p[2]["dir"] == "c2s"], "同上，握手後只有 client→server")
    # E5: two visible segments of one connection (tx10–12, tx150–152), everything between skipped (seq advances normally), /evil in tx150
    for total, tag in ((100_000, "100k"), (2_000_000, "2m"), (20_000_000, "20m")):
        per = max(total // 137, 300)
        for gap, gtag in ((10, "gap10s"), (60, "gap60s")):
            P = http_conn(n_tx=160, resp=per, evil_tx=150, post_tx=0, badresp_tx=0, evil2_tx=0, port=40010,
                          emit=lambda tx: 10 <= tx <= 12 or 150 <= tx <= 152,
                          gap_s=lambda tx, g=gap: g if tx == 150 else 0)
            add(f"e5_{tag}_{gtag}", P, f"tx10–12 與 tx150–152 可見，中間跳過約 {tag}（每個 response {per} B），第二段前閒置 {gap} 秒")
    # E5b: observation period sees tx1–12 fully (Suricata has identified HTTP), everything skipped while trusted, tx150–152 seen again (audit window aligned to transaction start)
    # E5c: same, but the audit window starts in the middle of the tx149 response
    for total, tag in ((100_000, "100k"), (2_000_000, "2m"), (20_000_000, "20m")):
        per = max(total // 137, 300)
        for gap, gtag in ((10, "gap10s"), (60, "gap60s")):
            P = http_conn(n_tx=160, resp=per, evil_tx=150, post_tx=0, badresp_tx=0, evil2_tx=0, port=40020,
                          emit=lambda tx: tx <= 12 or 149 <= tx <= 152,
                          gap_s=lambda tx, g=gap: g if tx == 149 else 0)
            ctrl = lambda m: m["kind"] in ("syn", "synack", "fin") or (m["kind"] == "ack" and "tx" not in m)
            keep_b = [p for p in P if ctrl(p[2]) or p[2].get("tx", 0) <= 12 or 150 <= p[2].get("tx", 0) <= 152]
            add(f"e5b_{tag}_{gtag}", keep_b, f"tx1–12 完整可見，跳過約 {tag}，第二段 tx150–152 從 request 開頭（閒置 {gap} 秒）")
            if tag == "2m":
                keep_c = [p for p in P if ctrl(p[2]) or p[2].get("tx", 0) <= 12 or 150 <= p[2].get("tx", 0) <= 152
                          or (p[2].get("tx") == 149 and p[2].get("msg", "").startswith("resp") and p[2].get("seg", 0) >= 2)]
                add(f"e5c_{tag}_{gtag}", keep_c, f"同 e5b，但第二段從 tx149 response 中間開始（閒置 {gap} 秒）")
    # E5d: same as e5b (same Suricata session, 10 s idle), but while trusted every k-th pure ACK goes to Suricata (keeps its ACK/window in sync)
    for total, tag in ((2_000_000, "2m"), (20_000_000, "20m")):
        per = max(total // 137, 300)
        F = http_conn(n_tx=160, resp=per, evil_tx=150, post_tx=0, badresp_tx=0, evil2_tx=0, port=40030,
                      gap_s=lambda tx: 10 if tx == 149 else 0)
        for k in (1, 10, 50):
            n = [0]

            def keep(m, k=k, n=n):
                tx = m.get("tx", 0)
                if m["kind"] in ("syn", "synack", "fin") or (m["kind"] == "ack" and "tx" not in m):
                    return True
                if tx <= 12 or 150 <= tx <= 152:
                    return True
                if m["kind"] == "ack":
                    n[0] += 1
                    return n[0] % k == 0
                return False
            add(f"e5d_{tag}_ack{k}", [p for p in F if keep(p[2])], f"同 e5b（{tag}、閒置 10 秒），但跳過期間每 {k} 個純 ACK 放 1 個")
    # E5w: handshake with window scale 7 (window ~8 MiB), same as e5b (10 s idle), and no ACKs at all while skipped
    for total, tag in ((2_000_000, "2m"), (20_000_000, "20m")):
        per = max(total // 137, 300)
        P = http_conn(n_tx=160, resp=per, evil_tx=150, post_tx=0, badresp_tx=0, evil2_tx=0, port=40050, wscale=7,
                      emit=lambda tx: tx <= 12 or 150 <= tx <= 152, gap_s=lambda tx: 10 if tx == 150 else 0)
        add(f"e5w_{tag}_noack", P, f"window scale 7；tx1–12 可見，跳過約 {tag}（不給任何 ACK），tx150–152 可見")
    # DPA large response: each response 2 MB, only the first 2000 bytes of each message; ACKs all/none/1 in 10
    BIG = http_conn(n_tx=8, resp=2_000_000, evil_tx=6, post_tx=7, badresp_tx=8, evil2_tx=0, port=40040)
    for mode, k in (("acks", 1), ("noacks", 0), ("ack10", 10)):
        sub = []
        n = 0
        for p in BIG:
            m = p[2]
            if m["kind"] == "data":
                if m["off"] < 2000:
                    sub.append(p)
            elif m["kind"] == "ack" and m.get("msg", "").endswith("_ack"):
                n += 1
                if k and n % k == 0:
                    sub.append(p)
            else:
                sub.append(p)
        add(f"dpa_big_{mode}", sub, f"8 個交易、response 2 MB（tx6 GET /evil、tx7 POST EVIL、tx8 BADRESP），每個訊息前 2000 bytes，資料的純 ACK：{mode}")
    # E2b: connection already fully observed (tx1–3), then only the one packet that hit the prefilter (tx15 request) / that one transaction
    ctrl = lambda m: m["kind"] in ("syn", "synack", "fin") or (m["kind"] == "ack" and "tx" not in m)
    add("e2b_insession_one", [p for p in H if ctrl(p[2]) or p[2].get("tx", 0) <= 3 or (p[2].get("tx") == 15 and p[2].get("msg") == "req")],
        "tx1–3 完整，之後只有 tx15 request 一個封包，最後 FIN")
    add("e2b_insession_tx", [p for p in H if ctrl(p[2]) or p[2].get("tx", 0) <= 3 or p[2].get("tx") == 15],
        "tx1–3 完整，之後只有 tx15 整個交易，最後 FIN")
    # DPA style: only the first N bytes of each message (rest skipped), two ACK variants
    for n in (500, 2000):
        for acks in ("acks", "noacks"):
            sub = []
            for p in H:
                m = p[2]
                if m["kind"] == "data":
                    if m["off"] < n:
                        sub.append(p)
                elif m["kind"] == "ack" and m.get("msg", "").endswith("_ack"):
                    if acks == "acks":
                        sub.append(p)
                else:
                    sub.append(p)
            add(f"dpa_{n}_{acks}", sub, f"每個訊息只給前 {n} bytes 的段（含握手、FIN），{'保留' if acks == 'acks' else '去掉'}資料的純 ACK")
    # MQTT: full, starting midway, two visible segments
    M = mqtt_conn()
    add("m_full", M, "MQTT 3.1.1（port 1883）CONNECT + 100 個 PUBLISH，第 60 個含 EVIL")
    add("m_mid", M[first_index(M, tx=50, msg="publish"):], "從第 50 個 PUBLISH 開始")
    for gap, gtag in ((10, "gap10s"), (60, "gap60s")):
        P = mqtt_conn(emit=lambda i: 10 <= i <= 12 or 59 <= i <= 61, gap_s=lambda i, g=gap: g if i == 59 else 0)
        add(f"m_two_{gtag}", P, f"PUBLISH 10–12 與 59–61 可見，中間跳過，第二段前閒置 {gap} 秒")
    with open(os.path.join(out, "manifest.tsv"), "w") as f:
        for c in cases:
            f.write("\t".join(map(str, c)) + "\n")
    print(f"{len(cases)} cases -> {out}")


if __name__ == "__main__":
    main()
