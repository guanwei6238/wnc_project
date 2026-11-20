#!/usr/bin/env python3
"""Count packets of one length at a TCX hook, to see which hooks a packet passes.

usage: tcx_count.py <interface> ingress|egress <skb len> <output file>
Attaches last on the hook, returns TCX_NEXT, and writes the count to the file every 0.2 s
until SIGINT or SIGTERM (needs CAP_BPF and CAP_NET_ADMIN). skb len includes the Ethernet header.
"""
import ctypes
import os
import signal
import socket
import struct
import sys
import time

SYS_BPF = {"x86_64": 321, "aarch64": 280}[os.uname().machine]
BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_PROG_LOAD, BPF_LINK_CREATE = 0, 1, 5, 28
BPF_MAP_TYPE_ARRAY, BPF_PROG_TYPE_SCHED_CLS = 2, 3
HOOKS = {"ingress": 46, "egress": 47}
BPF_F_AFTER = 1 << 4

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def bpf(cmd, attr):
    buf = ctypes.create_string_buffer(attr, len(attr))
    ret = libc.syscall(ctypes.c_long(SYS_BPF), ctypes.c_long(cmd), buf, ctypes.c_long(len(attr)))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def insn(code, dst=0, src=0, off=0, imm=0):
    return struct.pack("<BBhi", code, (src << 4) | dst, off, imm)


def main():
    if len(sys.argv) != 5 or sys.argv[2] not in HOOKS:
        sys.exit(__doc__)
    ifindex = socket.if_nametoindex(sys.argv[1])
    length, out = int(sys.argv[3]), sys.argv[4]
    map_fd = bpf(BPF_MAP_CREATE, struct.pack("<IIIII", BPF_MAP_TYPE_ARRAY, 4, 8, 1, 0) + bytes(52))
    insns = b"".join([
        insn(0x61, dst=2, src=1, off=0),        # r2 = skb->len
        insn(0x55, dst=2, off=9, imm=length),   # if r2 != length goto out
        insn(0x62, dst=10, off=-4, imm=0),      # *(u32 *)(r10 - 4) = 0
        insn(0x18, dst=1, src=1, imm=map_fd),   # r1 = map
        insn(0x00),
        insn(0xBF, dst=2, src=10),              # r2 = r10
        insn(0x07, dst=2, imm=-4),              # r2 -= 4
        insn(0x85, imm=1),                      # call bpf_map_lookup_elem
        insn(0x15, dst=0, off=2, imm=0),        # if r0 == 0 goto out
        insn(0xB7, dst=1, imm=1),               # r1 = 1
        insn(0xDB, dst=0, src=1, off=0, imm=0), # lock *(u64 *)(r0 + 0) += r1
        insn(0xB7, dst=0, imm=-1),              # out: r0 = -1 (TCX_NEXT)
        insn(0x95),                             # exit
    ])
    insns_buf = ctypes.create_string_buffer(insns, len(insns))
    license_buf = ctypes.create_string_buffer(b"GPL")
    prog_fd = bpf(BPF_PROG_LOAD, struct.pack(
        "<IIQQIIQII16sII", BPF_PROG_TYPE_SCHED_CLS, len(insns) // 8, ctypes.addressof(insns_buf),
        ctypes.addressof(license_buf), 0, 0, 0, 0, 0, b"tcx_count", 0, 0))
    bpf(BPF_LINK_CREATE, struct.pack("<IIIIIIQ", prog_fd, ifindex, HOOKS[sys.argv[2]], BPF_F_AFTER, 0, 0, 0))
    key, value = ctypes.c_uint32(0), ctypes.c_uint64(0)
    lookup = struct.pack("<IIQQQ", map_fd, 0, ctypes.addressof(key), ctypes.addressof(value), 0)
    running = [True]
    signal.signal(signal.SIGTERM, lambda *_: running.__setitem__(0, False))
    signal.signal(signal.SIGINT, lambda *_: running.__setitem__(0, False))
    while running[0]:
        bpf(BPF_MAP_LOOKUP_ELEM, lookup)
        with open(out + ".tmp", "w") as f:
            f.write(f"{value.value}\n")
        os.replace(out + ".tmp", out)
        time.sleep(0.2)


main()
