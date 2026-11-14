#!/usr/bin/env python3
"""Attach a TCX ingress program that only returns TCX_NEXT, to test how wnc-gw discloses other programs.

usage: foreign_tcx.py <interface> first|last [name]
Keeps the program attached until it gets SIGINT or SIGTERM (needs CAP_BPF and CAP_NET_ADMIN).
"""
import ctypes
import os
import signal
import socket
import struct
import sys

SYS_BPF = {"x86_64": 321, "aarch64": 280}[os.uname().machine]
BPF_PROG_LOAD, BPF_LINK_CREATE = 5, 28
BPF_PROG_TYPE_SCHED_CLS, BPF_TCX_INGRESS = 3, 46
BPF_F_BEFORE, BPF_F_AFTER = 1 << 3, 1 << 4

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def bpf(cmd, attr):
    buf = ctypes.create_string_buffer(attr, len(attr))
    ret = libc.syscall(ctypes.c_long(SYS_BPF), ctypes.c_long(cmd), buf, ctypes.c_long(len(attr)))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def main():
    if len(sys.argv) < 3 or sys.argv[2] not in ("first", "last"):
        sys.exit(__doc__)
    ifindex = socket.if_nametoindex(sys.argv[1])
    name = (sys.argv[3] if len(sys.argv) > 3 else "foreign").encode()[:15]
    # r0 = -1 (TCX_NEXT); exit
    insns = struct.pack("<BBhi", 0xB7, 0, 0, -1) + struct.pack("<BBhi", 0x95, 0, 0, 0)
    insns_buf = ctypes.create_string_buffer(insns, len(insns))
    license_buf = ctypes.create_string_buffer(b"GPL")
    prog_fd = bpf(BPF_PROG_LOAD, struct.pack(
        "<IIQQIIQII16sII", BPF_PROG_TYPE_SCHED_CLS, 2, ctypes.addressof(insns_buf),
        ctypes.addressof(license_buf), 0, 0, 0, 0, 0, name, 0, 0))
    flags = BPF_F_BEFORE if sys.argv[2] == "first" else BPF_F_AFTER
    bpf(BPF_LINK_CREATE, struct.pack("<IIIIIIQ", prog_fd, ifindex, BPF_TCX_INGRESS, flags, 0, 0, 0))
    print(f"attached {name.decode()} {sys.argv[2]} on {sys.argv[1]} tcx ingress", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        signal.pause()
    except KeyboardInterrupt:
        pass


main()
