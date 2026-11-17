#!/usr/bin/env python3
"""A long TLS connection that is busy, then idle, then busy again (the HTTPS keep-alive case for trust).

usage: tls_idle.py server <port> <cert> <key>
       tls_idle.py client <server ip> <port> <source ip> <source port> <phase>...
  phase = <seconds>:<interval>  send one echoed line every <interval> seconds for <seconds> seconds;
          <seconds>:0           stay idle
          mark:<file>           create <file> (the driver waits for it, e.g. to run wnc-gw trust del)
The client prints one line per phase and a final "result ..." line; an echo that does not come back
within 5 s, or a connection error, ends the client with ok=0 and the time it happened.
"""
import os
import socket
import ssl
import sys
import threading
import time


def server(port, cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("", port))
    listener.listen(16)

    def echo(raw):
        try:
            with context.wrap_socket(raw, server_side=True) as conn:
                while data := conn.recv(4096):
                    conn.sendall(data)
        except OSError:
            pass

    while True:
        threading.Thread(target=echo, args=(listener.accept()[0],), daemon=True).start()


def client(host, port, source, sport, phases):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    start = time.time()
    sent = echoed = 0
    buffer = b""
    try:
        raw = socket.create_connection((host, port), timeout=5, source_address=(source, sport))
        conn = context.wrap_socket(raw)
        print(f"connected {conn.version()} t=0", flush=True)
        for phase in phases:
            what, arg = phase.split(":", 1)
            if what == "mark":
                open(arg, "w").close()
                continue
            seconds, interval = float(what), float(arg)
            if interval == 0:
                time.sleep(seconds)
                print(f"idle {seconds:.0f} s t={time.time() - start:.0f}", flush=True)
                continue
            end = time.time() + seconds
            before = echoed
            slowest = 0.0
            while time.time() < end:
                line = f"line {sent}\n".encode()
                sent_at = time.time()
                conn.sendall(line)
                sent += 1
                while b"\n" not in buffer:
                    data = conn.recv(4096)
                    if not data:
                        raise ConnectionError("closed by the server")
                    buffer += data
                got, buffer = buffer.split(b"\n", 1)
                if got + b"\n" != line:
                    raise ConnectionError(f"wrong echo {got!r}")
                echoed += 1
                slowest = max(slowest, time.time() - sent_at)
                time.sleep(interval)
            print(f"busy {seconds:.0f} s every {interval} s: echoed {echoed - before}, slowest echo "
                  f"{1000 * slowest:.0f} ms t={time.time() - start:.0f}", flush=True)
        conn.close()
        print(f"result ok=1 sent={sent} echoed={echoed} t={time.time() - start:.0f}", flush=True)
    except (OSError, ConnectionError) as e:
        print(f"result ok=0 sent={sent} echoed={echoed} t={time.time() - start:.0f} error={e!r}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "server":
        server(int(sys.argv[2]), sys.argv[3], sys.argv[4])
    elif len(sys.argv) >= 7 and sys.argv[1] == "client":
        client(sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5]), sys.argv[6:])
    else:
        sys.exit(__doc__)
    os._exit(0)
