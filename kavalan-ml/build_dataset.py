#!/usr/bin/env python3
"""
build_dataset.py - assembles Kavalan's request-tactic training set from public sources.

Classes: benign, sqli, xss, cmdi, traversal, ssrf

Sources (all downloaded into data/ beforehand):
  HttpParamsDataset (Morzeux, GitHub)  benign values from CSIC 2010, sqlmap SQLi,
                                        XSS, command injection, path traversal
  SecLists (danielmiessler, GitHub)     XSS-Jhaddix, LFI-Jhaddix, command-injection-commix
  PayloadsAllTheThings SSRF README      SSRF target URLs
  Generated here (marked source=generated):
    SSRF variants built from standard internal targets and schemes, and benign
    external URLs, so the model cannot learn "any URL means SSRF".

Every row keeps its source, so evaluation can test on a source the model never saw.
Writes data/dataset.csv
"""
import csv
import random
import re
from pathlib import Path
from urllib.parse import unquote

D = Path(__file__).parent / "data"
rng = random.Random(7)
rows = []


def norm(s):
    """Same normalisation the detector applies: decode twice, lowercase, trim."""
    return unquote(unquote(s)).strip().lower()


def add(payload, label, source):
    p = norm(payload)
    if p and len(p) <= 2000:
        rows.append((p, label, source))


# 1. HttpParamsDataset
LABELS = {"norm": "benign", "sqli": "sqli", "xss": "xss", "cmdi": "cmdi", "path-traversal": "traversal"}
FILES = ["/etc/passwd", "/etc/hosts", "/windows/win.ini", "/boot.ini", "/etc/shadow", "/proc/self/environ"]
with open(D / "payload_full.csv", newline="") as f:
    for r in csv.DictReader(f):
        p = r["payload"]
        if "{file}" in p:  # scanner template: fill in a real target file
            p = p.replace("{file}", rng.choice(FILES).lstrip("/"))
        add(p, LABELS[r["attack_type"]], "httpparams")

# 2. SecLists
for line in (D / "XSS-Jhaddix.txt").read_text(errors="replace").splitlines():
    add(line, "xss", "seclists")
for line in (D / "LFI-Jhaddix.txt").read_text(errors="replace").splitlines():
    if ".." in line or "%2e" in line.lower() or "2f" in line.lower():  # keep real traversal strings,
        add(line, "traversal", "seclists")                               # not bare file names
commix = [l for l in (D / "command-injection-commix.txt").read_text(errors="replace").splitlines() if l.strip()]
for line in rng.sample(commix, 1500):  # 8k near-identical templates; a sample avoids swamping the set
    add(line, "cmdi", "seclists")

# 3. SSRF from PayloadsAllTheThings, keeping only URLs that point at internal targets
INTERNAL = re.compile(r"(localhost|127\.|0\.0\.0\.0|0x7f|169\.254|\[::|\[0:0|metadata|2130706433|017700000001|"
                      r"^(file|gopher|dict|ftp|ldap|tftp|jar|netdoc)://)", re.I)
md = (D / "ssrf_README.md").read_text(errors="replace")
for u in set(re.findall(r"(?:https?|gopher|file|dict|ftp|ldap|tftp|jar|netdoc)://[^\s`\"<>)\]]+", md)):
    if INTERNAL.search(u) and "github.com" not in u and "web.archive" not in u:
        add(u, "ssrf", "payloadsallthethings")

# 4. Generated SSRF variants and benign URLs
hosts = ["127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0", "[::1]", "0x7f000001", "2130706433",
         "127.1", "metadata.google.internal", "10.0.0.1", "192.168.1.1", "172.16.0.1", "internal-api"]
paths = ["", "/", "/admin", "/latest/meta-data/", "/latest/meta-data/iam/security-credentials/",
         "/computeMetadata/v1/", "/server-status", "/.env", ":6379/", ":8080/actuator/env", ":2375/containers/json"]
for _ in range(400):
    scheme = rng.choice(["http", "http", "https", "gopher", "dict"])
    add(f"{scheme}://{rng.choice(hosts)}{rng.choice(paths)}", "ssrf", "generated")
for _ in range(80):
    add(f"file://{rng.choice(FILES)}", "ssrf", "generated")

sites = ["example.com", "github.com", "docs.python.org", "en.wikipedia.org", "news.ycombinator.com",
         "www.google.com", "cdn.jsdelivr.net", "images.unsplash.com", "stackoverflow.com", "arxiv.org"]
words = ["about", "docs", "search", "image", "profile", "article", "page", "blog", "release", "user"]
for _ in range(600):
    path = "/".join(rng.sample(words, rng.randint(1, 3)))
    q = f"?q={rng.choice(words)}&page={rng.randint(1, 50)}" if rng.random() < 0.4 else ""
    add(f"https://{rng.choice(sites)}/{path}{q}", "benign", "generated")

# dedupe on normalised payload; drop strings that appear under two labels
seen, clash = {}, set()
for p, label, src in rows:
    if p in seen and seen[p][0] != label:
        clash.add(p)
    seen.setdefault(p, (label, src))
out = [(p, l, s) for p, (l, s) in seen.items() if p not in clash]

with open(D / "dataset.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["payload", "label", "source"])
    w.writerows(out)

from collections import Counter
print(f"{len(out):,} unique payloads ({len(rows) - len(out):,} duplicates or conflicts removed)")
for (l, s), n in sorted(Counter((l, s) for _, l, s in out).items()):
    print(f"  {l:<10} {s:<22} {n:>6}")
