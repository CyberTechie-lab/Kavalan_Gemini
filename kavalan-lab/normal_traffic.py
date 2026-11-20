#!/usr/bin/env python3
"""
normal_traffic.py - generates realistic benign traffic against the lab Juice Shop,
so Kavalan has a "normal" baseline to measure false positives against.

It behaves like several ordinary shoppers: browsing products, searching with
plain words, viewing the basket, reading reviews, with human-like pauses. It
sends no attack payloads. Run it during your "normal" window.

Usage:
    python3 normal_traffic.py --base http://127.0.0.1:8080 --minutes 15 --shoppers 6
"""
import argparse
import random
import threading
import time
import urllib.parse
import urllib.request

PRODUCT_SEARCHES = ["apple", "juice", "banana", "cherry", "lemon", "orange",
                    "t-shirt", "sticker", "cover", "melon", "honey", "coffee"]
PAGES = ["/", "/#/", "/#/search", "/#/login", "/#/register", "/#/contact",
         "/#/about", "/#/photo-wall", "/#/score-board"]
API = ["/rest/products/search?q=", "/api/Products", "/api/Challenges/",
       "/rest/basket/1", "/api/Quantitys/"]
ASSETS = ["/main.js", "/styles.css", "/vendor.js", "/runtime.js",
          "/assets/public/images/products/apple_juice.jpg",
          "/assets/public/favicon_js.ico"]


def get(base, path, ua):
    url = base + path
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read(2048)
            return r.status
    except Exception:
        return None


def shopper(base, stop_at, ua, rng):
    # each shopper loads the app once, then browses and searches at a human pace
    get(base, "/", ua)
    for a in rng.sample(ASSETS, 3):
        get(base, a, ua)
    while time.time() < stop_at:
        roll = rng.random()
        if roll < 0.4:
            term = rng.choice(PRODUCT_SEARCHES)
            get(base, "/rest/products/search?q=" + urllib.parse.quote(term), ua)
        elif roll < 0.7:
            get(base, rng.choice(PAGES), ua)
            if rng.random() < 0.5:
                get(base, rng.choice(ASSETS), ua)
        elif roll < 0.9:
            get(base, rng.choice(API), ua)
        else:
            get(base, "/rest/products/" + str(rng.randint(1, 40)) + "/reviews", ua)
        time.sleep(rng.uniform(2, 12))  # human think-time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8080")
    ap.add_argument("--minutes", type=float, default=15)
    ap.add_argument("--shoppers", type=int, default=6)
    args = ap.parse_args()

    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Version/17.6 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/129.0 Mobile Safari/537.36",
    ]
    stop_at = time.time() + args.minutes * 60
    print(f"{args.shoppers} shoppers browsing {args.base} for {args.minutes} min. Ctrl-C to stop early.")
    threads = []
    for i in range(args.shoppers):
        rng = random.Random(1000 + i)
        t = threading.Thread(target=shopper, args=(args.base, stop_at, rng.choice(uas), rng))
        t.daemon = True
        t.start()
        threads.append(t)
        time.sleep(rng.uniform(0.5, 3))  # shoppers arrive staggered
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\nStopping.")
    print("Done. Check logs/access.log")


if __name__ == "__main__":
    main()
