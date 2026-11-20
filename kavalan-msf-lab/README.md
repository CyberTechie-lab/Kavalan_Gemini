# Kavalan — Metasploitable multi-source lab

A realistic target for testing Kavalan beyond web traffic. You attack a vulnerable box on
**two fronts** — the web app and SSH — and Kavalan reads **both** logs and ties a single
attacker across them into one cross-source agent. That cross-source correlation is the
thing signature SIEMs can't do, and the point this lab proves.

> **Safety first.** Metasploitable 2 is deliberately insecure. The compose file binds its
> ports to `127.0.0.1` only. **Never** expose it to a network or the internet, and don't
> run other sensitive services on the same machine while it's up.

## What's here
- `docker-compose.yml` — the Metasploitable 2 target (SSH on `2222`, HTTP on `8080`)
- `collect_logs.sh` — streams the box's `auth.log` + Apache `access.log` into `./logs/`
- `attack_ssh.py` — SSH brute-force (needs `pip3 install paramiko`)
- web attack — reuse `script_attack.py` from your `kavalan-lab` folder, or Strix
- detection — `kavalan_multi.py` in your `kavalan-ml` folder

## Prerequisites
- Docker Desktop running
- `pip3 install paramiko`

## Run it (4 terminal tabs)

**1 — start the target**
```bash
cd ~/Downloads/Kavalan/kavalan-msf-lab
docker compose up -d
# give it ~30s to boot its services, then confirm the web app answers:
curl -s -o /dev/null -w "web: %{http_code}\n" http://127.0.0.1:8080/
```

**2 — start the log collector (leave running)**
```bash
cd ~/Downloads/Kavalan/kavalan-msf-lab
bash collect_logs.sh
```

**3 — attack both channels**
```bash
cd ~/Downloads/Kavalan/kavalan-msf-lab
# SSH brute force -> fills auth.log
python3 attack_ssh.py --host 127.0.0.1 --port 2222 --tries 60
# Web scan -> fills access.log  (reuse the scripted scanner you already have)
python3 ~/Downloads/Kavalan/kavalan-lab/script_attack.py --base http://127.0.0.1:8080 --minutes 3 --rate 10
```

**4 — run Kavalan across both logs**
```bash
cd ~/Downloads/Kavalan/kavalan-ml
python3 kavalan_multi.py \
  --web  ~/Downloads/Kavalan/kavalan-msf-lab/logs/access.log \
  --auth ~/Downloads/Kavalan/kavalan-msf-lab/logs/auth.log
```
You'll see SSH and web sources scored separately, and — if you drive both from the same
machine — a **CROSS-SOURCE** alert tying them together.

> To make the cross-source agent obvious, run the SSH brute force and the web scan from the
> **same** host so they share a source IP. On this single-box setup that happens naturally.

## No Docker? Prove the engine first
The detector doesn't need the lab to demonstrate. From `kavalan-ml`:
```bash
python3 simulate_multi.py          # writes a matching access.log + auth.log
python3 kavalan_multi.py --web access.log --auth auth.log
```
This runs a built-in scenario (benign users, a web scanner, an SSH brute-forcer, and one
cross-source agent) so you can see the output shape instantly.

## Troubleshooting
- **Container won't stay up:** `docker logs kavalan-msf`. Some Metasploitable images need a
  service kick: `docker exec -it kavalan-msf service apache2 start && docker exec -it kavalan-msf service ssh start`.
- **No lines in `logs/auth.log`:** SSH logging needs syslog running in the box:
  `docker exec -it kavalan-msf service rsyslog start` (or `/etc/init.d/sysklogd start`), then retry the brute force.
- **SSH connection errors (no matching key exchange / host key):** Metasploitable uses old
  algorithms. `attack_ssh.py` widens them via paramiko; if your client still refuses, add to the attempt:
  `ssh -oHostKeyAlgorithms=+ssh-rsa -oKexAlgorithms=+diffie-hellman-group1-sha1 msfadmin@127.0.0.1 -p 2222`.
- **No lines in `logs/access.log`:** confirm the web path with the `curl` check in step 1;
  Apache may log to `/var/log/apache2/other_vhosts_access.log` on some images — adjust `collect_logs.sh` if so.

## Shut down
```bash
cd ~/Downloads/Kavalan/kavalan-msf-lab && docker compose down
```
