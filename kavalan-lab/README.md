# Kavalan lab: capturing a real agent attack

The goal of this lab is to produce two real access logs on your own laptop — one of
normal browsing, one of an AI agent attacking — so you can test whether Kavalan
catches the agent and what it wrongly flags. Everything runs locally and offline;
nothing touches the college network or the public internet.

**Target:** OWASP Juice Shop, a deliberately vulnerable web app built for exactly this
kind of authorised testing.
**Time:** about 1 hour, most of it waiting for the agent to run.

---

## What's in this folder

| File | Purpose |
|---|---|
| `docker-compose.yml` | Runs Juice Shop behind nginx, isolated |
| `nginx.conf` | Reverse proxy that writes the access log Kavalan reads |
| `normal_traffic.py` | Generates benign shopper traffic for the baseline |
| `logs/` | Where `access.log` will appear |

You'll also need the detector from the `kavalan-ml` package (`detector.py` and the
trained model) to analyse the logs at the end.

---

## Prerequisites

- **Docker Desktop** (or Docker Engine + Compose), installed and running.
- **Python 3.8+** for the traffic generator and detector.
- **An LLM API key** for the attack agent. Any provider the agent supports works
  (OpenAI, Anthropic, DeepSeek, or a local model via Ollama). Budget a few dollars;
  a full agent run uses real tokens.

---

## Step 1 — Start the isolated target

From this folder:

```bash
docker compose up -d
```

This starts two containers:

- `lab-juice-shop` on an **internal-only** network, so the vulnerable app has no
  route to the internet.
- `lab-nginx`, published on **127.0.0.1:8080 only**, so nothing outside your laptop
  can reach the lab.

Confirm it's up by opening `http://127.0.0.1:8080` in your browser. You should see
the Juice Shop store.

> **Isolation check:** the compose file binds to `127.0.0.1`, not `0.0.0.0`. Keep it
> that way. It means a device on the same Wi-Fi or LAN cannot see the lab.

---

## Step 2 — Record the NORMAL window

This is your false-positive baseline: what ordinary use looks like.

```bash
# note the start time
date
python3 normal_traffic.py --base http://127.0.0.1:8080 --minutes 15 --shoppers 6
# note the end time
date
```

While that runs, browse the store yourself too — register an account, search for
products, add things to the basket. Real human clicks make the baseline stronger.

Write down the start and end times. You'll use them to label this slice of the log.

---

## Step 3 — Snapshot the log, then reset

Separate the two windows cleanly so each has its own ground truth:

```bash
cp logs/access.log logs/normal.log
: > logs/access.log          # truncate, so the attack window starts fresh
```

---

## Step 4 — Record the ATTACK window

Use an open-source AI pentesting agent. **Strix** is the simplest to point at a live
URL; its own docs have the current, authoritative steps, so follow those — the lines
below are the shape of a run, not a substitute for the official quickstart:

```bash
# install (see https://docs.strix.ai/quickstart for the current method)
curl -sSL https://strix.ai/install | bash

# choose your model and key
export STRIX_LLM="openai/gpt-5.4"      # or deepseek/..., anthropic/..., or a local model
export LLM_API_KEY="your-api-key"

# note the start time, then run non-interactively against the lab
date
strix -n --target http://127.0.0.1:8080
date
```

Let it run to completion (it can take a while). It will try many techniques against
the app — this is the agent behaviour you want recorded.

> **Authorised use only.** Run an attack agent only against this local lab target that
> you own. Keep it pointed at `127.0.0.1:8080` and nothing else.

Alternatives if you'd rather: **PentAGI** (runs in its own container; point it at the
nginx container's network hostname) or **Shannon** (needs the app's source code in a
folder as well as the URL). All three are open source and take any LLM key.

When it finishes, snapshot this window too:

```bash
cp logs/access.log logs/attack.log
```

---

## Step 5 — Run Kavalan on both logs

Copy `detector.py` and the `model/` folder from the `kavalan-ml` package into a place
you can run them, then:

```bash
# the attack window: did Kavalan catch the agent?
python3 detector.py logs/attack.log --model model/tactic_model.joblib --out attack_alerts.json

# the normal window: how many false alarms?
python3 detector.py logs/normal.log --model model/tactic_model.joblib --out normal_alerts.json
```

What you're looking for:

- **On `attack.log`:** a CRITICAL agent-campaign alert, or at least HIGH-scoring
  sources. That's a real agent caught for the first time, not a simulated one.
- **On `normal.log`:** ideally nothing. Every alert here is a false positive, and the
  real browsing data is exactly what we need to fix the model's weak spot (the
  "select a plan" problem from the training notes).

---

## Step 6 — Send me the results

Bring back `attack_alerts.json`, `normal_alerts.json`, and both logs
(`normal.log`, `attack.log`) with the start/end times you noted. With those I can:

1. Measure Kavalan's real detection rate and false-positive rate.
2. Retrain the model using your real `normal.log` as benign data.
3. Use the agent's real request sequence to build the prediction module.

---

## Shut down

```bash
docker compose down
```

This stops and removes the containers. Your logs stay in `logs/`.
