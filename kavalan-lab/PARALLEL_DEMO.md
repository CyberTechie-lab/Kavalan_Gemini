# Kavalan parallel demo: normal + human attacker + AI agent

Run three kinds of traffic against Juice Shop at once and watch Kavalan's SIEM
dashboard tell them apart in real time.

## 1. Start the lab and the SIEM monitor
```
cd ~/Downloads/kavalan-lab
docker compose up -d                 # juice-shop + nginx

cd ~/Downloads/kavalan-ml
python3 kavalan_monitor.py --log ~/Downloads/kavalan-lab/logs/access.log --window 30
# open http://127.0.0.1:8900  (add --model model/tactic_model.joblib if scikit-learn is installed)
```

## 2. Start the two built-in sources (normal users + human attacker)
In another terminal:
```
cd ~/Downloads/kavalan-lab
docker compose --profile traffic up -d normal-users human-attacker
```
These run inside the lab network, so each gets its own source IP.

## 3. Launch the AI agent
In another terminal (same Strix setup as before):
```
cd ~/Downloads/kavalan-lab
export STRIX_LLM="openai/gemma4:31b-cloud"
export LLM_API_BASE="http://localhost:11434/v1"
export LLM_API_KEY="ollama"
strix -n --target http://host.docker.internal:8080
```

## What to watch on the dashboard
The Sources table should separate them by behaviour:
- **normal-users** -> OK (green): low rate, no protected hits
- **human-attacker** -> OK/MEDIUM: slow, a few probes, hand-paced
- **AI agent** (gateway IP) -> HIGH: machine speed, huge breadth, protected hits

That contrast is the whole thesis: Kavalan flags the autonomous agent while leaving
normal users and even a slow human attacker alone.

## Reset between runs
```
docker compose --profile traffic down          # stop the traffic sources
: > logs/access.log                             # clear the log
```
