# Kavalan: request-tactic model

A machine-learning classifier that labels each request parameter as one of
`benign, sqli, xss, cmdi, traversal, ssrf`, plugged into Kavalan's detector as a
second opinion after the hand-written rules.

## Files

| File | What it does |
|---|---|
| `build_dataset.py` | Assembles the training set from the public sources below into `data/dataset.csv` |
| `train.py` | Trains the model, runs four evaluations, saves `model/tactic_model.joblib` and `model/report.txt` |
| `detector.py` | Kavalan's detector, now with an optional `--model` flag |
| `simulate.py` | Traffic simulator, now with an XSS tactic in the agent campaign |

## Run it

Needs Python 3.8+, `pip install scikit-learn pandas joblib`.

```
# 1. download the data into data/ (once)
mkdir -p data && cd data
B=https://raw.githubusercontent.com
curl -sO $B/Morzeux/HttpParamsDataset/master/payload_full.csv
curl -sO $B/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt
curl -sO $B/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt
curl -sO $B/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt
curl -s -o ssrf_README.md "$B/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/README.md"
cd ..

# 2. build and train (about a minute)
python3 build_dataset.py
python3 train.py

# 3. use it
python3 simulate.py
python3 detector.py access.log --truth truth.json --model model/tactic_model.joblib
```

## Data sources

- **HttpParamsDataset** (Morzeux): 31k parameter values. Benign values from the CSIC 2010
  dataset, SQLi from sqlmap, plus XSS, command injection and traversal from scanners and FuzzDB.
- **SecLists** (Daniel Miessler): XSS-Jhaddix, LFI-Jhaddix, command-injection-commix.
- **PayloadsAllTheThings** (swisskyrepo): SSRF target URLs.
- **Generated in build_dataset.py**: SSRF variants from standard internal targets, and benign
  external URLs so the model does not learn "any URL is SSRF". These rows are marked `generated`.

## Results (from model/report.txt)

| Test | Accuracy | Notes |
|---|---|---|
| A. Random 20% hold-out | 99.9% | Flattering: test payloads come from the same tools as training |
| B. Model alone, unseen sources | 75.6% | Command injection recall only 9%: the 89 training examples looked nothing like commix payloads |
| C. Old regex rules alone, same set | 96.3% | Misses every XSS payload and over half of SSRF |
| D. **Rules first, then model** | **99.3%** | Zero false positives on 3,861 real benign values |

Test B is the honest one. It shows a model only recognises attack styles it has seen, which is
why Kavalan uses both layers.

## Known limitations

- **Benign data is narrow.** It comes from one Spanish e-commerce test app (CSIC 2010). Ordinary
  English search text with SQL words is mislabelled: `select a plan` and `1 or 2 tickets` come
  back as `sqli`. Real query logs from your own servers are the fix.
- **Payload tactic is not agent detection.** These datasets are from human-run tools. The model
  improves Kavalan's tactic labels, which feed the diversity, switching and campaign signals;
  it does not by itself tell an agent from a human.
- **Parameter values only.** Payloads in the path, headers or POST bodies are not scored yet.

## Standalone monitor

`kavalan_monitor.py` turns the detector into a self-contained monitoring tool, the
shape defence asked for: one process that watches a log live, detects, and shows
alerts on its own dashboard. No cloud, no external SIEM, no agent framework.
Standard library plus the optional model; footprint well under 1 GB.

```
python3 kavalan_monitor.py --log /var/log/nginx/access.log --model model/tactic_model.joblib
# then open http://127.0.0.1:8900
```

What it does each cycle:
- follows the access log like `tail -f` (handles rotation and truncation),
- keeps a rolling time window (default 15 min) of requests,
- runs the rules + model + campaign correlation over the window,
- stores alerts in a local SQLite file (`kavalan.db`),
- serves a live, auto-refreshing dashboard on `127.0.0.1` only.

Options: `--window` minutes, `--interval` seconds between scans, `--host`/`--port`
for the dashboard (keep it on localhost), `--db` path. Run without `--model` for
rules-only, no scikit-learn needed.

The dashboard shows the one campaign alert front and centre, collapses its members
into a single line instead of flooding the screen, and lists only genuinely separate
sources below. It is monitoring only: it raises alerts, it never acts on the system.
