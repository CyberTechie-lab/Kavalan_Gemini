# Kavalan CI/CD

GitHub Actions pipeline in `.github/workflows/ci.yml`:

- **test** (every push and PR): lint, then the detection-quality gate in
  `tests/test_detection.py`. These assert the invariants that matter:
  the agent campaign is detected, humans and a benign crawler are never flagged,
  the scanner is flagged, and a lone aggressive agent scores HIGH. Rules-only,
  no dataset download, fully deterministic.
- **model** (on main / manual): fetches the public corpora, rebuilds the dataset
  and retrains the tactic model, and uploads it as a build artifact.
- **release** (on a `v*` tag): zips the standalone offline bundle
  (detector, monitor, dashboard, model) and attaches it to the GitHub Release.

## To use it
1. Put the Kavalan code in a GitHub repo (detector.py, kavalan_monitor.py,
   dashboard.html, build_dataset.py, train.py, simulate.py, this folder's files).
2. Push to `main`. The test job runs automatically.
3. Tag a release: `git tag v0.1.0 && git push --tags` to build the bundle.

Run the gate locally any time: `pip install -r requirements.txt pytest && pytest -q`
