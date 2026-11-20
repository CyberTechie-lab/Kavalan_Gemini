#!/usr/bin/env python3
"""
train.py - trains and evaluates Kavalan's request-tactic classifier.

Model: character n-gram TF-IDF -> logistic regression (class-balanced).
Attack strings are mostly about characters and short fragments (' or 1=1, ../, <script),
so character n-grams work well and the model stays small, fast and explainable.

Three evaluations:
  A. In-distribution     random 80/20 split of the whole dataset
  B. Cross-source        trained WITHOUT SecLists and PayloadsAllTheThings, tested on them.
                         This is the honest test: payloads from tools the model never saw.
  C. Baseline            Kavalan's current hand-written regex rules on the same test set as B

Saves the final model (trained on everything) to model/tactic_model.joblib and
writes results to model/report.txt
"""
import re
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline

ROOT = Path(__file__).parent
LABELS = ["benign", "sqli", "xss", "cmdi", "traversal", "ssrf"]
OUT = ROOT / "model"
OUT.mkdir(exist_ok=True)
report = []


def log(s=""):
    print(s)
    report.append(s)


def make_model():
    return make_pipeline(
        TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, max_features=200_000,
                        sublinear_tf=True, lowercase=True),
        LogisticRegression(max_iter=3000, C=8.0, class_weight="balanced"),
    )


def show(title, y_true, y_pred):
    log("=" * 72)
    log(title)
    log("=" * 72)
    labels = [l for l in LABELS if l in set(y_true) | set(y_pred)]
    log(classification_report(y_true, y_pred, labels=labels, digits=3, zero_division=0))
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    log("confusion matrix (rows = true, columns = predicted)")
    log(" " * 11 + "".join(f"{l[:9]:>10}" for l in labels))
    for l, row in zip(labels, cm):
        log(f"{l:<11}" + "".join(f"{n:>10}" for n in row))
    log()


# ---------------------------------------------------------------- regex baseline
# The payload-level rules from detector.py, applied to the value as if it were a query parameter.
SSRF_RE = re.compile(r"=(https?://(169\.254\.169\.254|localhost|127\.0\.0\.1|metadata\.)|file://|gopher://)")
TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|\.\.\.\.//|/etc/passwd|/etc/hosts)")
SQLI_RE = re.compile(r"(union\s+select|'\s*or\s*'|'\s*and\s|sleep\(|;\s*--|information_schema)")
CMDI_RE = re.compile(r"(;\s*(id|ls|cat|whoami)\b|\|\s*(id|ls|cat|whoami)\b|\$\(|`)")


def regex_label(p):
    url = "/x?v=" + p
    if SSRF_RE.search(url):
        return "ssrf"
    if TRAVERSAL_RE.search(url):
        return "traversal"
    if SQLI_RE.search(url):
        return "sqli"
    if CMDI_RE.search(url):
        return "cmdi"
    return "benign"   # the old rules have no XSS check at all


def main():
    df = pd.read_csv(ROOT / "data" / "dataset.csv", keep_default_na=False)
    log(f"Dataset: {len(df):,} payloads")
    log(df.label.value_counts().to_string())
    log()

    # A. random split
    tr, te = train_test_split(df, test_size=0.2, stratify=df.label, random_state=42)
    m = make_model().fit(tr.payload, tr.label)
    show("A. IN-DISTRIBUTION TEST (random 20% hold-out)", te.label, m.predict(te.payload))

    # B. cross-source: hold out every SecLists / PayloadsAllTheThings row,
    #    plus 20% of real benign values so false positives are measured too
    unseen = df.source.isin(["seclists", "payloadsallthethings"])
    benign_real = df[(df.label == "benign") & (df.source == "httpparams")]
    benign_test = benign_real.sample(frac=0.2, random_state=42)
    test_b = pd.concat([df[unseen], benign_test])
    train_b = df[~unseen & ~df.index.isin(benign_test.index)]
    mb = make_model().fit(train_b.payload, train_b.label)
    pred_b = mb.predict(test_b.payload)
    show("B. CROSS-SOURCE TEST (payload sources the model never saw in training)", test_b.label, pred_b)

    # C. regex baseline on the same set
    show("C. BASELINE: Kavalan's current regex rules, same test set as B",
         test_b.label, [regex_label(p) for p in test_b.payload])

    # D. hybrid: trust a regex hit (precise), otherwise use the model (broad)
    hybrid = [r if r != "benign" else m_ for r, m_ in
              zip((regex_label(p) for p in test_b.payload), pred_b)]
    show("D. HYBRID: regex first, model for everything the regex misses, same test set as B",
         test_b.label, hybrid)

    # examples of mistakes from B, for inspection
    wrong = test_b[test_b.label.values != pred_b].assign(pred=pred_b[test_b.label.values != pred_b])
    log(f"B mistakes: {len(wrong)} of {len(test_b)}. Up to 15 examples:")
    for _, r in wrong.head(15).iterrows():
        log(f"  true={r.label:<10} pred={r.pred:<10} {r.payload[:80]!r}")
    log()

    # final model on all data
    final = make_model().fit(df.payload, df.label)
    joblib.dump({"model": final, "labels": LABELS}, OUT / "tactic_model.joblib", compress=3)
    (OUT / "report.txt").write_text("\n".join(report))
    size = (OUT / "tactic_model.joblib").stat().st_size / 1e6
    print(f"Final model trained on all {len(df):,} payloads -> model/tactic_model.joblib ({size:.1f} MB)")


if __name__ == "__main__":
    sys.exit(main())
