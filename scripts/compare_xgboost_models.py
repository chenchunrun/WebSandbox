from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import joblib


FEATURE_COLUMNS = [
    "is_new_domain",
    "self_signed_cert",
    "brand_domain_mismatch",
    "js_obfuscation_hits",
    "hidden_iframe_count",
    "cross_domain_form_submit",
    "keyword_hit_count",
    "high_risk_xhr_count",
]


def to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def load_dataset(path: Path) -> tuple[list[list[float]], list[int]]:
    X: list[list[float]] = []
    y: list[int] = []
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            target = row.get("target_label")
            if target is None:
                continue
            try:
                target_int = int(float(target))
            except (TypeError, ValueError):
                continue
            y.append(0 if target_int == 0 else 1)
            X.append([to_float(row.get(c)) for c in FEATURE_COLUMNS])
    return X, y


def metrics(y_true: list[int], y_pred: list[int]) -> dict:
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    total = len(y_true)
    acc = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "accuracy": round(acc, 6),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "count": total,
    }


def evaluate(model_path: Path, X: list[list[float]], y: list[int]) -> dict:
    model = joblib.load(model_path)
    pred = [int(v) for v in model.predict(X)]
    out = metrics(y, pred)
    out["model"] = str(model_path)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare baseline vs challenger XGBoost models")
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--challenger", required=True)
    parser.add_argument("--input", default="/tmp/training_dataset.csv")
    parser.add_argument("--output", default="/tmp/xgb_compare.json")
    args = parser.parse_args()

    baseline = Path(args.baseline)
    challenger = Path(args.challenger)
    dataset = Path(args.input)
    if not baseline.exists():
        raise FileNotFoundError(f"baseline not found: {baseline}")
    if not challenger.exists():
        raise FileNotFoundError(f"challenger not found: {challenger}")
    if not dataset.exists():
        raise FileNotFoundError(f"dataset not found: {dataset}")

    X, y = load_dataset(dataset)
    if not X:
        raise RuntimeError("empty dataset")

    base_metrics = evaluate(baseline, X, y)
    chal_metrics = evaluate(challenger, X, y)

    delta = {
        "accuracy": round(chal_metrics["accuracy"] - base_metrics["accuracy"], 6),
        "precision": round(chal_metrics["precision"] - base_metrics["precision"], 6),
        "recall": round(chal_metrics["recall"] - base_metrics["recall"], 6),
        "f1": round(chal_metrics["f1"] - base_metrics["f1"], 6),
    }

    result = {
        "dataset": str(dataset),
        "feature_columns": FEATURE_COLUMNS,
        "baseline": base_metrics,
        "challenger": chal_metrics,
        "delta": delta,
        "recommendation": "promote" if delta["f1"] > 0 and delta["recall"] >= 0 else "hold",
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"comparison saved: {out}")
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
