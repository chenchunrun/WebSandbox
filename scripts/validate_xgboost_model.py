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


def to_float(v: str | float | int | None) -> float:
    if v is None:
        return 0.0
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def compute_metrics(y_true: list[int], y_pred: list[int]) -> dict:
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate trained XGBoost model on dataset")
    parser.add_argument("--model", default="/tmp/xgb_model.joblib")
    parser.add_argument("--input", default="/tmp/training_dataset.csv")
    parser.add_argument("--output", default="/tmp/xgb_validation.json")
    args = parser.parse_args()

    model_path = Path(args.model)
    if not model_path.exists():
        raise FileNotFoundError(f"model not found: {model_path}")

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"dataset not found: {input_path}")

    model = joblib.load(model_path)

    X = []
    y = []
    with input_path.open("r", encoding="utf-8") as f:
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
            X.append([to_float(row.get(col)) for col in FEATURE_COLUMNS])

    if not X:
        raise RuntimeError("empty dataset")

    y_pred = [int(v) for v in model.predict(X)]
    metrics = compute_metrics(y, y_pred)
    metrics.update(
        {
            "feature_columns": FEATURE_COLUMNS,
            "model": str(model_path),
            "dataset": str(input_path),
        }
    )

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"validation saved: {out}")
    print(json.dumps(metrics, ensure_ascii=False))


if __name__ == "__main__":
    main()
