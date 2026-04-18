from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path

import joblib
from xgboost import XGBClassifier


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
            binary_label = 0 if target_int == 0 else 1
            feats = [to_float(row.get(col)) for col in FEATURE_COLUMNS]
            X.append(feats)
            y.append(binary_label)

    return X, y


def split_dataset(X: list[list[float]], y: list[int], test_ratio: float, seed: int) -> tuple[list, list, list, list]:
    idx = list(range(len(X)))
    rnd = random.Random(seed)
    rnd.shuffle(idx)

    test_size = max(1, int(len(idx) * test_ratio))
    if len(idx) - test_size < 1:
        test_size = max(0, len(idx) - 1)

    test_idx = idx[:test_size]
    train_idx = idx[test_size:]

    X_train = [X[i] for i in train_idx]
    y_train = [y[i] for i in train_idx]
    X_test = [X[i] for i in test_idx]
    y_test = [y[i] for i in test_idx]
    return X_train, y_train, X_test, y_test


def compute_metrics(y_true: list[int], y_pred: list[int]) -> dict:
    if not y_true:
        return {
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "tp": 0,
            "tn": 0,
            "fp": 0,
            "fn": 0,
        }

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
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train binary XGBoost model for malicious-site prescreen")
    parser.add_argument("--input", default="/tmp/training_dataset.csv")
    parser.add_argument("--model-out", default="/tmp/xgb_model.joblib")
    parser.add_argument("--metrics-out", default="/tmp/xgb_metrics.json")
    parser.add_argument("--test-ratio", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-estimators", type=int, default=300)
    parser.add_argument("--max-depth", type=int, default=5)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument("--subsample", type=float, default=0.9)
    parser.add_argument("--colsample-bytree", type=float, default=0.9)
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"training dataset not found: {input_path}")

    X, y = load_dataset(input_path)
    if len(X) < 10:
        raise RuntimeError("not enough samples to train (need at least 10)")
    if len(set(y)) < 2:
        raise RuntimeError("dataset must include both benign and malicious labels")

    X_train, y_train, X_test, y_test = split_dataset(X, y, test_ratio=args.test_ratio, seed=args.seed)
    if not X_train or not X_test:
        raise RuntimeError("train/test split failed; check dataset size or test_ratio")

    model = XGBClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
        subsample=args.subsample,
        colsample_bytree=args.colsample_bytree,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=args.seed,
        n_jobs=4,
    )
    model.fit(X_train, y_train)

    y_pred = [int(v) for v in model.predict(X_test)]
    metrics = compute_metrics(y_test, y_pred)
    metrics.update(
        {
            "train_size": len(X_train),
            "test_size": len(X_test),
            "feature_columns": FEATURE_COLUMNS,
            "label_mapping": {"benign": 0, "malicious": 1},
            "input_dataset": str(input_path),
        }
    )

    model_out = Path(args.model_out)
    model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_out)

    metrics_out = Path(args.metrics_out)
    metrics_out.parent.mkdir(parents=True, exist_ok=True)
    metrics_out.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"model saved: {model_out}")
    print(f"metrics saved: {metrics_out}")
    print(json.dumps(metrics, ensure_ascii=False))


if __name__ == "__main__":
    main()
