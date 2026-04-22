from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime
from pathlib import Path

from app.core.dataset import dataset_version as build_dataset_version
from app.core.dataset import sample_key as build_sample_key
from app.db import SessionLocal
from app.models import FeedbackRecord


FEATURE_COLUMNS = [
    "is_new_domain",
    "self_signed_cert",
    "brand_domain_mismatch",
    "js_obfuscation_hits",
    "hidden_iframe_count",
    "cross_domain_form_submit",
    "keyword_hit_count",
    "high_risk_xhr_count",
    "domain_age_days",
]

LABEL_MAP = {"benign": 0, "phishing": 1, "malware": 2}


def to_float(v, default: float = 0.0) -> float:
    if v is None:
        return default
    if isinstance(v, bool):
        return float(int(v))
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    return datetime.fromisoformat(ts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build model-ready dataset from feedback records")
    parser.add_argument("--output", default="/tmp/training_dataset.csv")
    parser.add_argument("--from-ts", default=None)
    parser.add_argument("--to-ts", default=None)
    parser.add_argument("--only-false-positive", action="store_true")
    parser.add_argument("--balanced", action="store_true")
    parser.add_argument("--dedup-by-sample", action="store_true", default=True)
    parser.add_argument("--no-dedup-by-sample", dest="dedup_by_sample", action="store_false")
    parser.add_argument("--limit", type=int, default=100000)
    args = parser.parse_args()

    from_dt = parse_iso(args.from_ts)
    to_dt = parse_iso(args.to_ts)

    db = SessionLocal()
    try:
        query = db.query(FeedbackRecord).order_by(FeedbackRecord.created_at.asc())
        if from_dt is not None:
            query = query.filter(FeedbackRecord.created_at >= from_dt)
        if to_dt is not None:
            query = query.filter(FeedbackRecord.created_at <= to_dt)
        if args.only_false_positive:
            query = query.filter(FeedbackRecord.is_false_positive.is_(True))

        rows = query.limit(max(1, args.limit)).all()

        samples = []
        for row in rows:
            if row.human_label not in LABEL_MAP:
                continue
            features = row.features_json or {}
            sample_key = build_sample_key(row.url or "", row.human_label or "unknown", features)
            item = {
                "feedback_id": row.feedback_id,
                "task_id": row.task_id,
                "url": row.url,
                "sample_key": sample_key,
                "label_source": "human_feedback",
                "can_use_for_training": int(bool(row.human_label in LABEL_MAP)),
                "human_label": row.human_label,
                "target_label": LABEL_MAP[row.human_label],
                "created_at": row.created_at.isoformat() if row.created_at else "",
                "is_false_positive": int(bool(row.is_false_positive)),
            }
            for col in FEATURE_COLUMNS:
                item[col] = to_float(features.get(col))
            item["keyword_hits_json"] = json.dumps(features.get("keyword_hits", []), ensure_ascii=False)
            samples.append(item)

        raw_count = len(samples)
        if args.dedup_by_sample:
            deduped = []
            seen = set()
            for sample in samples:
                s_key = sample["sample_key"]
                if s_key in seen:
                    continue
                seen.add(s_key)
                deduped.append(sample)
            samples = deduped

        if args.balanced:
            by_label = {"benign": [], "phishing": [], "malware": []}
            for sample in samples:
                by_label[sample["human_label"]].append(sample)
            non_empty = [v for v in by_label.values() if v]
            if non_empty:
                min_count = min(len(v) for v in non_empty)
                balanced_rows = []
                for label in ("benign", "phishing", "malware"):
                    balanced_rows.extend(by_label[label][:min_count])
                samples = balanced_rows

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        columns = [
            "feedback_id",
            "task_id",
            "url",
            "sample_key",
            "label_source",
            "can_use_for_training",
            "human_label",
            "target_label",
            "created_at",
            "is_false_positive",
            *FEATURE_COLUMNS,
            "keyword_hits_json",
        ]

        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            for sample in samples:
                writer.writerow(sample)

        version = build_dataset_version(
            [s["sample_key"] for s in samples],
            {
                "from_ts": args.from_ts,
                "to_ts": args.to_ts,
                "only_false_positive": args.only_false_positive,
                "balanced": args.balanced,
                "dedup_by_sample": args.dedup_by_sample,
                "limit": args.limit,
            },
        )
        print(
            f"exported {len(samples)} training rows to {output_path} "
            f"(raw_count={raw_count}, dedup_by_sample={args.dedup_by_sample}, dataset_version={version})"
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()
