from __future__ import annotations

import argparse
import csv
from pathlib import Path

from app.core.dataset import dataset_version as build_dataset_version
from app.core.dataset import sample_key as build_sample_key
from app.db import SessionLocal
from app.models import FeedbackRecord


def main() -> None:
    parser = argparse.ArgumentParser(description="Export feedback records to CSV")
    parser.add_argument("--output", default="/tmp/feedback_export.csv")
    parser.add_argument("--dedup-by-sample", action="store_true", default=True)
    parser.add_argument("--no-dedup-by-sample", dest="dedup_by_sample", action="store_false")
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    db = SessionLocal()
    try:
        rows = db.query(FeedbackRecord).order_by(FeedbackRecord.created_at.desc()).all()
        raw_count = len(rows)
        deduped_rows = []
        sample_keys = []
        seen = set()
        for row in rows:
            s_key = build_sample_key(row.url or "", row.human_label or "unknown", row.features_json or {})
            if args.dedup_by_sample and s_key in seen:
                continue
            seen.add(s_key)
            deduped_rows.append((row, s_key))
            sample_keys.append(s_key)
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "feedback_id",
                    "task_id",
                    "url",
                    "sample_key",
                    "label_source",
                    "can_use_for_training",
                    "predicted_label",
                    "human_label",
                    "is_false_positive",
                    "note",
                    "reviewer",
                    "created_at",
                    "features_json",
                ],
            )
            writer.writeheader()
            for row, s_key in deduped_rows:
                writer.writerow(
                    {
                        "feedback_id": row.feedback_id,
                        "task_id": row.task_id,
                        "url": row.url,
                        "sample_key": s_key,
                        "label_source": "human_feedback",
                        "can_use_for_training": bool(row.human_label in {"benign", "phishing", "malware"}),
                        "predicted_label": row.predicted_label,
                        "human_label": row.human_label,
                        "is_false_positive": row.is_false_positive,
                        "note": row.note,
                        "reviewer": row.reviewer,
                        "created_at": row.created_at.isoformat() if row.created_at else "",
                        "features_json": row.features_json,
                    }
                )
        version = build_dataset_version(
            sample_keys,
            {"dedup_by_sample": args.dedup_by_sample, "limit": "all"},
        )
        print(
            f"exported {len(deduped_rows)} rows to {output_path} "
            f"(raw_count={raw_count}, dedup_by_sample={args.dedup_by_sample}, dataset_version={version})"
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()
