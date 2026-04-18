from __future__ import annotations

import argparse
import csv
from pathlib import Path

from app.db import SessionLocal
from app.models import FeedbackRecord


def main() -> None:
    parser = argparse.ArgumentParser(description="Export feedback records to CSV")
    parser.add_argument("--output", default="/tmp/feedback_export.csv")
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    db = SessionLocal()
    try:
        rows = db.query(FeedbackRecord).order_by(FeedbackRecord.created_at.asc()).all()
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "feedback_id",
                    "task_id",
                    "url",
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
            for row in rows:
                writer.writerow(
                    {
                        "feedback_id": row.feedback_id,
                        "task_id": row.task_id,
                        "url": row.url,
                        "predicted_label": row.predicted_label,
                        "human_label": row.human_label,
                        "is_false_positive": row.is_false_positive,
                        "note": row.note,
                        "reviewer": row.reviewer,
                        "created_at": row.created_at.isoformat() if row.created_at else "",
                        "features_json": row.features_json,
                    }
                )
        print(f"exported {len(rows)} rows to {output_path}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
