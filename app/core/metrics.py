from __future__ import annotations

from collections import defaultdict
from threading import Lock
from typing import Any


def _labels_key(labels: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((str(k), str(v)) for k, v in labels.items()))


class MetricsRegistry:
    def __init__(self) -> None:
        self._counter: defaultdict[tuple[str, tuple[tuple[str, str], ...]], int] = defaultdict(int)
        self._hist: defaultdict[tuple[str, tuple[tuple[str, str], ...]], dict[str, float]] = defaultdict(
            lambda: {"count": 0.0, "sum": 0.0, "min": float("inf"), "max": float("-inf")}
        )
        self._lock = Lock()

    def incr(self, name: str, value: int = 1, **labels: Any) -> None:
        key = (name, _labels_key(labels))
        with self._lock:
            self._counter[key] += int(value)

    def observe(self, name: str, value: float, **labels: Any) -> None:
        key = (name, _labels_key(labels))
        with self._lock:
            item = self._hist[key]
            v = float(value)
            item["count"] += 1.0
            item["sum"] += v
            if v < item["min"]:
                item["min"] = v
            if v > item["max"]:
                item["max"] = v

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            counters = []
            for (name, labels), value in self._counter.items():
                counters.append({"name": name, "labels": dict(labels), "value": value})

            histograms = []
            for (name, labels), item in self._hist.items():
                count = int(item["count"])
                avg = (item["sum"] / item["count"]) if item["count"] else 0.0
                histograms.append(
                    {
                        "name": name,
                        "labels": dict(labels),
                        "count": count,
                        "sum": round(item["sum"], 3),
                        "avg": round(avg, 3),
                        "min": round(item["min"], 3) if count else None,
                        "max": round(item["max"], 3) if count else None,
                    }
                )

        counters.sort(key=lambda x: (x["name"], sorted(x["labels"].items())))
        histograms.sort(key=lambda x: (x["name"], sorted(x["labels"].items())))
        return {"counters": counters, "histograms": histograms}


metrics_registry = MetricsRegistry()
