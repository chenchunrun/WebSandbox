from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import threading
import time
from typing import Any

import joblib

from app.core.config import get_settings

settings = get_settings()


@dataclass
class ModelStatus:
    path: str
    exists: bool
    loaded: bool
    last_loaded_ts: float | None
    mtime: float | None
    error: str | None = None


class XGBoostModelRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._model: Any = None
        self._path = Path(settings.xgboost_model_path)
        self._last_mtime: float | None = None
        self._last_loaded_ts: float | None = None
        self._last_error: str | None = None

    def get_model(self) -> Any:
        with self._lock:
            if not self._path.exists():
                self._model = None
                self._last_mtime = None
                self._last_error = "model file not found"
                return None

            current_mtime = self._path.stat().st_mtime
            if self._model is None or self._last_mtime != current_mtime:
                try:
                    self._model = joblib.load(self._path)
                    self._last_mtime = current_mtime
                    self._last_loaded_ts = time.time()
                    self._last_error = None
                except Exception as exc:
                    self._model = None
                    self._last_error = str(exc)
            return self._model

    def force_reload(self) -> ModelStatus:
        with self._lock:
            if not self._path.exists():
                self._model = None
                self._last_mtime = None
                self._last_error = "model file not found"
                return self.status()
            try:
                self._model = joblib.load(self._path)
                self._last_mtime = self._path.stat().st_mtime
                self._last_loaded_ts = time.time()
                self._last_error = None
            except Exception as exc:
                self._model = None
                self._last_error = str(exc)
            return self.status()

    def status(self) -> ModelStatus:
        exists = self._path.exists()
        mtime = self._path.stat().st_mtime if exists else None
        return ModelStatus(
            path=str(self._path),
            exists=exists,
            loaded=self._model is not None,
            last_loaded_ts=self._last_loaded_ts,
            mtime=mtime,
            error=self._last_error,
        )


registry = XGBoostModelRegistry()
