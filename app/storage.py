from __future__ import annotations

import io
import json
from pathlib import Path
from minio import Minio
from minio.error import S3Error

from app.core.config import get_settings

settings = get_settings()


class ArtifactStore:
    def __init__(self) -> None:
        self.bucket = settings.minio_bucket
        self.client = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure,
        )
        self.local_dir = Path("/tmp/artifacts")
        self.local_dir.mkdir(parents=True, exist_ok=True)

    def ensure_bucket(self) -> None:
        try:
            if not self.client.bucket_exists(self.bucket):
                self.client.make_bucket(self.bucket)
        except (S3Error, Exception):
            pass

    def upload_bytes(self, object_name: str, payload: bytes, content_type: str) -> str:
        self.ensure_bucket()
        try:
            data = io.BytesIO(payload)
            self.client.put_object(
                bucket_name=self.bucket,
                object_name=object_name,
                data=data,
                length=len(payload),
                content_type=content_type,
            )
            return f"s3://{self.bucket}/{object_name}"
        except Exception:
            local_path = self.local_dir / object_name.replace("/", "_")
            local_path.write_bytes(payload)
            return str(local_path)

    def upload_json(self, object_name: str, content: dict) -> str:
        return self.upload_bytes(
            object_name=object_name,
            payload=json.dumps(content, ensure_ascii=False).encode("utf-8"),
            content_type="application/json",
        )

    def read_bytes(self, uri: str) -> bytes | None:
        if not uri:
            return None
        if uri.startswith("s3://"):
            try:
                _, rest = uri.split("s3://", 1)
                bucket, object_name = rest.split("/", 1)
                resp = self.client.get_object(bucket, object_name)
                return resp.read()
            except Exception:
                return None
        path = Path(uri)
        if path.exists():
            return path.read_bytes()
        return None
