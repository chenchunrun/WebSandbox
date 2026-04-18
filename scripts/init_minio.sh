#!/bin/sh
set -e

/usr/bin/mc alias set local http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"
/usr/bin/mc mb -p local/sandbox-artifacts || true
/usr/bin/mc anonymous set private local/sandbox-artifacts || true
