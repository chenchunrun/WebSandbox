# Production Deployment Guide

## Release Artifacts

A production release should include:

- `docker-compose.yml`
- `.env.example`
- `Dockerfile`
- `requirements.txt`
- `app/`
- `scripts/init_minio.sh`
- `release/RELEASE_CHECKLIST.md`

## Recommended Packaging Form

1. Source release tag: `vMAJOR.MINOR.PATCH`
2. Application image: `websandbox-api:<version>` and `websandbox-worker:<version>`
3. Compose bundle archive: `websandbox-<version>.tar.gz`

## Build and Publish Image

```bash
docker build -t <registry>/websandbox-api:v1.0.0 .
docker build -t <registry>/websandbox-worker:v1.0.0 .
docker push <registry>/websandbox-api:v1.0.0
docker push <registry>/websandbox-worker:v1.0.0
```

If using a private registry, update compose image references before release.

## Environment Preparation

Create `.env` from `.env.example` and set at least:

- `OPENAI_BASE_URL` (optional if no LLM gray-zone analysis)
- `OPENAI_API_KEY` (optional if no LLM gray-zone analysis)
- `GOVERNANCE_API_KEY` (recommended for `/model/*` protection)

## Start Service

```bash
docker compose up -d
```

Health check:

```bash
curl http://localhost:8000/health
```

## Smoke Test

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","depth":"standard","mode":"sync"}'
```

Expected: JSON with `status=done` and `verdict`.

## Upgrade

```bash
docker compose pull
docker compose up -d
```

## Rollback

1. Switch image tag in `docker-compose.yml` to previous stable version.
2. Restart services:

```bash
docker compose up -d
```

## Notes

- `worker` default uses per-task container isolation (`ISOLATION_MODE=docker_task`).
- If Docker socket policy disallows nested container launch, use `ISOLATION_MODE=local` for worker.
