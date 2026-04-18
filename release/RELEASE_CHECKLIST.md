# Release Checklist

## Versioning

- [ ] Decide version (`vMAJOR.MINOR.PATCH`)
- [ ] Create and push git tag
- [ ] Update image tag and changelog

## Security

- [ ] Set `GOVERNANCE_API_KEY`
- [ ] Confirm no secrets in repo or image layers
- [ ] Confirm production `.env` is managed outside repo

## Functional Checks

- [ ] `GET /health` returns `{"status":"ok"}`
- [ ] `POST /analyze` sync test passes
- [ ] `POST /analyze` async test passes (worker + redis)
- [ ] `POST /analyze/batch` test passes
- [ ] `scripts/run_async_e2e_suite.sh` passes
- [ ] Artifact upload works (MinIO or local fallback)

## Isolation Checks

- [ ] Worker isolation mode validated (`docker_task` or `local`)
- [ ] Download blocking and form-submit blocking verified
- [ ] Per-task timeout enforced (30s)

## Data and Persistence

- [ ] PostgreSQL persistence verified
- [ ] MinIO bucket initialized and writable
- [ ] Backup/restore plan documented

## Ops

- [ ] Logs and metrics collection configured
- [ ] Alerting for API/worker failure configured
- [ ] Restart and rollback procedure validated

## Release Package

- [ ] Build image and push to registry
- [ ] Generate compose bundle archive
- [ ] Attach `DEPLOYMENT.md` and this checklist
- [ ] Publish release notes with known limitations
