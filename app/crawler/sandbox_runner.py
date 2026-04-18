from __future__ import annotations

import json
import shutil
import subprocess
import time

from app.core.config import get_settings
from app.crawler.playwright_crawler import CrawlArtifacts, crawl_url_sync

settings = get_settings()


class SandboxRunner:
    def __init__(self) -> None:
        self.last_execution: dict = {}

    def run(self, url: str, depth: str, task_id: str) -> CrawlArtifacts:
        if settings.isolation_mode == "docker_task":
            return self._run_with_resilience(url, depth, task_id)
        timeout_seconds = self._timeout_for_depth(depth)
        artifacts = crawl_url_sync(url, depth, task_id, timeout_seconds=timeout_seconds)
        self.last_execution = {
            "mode": "local",
            "fallback_used": False,
            "attempts": 1,
            "effective_timeout_seconds": timeout_seconds,
        }
        return artifacts

    def _timeout_for_depth(self, depth: str) -> int:
        mapping = {
            "quick": settings.crawl_timeout_quick_seconds,
            "standard": settings.crawl_timeout_standard_seconds,
            "deep": settings.crawl_timeout_deep_seconds,
        }
        timeout_seconds = int(mapping.get(depth, settings.crawl_timeout_seconds))
        return max(5, timeout_seconds)

    @staticmethod
    def _is_timeout_error(exc: Exception) -> bool:
        text = str(exc).lower()
        if "timed out" in text or "timeout" in text:
            return True
        return isinstance(exc, subprocess.TimeoutExpired)

    def _run_with_resilience(self, url: str, depth: str, task_id: str) -> CrawlArtifacts:
        base_timeout = self._timeout_for_depth(depth)
        attempts = max(1, int(settings.sandbox_timeout_retries) + 1)
        multiplier = max(1.0, float(settings.sandbox_retry_timeout_multiplier))
        errors: list[str] = []
        last_exc: Exception | None = None

        for idx in range(attempts):
            timeout_seconds = max(5, int(round(base_timeout * (multiplier**idx))))
            try:
                artifacts = self._run_docker_task(url, depth, task_id, timeout_seconds=timeout_seconds)
                self.last_execution = {
                    "mode": "docker_task",
                    "fallback_used": False,
                    "attempts": idx + 1,
                    "effective_timeout_seconds": timeout_seconds,
                    "errors": errors,
                }
                return artifacts
            except Exception as exc:
                last_exc = exc
                errors.append(f"attempt_{idx + 1}:{exc}")
                if not self._is_timeout_error(exc):
                    break

        if (
            settings.sandbox_fallback_to_local_on_timeout
            and last_exc is not None
            and self._is_timeout_error(last_exc)
        ):
            fallback_timeout = max(
                5,
                int(settings.sandbox_fallback_timeout_seconds),
                int(round(base_timeout * (multiplier ** max(0, attempts - 1)))),
            )
            artifacts = crawl_url_sync(url, depth, task_id, timeout_seconds=fallback_timeout)
            self.last_execution = {
                "mode": "local_fallback",
                "fallback_used": True,
                "attempts": attempts,
                "effective_timeout_seconds": fallback_timeout,
                "errors": errors,
            }
            return artifacts

        if last_exc is None:
            raise RuntimeError("sandbox run failed without error details")
        raise last_exc

    def _run_docker_task(self, url: str, depth: str, task_id: str, timeout_seconds: int) -> CrawlArtifacts:
        if shutil.which("docker"):
            return self._run_docker_task_cli(url, depth, task_id, timeout_seconds)
        return self._run_docker_task_sdk(url, depth, task_id, timeout_seconds)

    def _run_docker_task_cli(self, url: str, depth: str, task_id: str, timeout_seconds: int) -> CrawlArtifacts:
        cmd = [
            "docker",
            "run",
            "--rm",
            "--network",
            settings.sandbox_network,
            "--cpus",
            str(settings.sandbox_cpu_limit),
            "--memory",
            settings.sandbox_memory_limit,
            "--pids-limit",
            str(settings.sandbox_pids_limit),
            "--security-opt",
            "no-new-privileges:true",
            "--cap-drop",
            "ALL",
            "-e",
            f"MINIO_ENDPOINT={settings.minio_endpoint}",
            "-e",
            f"MINIO_ACCESS_KEY={settings.minio_access_key}",
            "-e",
            f"MINIO_SECRET_KEY={settings.minio_secret_key}",
            "-e",
            f"MINIO_SECURE={str(settings.minio_secure).lower()}",
            "-e",
            f"MINIO_BUCKET={settings.minio_bucket}",
            "-e",
            f"CRAWL_TIMEOUT_SECONDS={timeout_seconds}",
            settings.sandbox_image,
            "python",
            "-m",
            "app.crawler.cli",
            "--url",
            url,
            "--depth",
            depth,
            "--task-id",
            task_id,
        ]

        try:
            proc = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 20,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("docker sandbox timed out") from exc

        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        if not lines:
            raise RuntimeError("docker sandbox produced empty output")

        payload = json.loads(lines[-1])
        return CrawlArtifacts.from_dict(payload)

    def _run_docker_task_sdk(self, url: str, depth: str, task_id: str, timeout_seconds: int) -> CrawlArtifacts:
        try:
            import docker
            from docker.errors import DockerException
        except Exception as exc:
            raise RuntimeError("docker CLI not found and docker SDK unavailable") from exc

        client = docker.from_env()
        container = None
        deadline = time.time() + timeout_seconds + 20
        envs = {
            "MINIO_ENDPOINT": settings.minio_endpoint,
            "MINIO_ACCESS_KEY": settings.minio_access_key,
            "MINIO_SECRET_KEY": settings.minio_secret_key,
            "MINIO_SECURE": str(settings.minio_secure).lower(),
            "MINIO_BUCKET": settings.minio_bucket,
            "CRAWL_TIMEOUT_SECONDS": str(timeout_seconds),
        }
        command = [
            "python",
            "-m",
            "app.crawler.cli",
            "--url",
            url,
            "--depth",
            depth,
            "--task-id",
            task_id,
        ]

        try:
            container = client.containers.run(
                image=settings.sandbox_image,
                command=command,
                environment=envs,
                network=settings.sandbox_network,
                detach=True,
                remove=False,
                security_opt=["no-new-privileges:true"],
                cap_drop=["ALL"],
                mem_limit=settings.sandbox_memory_limit,
                nano_cpus=int(settings.sandbox_cpu_limit * 1_000_000_000),
                pids_limit=settings.sandbox_pids_limit,
            )

            while time.time() < deadline:
                container.reload()
                if container.status in {"exited", "dead"}:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("docker sandbox timed out")

            result = container.wait(timeout=5)
            status_code = int(result.get("StatusCode", 1))
            logs = container.logs(stdout=True, stderr=False).decode("utf-8", errors="ignore")
            if status_code != 0:
                raise RuntimeError(f"docker sandbox exit code: {status_code}")
            lines = [line for line in logs.splitlines() if line.strip()]
            if not lines:
                raise RuntimeError("docker sandbox produced empty output")
            payload = json.loads(lines[-1])
            return CrawlArtifacts.from_dict(payload)
        except DockerException as exc:
            raise RuntimeError(f"docker SDK error: {exc}") from exc
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
