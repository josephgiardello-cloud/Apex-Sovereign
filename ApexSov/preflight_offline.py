"""Offline preflight checks for Apex Sovereign local mode.

Checks local dependencies and optional Apex endpoints with actionable output.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import requests
from redis import Redis


@dataclass
class CheckResult:
    name: str
    ok: bool
    details: str


def _load_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.exists():
        return values

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        k = key.strip()
        v = value.strip().strip('"').strip("'")
        if k:
            values[k] = v
    return values


def _apply_local_defaults() -> None:
    os.environ.setdefault("APEX_ENV", "dev")
    os.environ.setdefault("APEX_REDIS_URL", "redis://127.0.0.1:6379/0")
    os.environ.setdefault("APEX_OPENAI_URL", "http://127.0.0.1:11434/v1/chat/completions")
    os.environ.setdefault("APEX_DRIFT_BACKEND", "redis")
    os.environ.setdefault("APEX_NO_INTERNET", "true")
    os.environ.setdefault("OPENAI_API_KEY", "")


def _derive_openai_base_url(chat_url: str) -> str:
    parsed = urlparse((chat_url or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return ""

    path = (parsed.path or "").rstrip("/")
    for suffix in ("/chat/completions", "/v1/chat/completions"):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break
    if not path:
        path = "/v1"
    return parsed._replace(path=path.rstrip("/"), params="", query="", fragment="").geturl()


def _check_redis(redis_url: str, timeout_seconds: float) -> CheckResult:
    if not redis_url:
        return CheckResult("redis", False, "APEX_REDIS_URL is empty")
    try:
        client = Redis.from_url(redis_url, socket_timeout=timeout_seconds, socket_connect_timeout=timeout_seconds)
        client.ping()
        return CheckResult("redis", True, f"Connected to {redis_url}")
    except Exception as exc:
        return CheckResult(
            "redis",
            False,
            f"Cannot connect to {redis_url}: {exc}. Start Redis or fix APEX_REDIS_URL.",
        )


def _check_local_model(chat_url: str, timeout_seconds: float) -> CheckResult:
    base = _derive_openai_base_url(chat_url)
    if not base:
        return CheckResult("model-server", False, "APEX_OPENAI_URL is invalid")

    # Prefer OpenAI-compatible models route.
    try:
        resp = requests.get(base + "/models", timeout=timeout_seconds)
        if resp.status_code == 200:
            return CheckResult("model-server", True, f"OpenAI-compatible endpoint reachable at {base}/models")
    except Exception:
        pass

    # Ollama native fallback.
    try:
        parsed = urlparse(base)
        ollama_base = f"{parsed.scheme}://{parsed.netloc}"
        resp = requests.get(ollama_base + "/api/tags", timeout=timeout_seconds)
        if resp.status_code == 200:
            return CheckResult("model-server", True, f"Ollama endpoint reachable at {ollama_base}/api/tags")
    except Exception:
        pass

    return CheckResult(
        "model-server",
        False,
        f"Cannot reach model server from APEX_OPENAI_URL={chat_url}. Start Ollama/LM Studio or fix URL.",
    )


def _check_apex_endpoint(base_url: str, path: str, timeout_seconds: float) -> CheckResult:
    url = base_url.rstrip("/") + path
    try:
        resp = requests.get(url, timeout=timeout_seconds)
        if resp.status_code == 200:
            return CheckResult(path, True, f"200 from {url}")
        return CheckResult(path, False, f"{resp.status_code} from {url}: {resp.text[:200]}")
    except Exception as exc:
        return CheckResult(path, False, f"Cannot reach {url}: {exc}")


def _run_checks(check_apex: bool, apex_base_url: str, timeout_seconds: float) -> List[CheckResult]:
    redis_url = os.getenv("APEX_REDIS_URL", "")
    openai_url = os.getenv("APEX_OPENAI_URL", "")

    results = [
        _check_redis(redis_url, timeout_seconds),
        _check_local_model(openai_url, timeout_seconds),
    ]

    if check_apex:
        results.extend(
            [
                _check_apex_endpoint(apex_base_url, "/healthz", timeout_seconds),
                _check_apex_endpoint(apex_base_url, "/readyz", timeout_seconds),
                _check_apex_endpoint(apex_base_url, "/governance_status", timeout_seconds),
            ]
        )

    return results


def _print_results(results: List[CheckResult]) -> Tuple[int, int]:
    passed = sum(1 for r in results if r.ok)
    failed = len(results) - passed
    for r in results:
        status = "PASS" if r.ok else "FAIL"
        print(f"[{status}] {r.name}: {r.details}")
    return passed, failed


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline preflight checks for Apex Sovereign")
    parser.add_argument(
        "--env-file",
        default=str(Path(__file__).with_name(".env.offline")),
        help="Optional env file with KEY=VALUE lines",
    )
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-request timeout seconds")
    parser.add_argument("--check-apex", action="store_true", help="Also validate local Apex endpoints")
    parser.add_argument("--apex-url", default="http://127.0.0.1:8000", help="Base URL for Apex endpoint checks")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    for key, value in _load_env_file(Path(args.env_file)).items():
        os.environ.setdefault(key, value)
    _apply_local_defaults()

    results = _run_checks(args.check_apex, args.apex_url, args.timeout)
    passed, failed = _print_results(results)

    print(f"Summary: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
