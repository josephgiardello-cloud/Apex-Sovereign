"""Offline-first launcher for Apex Sovereign.

This starts the existing FastAPI app with local defaults that work against an
OpenAI-compatible local model server such as Ollama.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict

import uvicorn


def _load_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.exists():
        return values

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
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


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Apex Sovereign in offline-first local mode")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("--port", type=int, default=8000, help="Bind port")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    parser.add_argument(
        "--env-file",
        default=str(Path(__file__).with_name(".env.offline")),
        help="Optional env file with KEY=VALUE lines",
    )
    parser.add_argument(
        "--verify-chimera",
        action="store_true",
        help="Run Chimera contract verification before startup",
    )
    return parser.parse_args()


def _run_chimera_verification() -> int:
    cmd = [sys.executable, "verify_chimera.py"]
    return subprocess.run(cmd, cwd=Path(__file__).parent).returncode


def main() -> int:
    args = _parse_args()

    env_path = Path(args.env_file)
    for key, value in _load_env_file(env_path).items():
        os.environ.setdefault(key, value)

    _apply_local_defaults()

    if args.verify_chimera:
        verify_rc = _run_chimera_verification()
        if verify_rc != 0:
            print("Chimera verification failed. Fix contract/test failures before startup.")
            return verify_rc

    # Import after env is ready so config.py captures the intended local values.
    import BaseT8  # noqa: F401

    uvicorn.run("BaseT8:app", host=args.host, port=args.port, reload=args.reload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
