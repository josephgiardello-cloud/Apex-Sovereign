"""One-command offline bootstrap for Apex Sovereign.

Runs dependency preflight, starts the local runtime, and fails fast if readiness
checks do not come up in time.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

import requests


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bootstrap Apex Sovereign in offline-first mode")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("--port", type=int, default=8000, help="Bind port")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    parser.add_argument(
        "--env-file",
        default=str(Path(__file__).with_name(".env.offline")),
        help="Optional env file with KEY=VALUE lines",
    )
    parser.add_argument(
        "--startup-timeout",
        type=float,
        default=45.0,
        help="Seconds to wait for endpoint readiness after launch",
    )
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="Skip dependency preflight checks",
    )
    parser.add_argument(
        "--skip-chimera-verify",
        action="store_true",
        help="Skip Chimera verification before startup",
    )
    return parser.parse_args()


def _run_chimera_verification() -> int:
    cmd = [sys.executable, "verify_chimera.py"]
    return subprocess.run(cmd, cwd=Path(__file__).parent).returncode


def _run_preflight(env_file: str, apex_url: str) -> int:
    cmd = [
        sys.executable,
        "preflight_offline.py",
        "--env-file",
        env_file,
        "--apex-url",
        apex_url,
    ]
    return subprocess.run(cmd, cwd=Path(__file__).parent).returncode


def _wait_for_readiness(base_url: str, timeout_seconds: float) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            hz = requests.get(base_url + "/healthz", timeout=2.0)
            rz = requests.get(base_url + "/readyz", timeout=2.0)
            if hz.status_code == 200 and rz.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(1.0)
    return False


def main() -> int:
    args = _parse_args()
    base_url = f"http://{args.host}:{args.port}"

    if not args.skip_chimera_verify:
        verify_rc = _run_chimera_verification()
        if verify_rc != 0:
            print("Chimera verification failed. Resolve contract/test failures before startup.")
            return verify_rc

    if not args.skip_preflight:
        preflight_rc = _run_preflight(args.env_file, base_url)
        if preflight_rc != 0:
            print("Preflight failed. Fix the reported issues before startup.")
            return preflight_rc

    cmd = [
        sys.executable,
        "run_offline.py",
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--env-file",
        args.env_file,
    ]
    if args.reload:
        cmd.append("--reload")

    proc = subprocess.Popen(cmd, cwd=Path(__file__).parent)

    try:
        if not _wait_for_readiness(base_url, args.startup_timeout):
            print(f"Startup readiness check failed after {args.startup_timeout:.0f}s")
            print("Run preflight_offline.py --check-apex after fixing local services for details")
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
            return 3

        print(f"Apex offline runtime is ready at {base_url}")
        return proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
