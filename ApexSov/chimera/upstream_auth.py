from __future__ import annotations

from typing import Callable, Dict


def require_key_for_public_endpoint(
    *,
    api_key: str,
    endpoint_url: str,
    is_public_hostname: Callable[[str], bool],
    failure_message: str,
) -> None:
    if api_key:
        return
    if is_public_hostname(endpoint_url):
        raise ValueError(failure_message)


def build_upstream_headers(
    *,
    api_key: str,
    endpoint_url: str,
    is_public_hostname: Callable[[str], bool],
    public_key_required_message: str,
) -> Dict[str, str]:
    require_key_for_public_endpoint(
        api_key=api_key,
        endpoint_url=endpoint_url,
        is_public_hostname=is_public_hostname,
        failure_message=public_key_required_message,
    )

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers
