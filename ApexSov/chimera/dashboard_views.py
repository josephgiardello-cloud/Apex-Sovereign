from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Optional

import redis.asyncio as redis


def build_egress_validate_payload(
    url: str,
    *,
    egress_check_url: Callable[[str], Any],
    compile_egress_allowlist_patterns: Callable[[], Any],
    utc_now_z: Callable[[], str],
    block_ip_literals: bool,
    allowlist_regex: str,
    audit_blocks: bool,
) -> Dict[str, Any]:
    ok, reason, details = egress_check_url(url)
    patterns = compile_egress_allowlist_patterns()
    return {
        "ts": utc_now_z(),
        "allowed": bool(ok),
        "reason": reason,
        "details": details,
        "policy": {
            "block_ip_literals": bool(block_ip_literals),
            "allowlist_regex": allowlist_regex,
            "allowlist_patterns": int(len(patterns)),
            "audit_blocks": bool(audit_blocks),
        },
    }


async def get_last_kms_signed_at(
    r: redis.Redis,
    *,
    decode_single_json_skip_invalid: Callable[[Any], Optional[Dict[str, Any]]],
    ledger_key: str = "apex:audit_ledger",
    scan_window: int = 2000,
) -> Optional[str]:
    length = await r.llen(ledger_key)
    if length == 0:
        return None
    for idx in range(length - 1, max(length - scan_window, -1), -1):
        raw = await r.lindex(ledger_key, idx)
        if not raw:
            continue
        decoded = decode_single_json_skip_invalid(raw)
        if decoded is None:
            continue
        kms_signed_at = decoded.get("kms_signed_at")
        signing_status = decoded.get("signing_status")
        if kms_signed_at and signing_status == "kms_signed":
            return kms_signed_at
    return None


async def get_24h_risk_stats(
    r: redis.Redis,
    *,
    metrics_hour_key: Callable[[datetime], str],
    metrics_total_key: Callable[[str], str],
    metrics_blocked_key: Callable[[str], str],
    metrics_highrisk_key: Callable[[str], str],
    metrics_axis_hash_key: Callable[[str], str],
) -> Dict[str, Any]:
    now = datetime.utcnow()
    total = 0
    blocked = 0
    high_risk_alerts = 0
    axis_counts: Dict[str, int] = {}

    for i in range(24):
        dt = now - timedelta(hours=i)
        hour_key = metrics_hour_key(dt)
        total_key = metrics_total_key(hour_key)
        blocked_key = metrics_blocked_key(hour_key)
        highrisk_key = metrics_highrisk_key(hour_key)
        axis_hash_key = metrics_axis_hash_key(hour_key)

        t = await r.get(total_key)
        b = await r.get(blocked_key)
        h = await r.get(highrisk_key)
        axis_map = await r.hgetall(axis_hash_key)

        total += int(t or 0)
        blocked += int(b or 0)
        high_risk_alerts += int(h or 0)

        for axis, count_str in axis_map.items():
            try:
                c = int(count_str)
            except Exception:
                continue
            axis_counts[axis] = axis_counts.get(axis, 0) + c

    top_risk_axis = None
    if axis_counts:
        top_risk_axis = max(axis_counts.items(), key=lambda kv: kv[1])[0]

    return {
        "total_interactions_24h": total,
        "blocked_interactions_24h": blocked,
        "top_risk_axis": top_risk_axis,
        "high_risk_alerts": high_risk_alerts,
    }


async def system_integrity_metrics(
    r: redis.Redis,
    *,
    get_unsigned_backlog_status: Callable[[redis.Redis], Any],
    max_unsigned_queue: int,
    get_last_kms_signed_at_fn: Callable[[redis.Redis], Any],
) -> Dict[str, Any]:
    queue_len, _, _ = await get_unsigned_backlog_status(r)
    backpressure_level = float(queue_len) / float(max_unsigned_queue) if max_unsigned_queue else 0.0
    last_kms_signed_at = await get_last_kms_signed_at_fn(r)
    return {
        "backpressure_level": backpressure_level,
        "last_kms_signed_at": last_kms_signed_at,
    }


async def recent_ledger_status(
    r: redis.Redis,
    *,
    decode_single_json_skip_invalid: Callable[[Any], Optional[Dict[str, Any]]],
    compute_entry_hash: Callable[[Dict[str, Any], Optional[str]], str],
    ledger_key: str = "apex:audit_ledger",
    sample_size: int = 100,
) -> str:
    length = await r.llen(ledger_key)
    if length == 0:
        return "empty"

    start_idx = max(0, length - sample_size)
    prev_hash: Optional[str] = None
    ok = True

    for idx in range(start_idx, length):
        raw = await r.lindex(ledger_key, idx)
        if not raw:
            ok = False
            break
        decoded = decode_single_json_skip_invalid(raw)
        if decoded is None:
            ok = False
            break
        payload = decoded.get("payload", {})
        expected_prev = decoded.get("prev_hash")
        entry_hash = decoded.get("entry_hash")
        recomputed = compute_entry_hash(payload, prev_hash)
        if expected_prev != prev_hash or entry_hash != recomputed:
            ok = False
            break
        prev_hash = entry_hash

    return "healthy" if ok else "error"
