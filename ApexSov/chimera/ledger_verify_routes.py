from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Awaitable, Callable, Dict, List, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from fastapi import Depends, HTTPException
from pydantic import BaseModel


class MerkleAnchorInfo(BaseModel):
    anchor_index: int
    anchor_entry_id: Optional[str] = None
    anchored_start_index: int
    anchored_end_index: int
    merkle_alg: str
    merkle_root: str
    kms_signature_b64: Optional[str] = None
    signing_status: Optional[str] = None
    kms_signed_at: Optional[str] = None
    kid: Optional[str] = None
    alg: Optional[str] = None
    public_key_b64: Optional[str] = None
    public_key_format: Optional[str] = None
    signed_message_canonical: str
    signature_verified: Optional[bool] = None
    signature_verification_error: Optional[str] = None


class InclusionProofResponse(BaseModel):
    entry_index: int
    entry: Dict[str, Any]
    leaf_hash: str
    merkle_proof: List[Dict[str, str]]
    anchor: MerkleAnchorInfo


def register_ledger_verify_routes(
    app: Any,
    *,
    authz_engine: Any,
    get_identity: Callable[..., Any],
    get_redis_client: Callable[[], Awaitable[Any]],
    read_raw_ledger_entry: Callable[..., Awaitable[Optional[Dict[str, Any]]]],
    decode_single_json_skip_invalid: Callable[[Any], Optional[Dict[str, Any]]],
    extract_entry_hash_leaves: Callable[[List[Any]], List[str]],
    compute_entry_hash: Callable[[Dict[str, Any], Any], str],
    compute_merkle_root_hex: Callable[[List[str]], str],
    compute_merkle_inclusion_proof_hex: Callable[[List[str], int], List[Dict[str, str]]],
    get_signer_public_key_b64: Callable[[Optional[str]], Optional[str]],
    verify_scan_limit: int,
    anchor_search_limit: int,
) -> None:
    @app.get("/api/v1/verify/{entry_id}")
    async def verify_entry_inclusion(
        entry_id: str,
        identity=Depends(get_identity),
        zero_cache: bool = False,
        entry_index: Optional[int] = None,
        verify_signature: bool = False,
    ):
        """Auditor workflow: return an inclusion proof for a ledger entry_id."""
        authz_engine.require_audit_read(identity)
        r = await get_redis_client()

        index: Optional[int] = None
        length = int(await r.llen("apex:audit_ledger") or 0)

        if entry_index is not None:
            if int(entry_index) < 0 or int(entry_index) >= length:
                raise HTTPException(status_code=400, detail="entry_index out of range")
            candidate = await read_raw_ledger_entry(r, int(entry_index))
            if not candidate:
                raise HTTPException(status_code=404, detail="ledger entry missing")
            cand_payload = candidate.get("payload") or {}
            if cand_payload.get("entry_id") != entry_id:
                raise HTTPException(status_code=400, detail="entry_index does not match entry_id")
            index = int(entry_index)
        else:
            if not zero_cache:
                try:
                    raw_idx = await r.get(f"apex:ledger:index:{entry_id}")
                    if raw_idx is not None:
                        index = int(raw_idx)
                except Exception:
                    index = None

            if index is None:
                if zero_cache and length > max(1, int(verify_scan_limit)):
                    raise HTTPException(
                        status_code=413,
                        detail="zero_cache scan too large; provide entry_index or increase APEX_VERIFY_SCAN_LIMIT",
                    )

                start = 0 if zero_cache else max(0, length - max(1, int(verify_scan_limit)))
                for i in range(start, length):
                    raw = await r.lindex("apex:audit_ledger", i)
                    if not raw:
                        continue
                    decoded = decode_single_json_skip_invalid(raw)
                    if decoded is None:
                        continue
                    if (decoded.get("payload") or {}).get("entry_id") == entry_id:
                        index = i
                        break

        if index is None:
            raise HTTPException(status_code=404, detail="entry_id not found")

        entry = await read_raw_ledger_entry(r, index)
        if not entry:
            raise HTTPException(status_code=404, detail="ledger entry missing")

        payload = entry.get("payload", {})
        prev_hash = entry.get("prev_hash")
        leaf_hash = entry.get("entry_hash") or compute_entry_hash(payload, prev_hash)

        anchor_entry: Optional[Dict[str, Any]] = None
        anchor_index: Optional[int] = None
        length = int(await r.llen("apex:audit_ledger") or 0)
        search_end = min(length, index + max(1, anchor_search_limit))
        for j in range(index, search_end):
            candidate = await read_raw_ledger_entry(r, j)
            if not candidate:
                continue
            cand_payload = candidate.get("payload") or {}
            if cand_payload.get("decision") != "MERKLE_ANCHOR":
                continue
            try:
                s = int(cand_payload.get("anchored_start_index"))
                e = int(cand_payload.get("anchored_end_index"))
            except Exception:
                continue
            if s <= index <= e:
                anchor_entry = candidate
                anchor_index = j
                break

        if not anchor_entry or anchor_index is None:
            raise HTTPException(status_code=404, detail="no MERKLE_ANCHOR found for this entry (not anchored yet)")

        a_payload = anchor_entry.get("payload") or {}
        merkle_root = a_payload.get("merkle_root")
        if not merkle_root:
            raise HTTPException(status_code=500, detail="anchor entry missing merkle_root")

        anchored_start = int(a_payload.get("anchored_start_index"))
        anchored_end = int(a_payload.get("anchored_end_index"))
        raw_entries = await r.lrange("apex:audit_ledger", anchored_start, anchored_end)
        if len(raw_entries) != (anchored_end - anchored_start + 1):
            raise HTTPException(status_code=500, detail="anchored leaf window incomplete")

        leaves: List[str] = []
        if zero_cache:
            chain_prev: Optional[str] = None
            for k, raw in enumerate(raw_entries):
                decoded = decode_single_json_skip_invalid(raw)
                if decoded is None:
                    raise HTTPException(status_code=500, detail="invalid ledger entry JSON in anchored window")

                p = decoded.get("payload") or {}
                stored_prev = decoded.get("prev_hash")
                stored_hash = decoded.get("entry_hash")

                if k == 0:
                    chain_prev = stored_prev
                elif stored_prev != chain_prev:
                    raise HTTPException(status_code=500, detail="ledger chain mismatch inside anchored window")

                recomputed = compute_entry_hash(p, chain_prev)
                if stored_hash and stored_hash != recomputed:
                    raise HTTPException(status_code=500, detail="ledger entry_hash mismatch inside anchored window")

                leaves.append(recomputed)
                chain_prev = recomputed

            computed_root = compute_merkle_root_hex(leaves)
            if computed_root and computed_root != merkle_root:
                raise HTTPException(status_code=500, detail="anchor merkle_root does not match recomputed root")
        else:
            leaves = extract_entry_hash_leaves(raw_entries)

        pos = index - anchored_start
        if pos < 0 or pos >= len(leaves):
            raise HTTPException(status_code=500, detail="entry index not within anchored leaf set")

        proof = compute_merkle_inclusion_proof_hex(leaves, pos)

        if zero_cache:
            leaf_hash = leaves[pos]

        a_prev = anchor_entry.get("prev_hash")
        a_entry_hash = anchor_entry.get("entry_hash")
        canonical = json.dumps(
            {
                "payload": a_payload,
                "prev_hash": a_prev,
                "entry_hash": a_entry_hash,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

        signature_verified: Optional[bool] = None
        signature_verification_error: Optional[str] = None
        if verify_signature:
            try:
                sig_b64 = anchor_entry.get("kms_signature")
                if not (isinstance(sig_b64, str) and sig_b64):
                    raise RuntimeError("anchor entry missing kms_signature")

                anchor_kid = anchor_entry.get("kid")
                pub_b64 = get_signer_public_key_b64(anchor_kid if isinstance(anchor_kid, str) else None)
                if not (isinstance(pub_b64, str) and pub_b64):
                    raise RuntimeError("signer public key unavailable")

                recomputed_anchor_hash = compute_entry_hash(a_payload, a_prev)
                if a_entry_hash and recomputed_anchor_hash != a_entry_hash:
                    raise RuntimeError("anchor entry_hash mismatch")

                sig = base64.b64decode(sig_b64)
                pub_der = base64.b64decode(pub_b64)
                pub = serialization.load_der_public_key(pub_der)
                digest = hashlib.sha256(canonical.encode("utf-8")).digest()
                pub.verify(sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
                signature_verified = True
            except Exception as exc:
                signature_verified = False
                signature_verification_error = str(exc)[:200]

        anchor_info = MerkleAnchorInfo(
            anchor_index=anchor_index,
            anchor_entry_id=(a_payload.get("entry_id") if isinstance(a_payload, dict) else None),
            anchored_start_index=anchored_start,
            anchored_end_index=anchored_end,
            merkle_alg=a_payload.get("merkle_alg", "sha256"),
            merkle_root=merkle_root,
            kms_signature_b64=anchor_entry.get("kms_signature"),
            signing_status=anchor_entry.get("signing_status"),
            kms_signed_at=anchor_entry.get("kms_signed_at"),
            kid=anchor_entry.get("kid"),
            alg=anchor_entry.get("alg"),
            public_key_b64=get_signer_public_key_b64(anchor_entry.get("kid") if isinstance(anchor_entry.get("kid"), str) else None),
            public_key_format="spki_der",
            signed_message_canonical=canonical,
            signature_verified=signature_verified,
            signature_verification_error=signature_verification_error,
        )

        return InclusionProofResponse(
            entry_index=index,
            entry=entry,
            leaf_hash=leaf_hash,
            merkle_proof=proof,
            anchor=anchor_info,
        )
