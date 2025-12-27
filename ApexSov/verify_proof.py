"""Offline verifier for ApexSov auditor inclusion proofs.

Usage:
    python verify_proof.py proof.json
    python verify_proof.py proof.json --format json
    python verify_proof.py proof.json --format text
    python verify_proof.py proof.json --format json --out certificate.json

Where proof.json is the JSON body returned by:
    GET /api/v1/verify/{entry_id}

Checks (server-parity):
    1) Merkle inclusion proof: leaf_hash -> anchor.merkle_root
    2) Anchor entry_hash integrity: entry_hash == sha256(json({payload, prev_hash}))
         using canonical JSON settings, matching BaseT8.compute_entry_hash.
    3) Anchor ECDSA signature verification over SHA-256(signed_message_canonical)
         using SPKI DER public key + DER signature, matching BaseT8 signing_worker_loop.

Output:
    Emits a "Verification Certificate" (JSON or text) that mirrors server fields:
        anchor.signature_verified
        anchor.signature_verification_error

Fail-closed:
    This verifier fails closed by default: if the proof does not contain the
    signature material (public_key_b64, kms_signature_b64, signed_message_canonical),
    verification fails.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


SiblingPos = Literal["left", "right"]


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _compute_entry_hash(payload: Dict[str, Any], prev_hash: str | None) -> str:
    """Mirror BaseT8.compute_entry_hash.

    record_bytes = sha256(json({payload, prev_hash})) where JSON is canonicalized
    with separators and sort_keys.
    """
    base_record = {"payload": payload, "prev_hash": prev_hash}
    record_bytes = json.dumps(base_record, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(record_bytes).hexdigest()


def verify_anchor_entry_hash(*, message: str) -> None:
    """Verify the anchor entry_hash matches hash(payload, prev_hash)."""
    try:
        doc = json.loads(message)
    except Exception as e:
        raise ValueError(f"signed_message_canonical is not valid JSON: {e}")

    if not isinstance(doc, dict):
        raise ValueError("signed_message_canonical must decode to an object")

    payload = doc.get("payload")
    prev_hash = doc.get("prev_hash")
    entry_hash = doc.get("entry_hash")

    if not isinstance(payload, dict):
        raise ValueError("signed_message_canonical.payload missing/invalid")
    if prev_hash is not None and not isinstance(prev_hash, str):
        raise ValueError("signed_message_canonical.prev_hash invalid")
    if not isinstance(entry_hash, str) or len(entry_hash) != 64:
        raise ValueError("signed_message_canonical.entry_hash missing/invalid")

    if payload.get("decision") != "MERKLE_ANCHOR":
        # Not strictly required for cryptographic validity, but helps catch misuse.
        raise ValueError("signed_message_canonical.payload.decision is not MERKLE_ANCHOR")

    recomputed = _compute_entry_hash(payload, prev_hash)
    if recomputed != entry_hash:
        raise ValueError("anchor entry_hash mismatch")


def verify_anchor_payload_merkle_root(*, message: str, expected_merkle_root: str) -> None:
    """Verify the MERKLE_ANCHOR payload merkle_root matches anchor.merkle_root."""
    try:
        doc = json.loads(message)
    except Exception as e:
        raise ValueError(f"signed_message_canonical is not valid JSON: {e}")

    if not isinstance(doc, dict):
        raise ValueError("signed_message_canonical must decode to an object")
    payload = doc.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("signed_message_canonical.payload missing/invalid")
    mr = payload.get("merkle_root")
    if not isinstance(mr, str) or len(mr) != 64:
        raise ValueError("signed_message_canonical.payload.merkle_root missing/invalid")
    if mr != expected_merkle_root:
        raise ValueError("anchor payload merkle_root mismatch")


def verify_anchor_signature(*, public_key_b64: str, signature_b64: str, message: str) -> None:
    spki_der = base64.b64decode(public_key_b64)
    signature = base64.b64decode(signature_b64)

    pub = serialization.load_der_public_key(spki_der)
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise ValueError("public key is not an EC key")

    msg_bytes = message.encode("utf-8")
    digest = _sha256(msg_bytes)

    # In BaseT8.py the signer signs SHA-256(message_bytes) using Prehashed.
    pub.verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))


def merkle_root_from_proof(*, leaf_hash_hex: str, proof: List[Dict[str, str]]) -> str:
    cur = bytes.fromhex(leaf_hash_hex)
    for step in proof:
        sib_hex = step["sibling"]
        pos: SiblingPos = step["sibling_position"]  # type: ignore[assignment]
        sib = bytes.fromhex(sib_hex)

        if pos == "left":
            cur = _sha256(sib + cur)
        elif pos == "right":
            cur = _sha256(cur + sib)
        else:
            raise ValueError(f"invalid sibling_position: {pos!r}")

    return cur.hex()


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _render_certificate_text(cert: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("ApexSov Verification Certificate")
    lines.append(f"ts: {cert.get('ts')}")
    lines.append(f"status: {cert.get('verification_status')}")
    lines.append(f"input: {cert.get('input_file')}")

    checks = cert.get("checks") or {}
    if isinstance(checks, dict):
        lines.append("checks:")
        for k in (
            "merkle_inclusion",
            "anchor_entry_hash",
            "anchor_payload_merkle_root",
            "anchor_signature",
        ):
            v = checks.get(k)
            if v is True:
                lines.append(f"  - {k}: PASS")
            elif v is False:
                lines.append(f"  - {k}: FAIL")
            else:
                lines.append(f"  - {k}: SKIP")

    anchor = cert.get("anchor") or {}
    if isinstance(anchor, dict):
        sv = anchor.get("signature_verified")
        err = anchor.get("signature_verification_error")
        lines.append("anchor:")
        lines.append(f"  signature_verified: {sv}")
        if err:
            lines.append(f"  signature_verification_error: {err}")

    return "\n".join(lines) + "\n"


def _build_verification_certificate(
    *,
    proof_doc: Dict[str, Any],
    input_file: str,
    output_format: str,
) -> Dict[str, Any]:
    leaf_hash = proof_doc.get("leaf_hash")
    merkle_proof = proof_doc.get("merkle_proof")
    anchor = proof_doc.get("anchor")

    cert: Dict[str, Any] = {
        "type": "VERIFICATION_CERTIFICATE",
        "ts": _now_utc_iso(),
        "input_file": input_file,
        "format": output_format,
        "verification_status": "failed",
        "checks": {
            "merkle_inclusion": None,
            "anchor_entry_hash": None,
            "anchor_payload_merkle_root": None,
            "anchor_signature": None,
        },
        "errors": [],
        "evidence": {
            "leaf_hash": leaf_hash,
            "merkle_root_expected": None,
            "merkle_root_computed": None,
            "anchor_signing_status": None,
            "anchor_kms_signed_at": None,
        },
        # Mirror server fields under `anchor`.
        "anchor": {
            "signature_verified": None,
            "signature_verification_error": None,
        },
    }

    # Basic shape validation
    if not isinstance(leaf_hash, str) or len(leaf_hash) != 64:
        cert["errors"].append("leaf_hash missing/invalid")
        return cert
    if not isinstance(merkle_proof, list) or not isinstance(anchor, dict):
        cert["errors"].append("merkle_proof/anchor missing/invalid")
        return cert

    merkle_root_expected = anchor.get("merkle_root")
    cert["evidence"]["merkle_root_expected"] = merkle_root_expected
    if not isinstance(merkle_root_expected, str) or len(merkle_root_expected) != 64:
        cert["errors"].append("anchor.merkle_root missing/invalid")
        return cert

    # 1) Merkle inclusion
    try:
        merkle_root_computed = merkle_root_from_proof(leaf_hash_hex=leaf_hash, proof=merkle_proof)
        cert["evidence"]["merkle_root_computed"] = merkle_root_computed
        if merkle_root_computed != merkle_root_expected:
            cert["checks"]["merkle_inclusion"] = False
            cert["errors"].append("merkle root mismatch")
            return cert
        cert["checks"]["merkle_inclusion"] = True
    except Exception as e:
        cert["checks"]["merkle_inclusion"] = False
        cert["errors"].append(f"merkle inclusion error: {str(e)[:200]}")
        return cert

    # 2) Anchor integrity + signature (parity with server)
    public_key_b64 = anchor.get("public_key_b64")
    signature_b64 = anchor.get("kms_signature_b64")
    canonical_message = anchor.get("signed_message_canonical")
    signing_status = anchor.get("signing_status")
    kms_signed_at = anchor.get("kms_signed_at")

    cert["evidence"]["anchor_signing_status"] = signing_status
    cert["evidence"]["anchor_kms_signed_at"] = kms_signed_at

    # Fail-closed: signature material must be present.
    missing: List[str] = []
    if not isinstance(canonical_message, str) or not canonical_message:
        missing.append("anchor.signed_message_canonical")
    if not isinstance(public_key_b64, str) or not public_key_b64:
        missing.append("anchor.public_key_b64")
    if not isinstance(signature_b64, str) or not signature_b64:
        missing.append("anchor.kms_signature_b64")
    if not isinstance(signing_status, str) or not signing_status:
        missing.append("anchor.signing_status")
    if not isinstance(kms_signed_at, str) or not kms_signed_at:
        missing.append("anchor.kms_signed_at")
    if missing:
        cert["checks"]["anchor_entry_hash"] = False
        cert["checks"]["anchor_payload_merkle_root"] = False
        cert["checks"]["anchor_signature"] = False
        cert["anchor"]["signature_verified"] = False
        cert["anchor"]["signature_verification_error"] = "missing signature material: " + ", ".join(missing)
        cert["errors"].append(cert["anchor"]["signature_verification_error"])
        return cert

    if signing_status != "kms_signed":
        cert["checks"]["anchor_entry_hash"] = False
        cert["checks"]["anchor_payload_merkle_root"] = False
        cert["checks"]["anchor_signature"] = False
        cert["anchor"]["signature_verified"] = False
        cert["anchor"]["signature_verification_error"] = f"anchor signing_status is not kms_signed: {signing_status!r}"
        cert["errors"].append(cert["anchor"]["signature_verification_error"])
        return cert

    # With signature material present, enforce anchor integrity and signature.
    try:
        verify_anchor_entry_hash(message=canonical_message)
        cert["checks"]["anchor_entry_hash"] = True
    except Exception as e:
        cert["checks"]["anchor_entry_hash"] = False
        cert["anchor"]["signature_verified"] = False
        cert["anchor"]["signature_verification_error"] = str(e)[:200]
        cert["errors"].append(f"anchor entry_hash verification failed: {str(e)[:200]}")
        return cert

    try:
        verify_anchor_payload_merkle_root(message=canonical_message, expected_merkle_root=merkle_root_expected)
        cert["checks"]["anchor_payload_merkle_root"] = True
    except Exception as e:
        cert["checks"]["anchor_payload_merkle_root"] = False
        cert["anchor"]["signature_verified"] = False
        cert["anchor"]["signature_verification_error"] = str(e)[:200]
        cert["errors"].append(f"anchor payload merkle_root verification failed: {str(e)[:200]}")
        return cert

    try:
        verify_anchor_signature(
            public_key_b64=public_key_b64,
            signature_b64=signature_b64,
            message=canonical_message,
        )
        cert["checks"]["anchor_signature"] = True
        cert["anchor"]["signature_verified"] = True
        cert["anchor"]["signature_verification_error"] = None
    except Exception as e:
        cert["checks"]["anchor_signature"] = False
        cert["anchor"]["signature_verified"] = False
        cert["anchor"]["signature_verification_error"] = str(e)[:200]
        cert["errors"].append(f"signature verification failed: {str(e)[:200]}")
        return cert

    cert["verification_status"] = "verified"
    return cert


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Offline verifier for ApexSov inclusion proofs")
    parser.add_argument("proof_json", help="Path to proof JSON (response from GET /api/v1/verify/{entry_id})")
    parser.add_argument("--format", choices=["json", "text"], default="json", help="Certificate output format")
    parser.add_argument("--out", default="", help="Write certificate to a file instead of stdout")
    args = parser.parse_args(argv[1:])

    try:
        proof_doc = _load_json(args.proof_json)
    except Exception as e:
        print(f"FAIL: unable to load JSON: {e}", file=sys.stderr)
        return 2

    cert = _build_verification_certificate(
        proof_doc=proof_doc,
        input_file=args.proof_json,
        output_format=str(args.format),
    )

    if str(args.format) == "text":
        out = _render_certificate_text(cert)
    else:
        out = json.dumps(cert, indent=2, sort_keys=True) + "\n"

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out)
        except Exception as e:
            print(f"FAIL: unable to write certificate: {e}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(out)

    return 0 if cert.get("verification_status") == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
