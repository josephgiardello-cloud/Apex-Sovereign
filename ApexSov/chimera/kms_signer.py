"""Apex Sovereign – KMS/ECDSA signing primitives, Merkle tree utilities, and entry hash computation.

Extracted from BaseT8.py.  Call configure_kms_signer() before using
load_signer_for_worker() or get_signer_public_key_b64().
"""

import base64
import hashlib
import json
import os
from typing import Any, Callable, Dict, List, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

# ── Module-level config (set by configure_kms_signer) ─────────────────────────
_APEX_FIPS_MODE: bool = False
_KMS_KEY_ID: str = ""
_KMS_REGION: Optional[str] = None
_get_apex_env_fn: Optional[Callable] = None
_APEX_ENV_PROD: Any = None

# Public-key cache (rotation-aware)
_PUBLIC_KEY_CACHE_B64: Optional[str] = None
_PUBLIC_KEY_CACHE_BY_KID: Dict[str, str] = {}


def configure_kms_signer(
    *,
    apex_fips_mode: bool,
    kms_key_id: str,
    kms_region: Optional[str],
    get_apex_env_fn: Callable,
    apex_env_prod: Any,
) -> None:
    global _APEX_FIPS_MODE, _KMS_KEY_ID, _KMS_REGION, _get_apex_env_fn, _APEX_ENV_PROD
    _APEX_FIPS_MODE = bool(apex_fips_mode)
    _KMS_KEY_ID = str(kms_key_id or "")
    _KMS_REGION = kms_region or None
    _get_apex_env_fn = get_apex_env_fn
    _APEX_ENV_PROD = apex_env_prod


# ── Signer protocol + implementations ─────────────────────────────────────────

class Signer:
    """Signing interface (structural subtyping)."""

    def sign(self, message: bytes) -> bytes:
        raise NotImplementedError


class KmsEcdsaSigner:
    """
    AWS KMS-backed ECDSA signer.
    Produces signatures over SHA-256 digests of canonical ledger records.
    """

    def __init__(self, key_id: str, region: Optional[str] = None):
        if not key_id:
            raise RuntimeError("KMS key id must be set (APEX_KMS_KEY_ID or APEX_HSM_KEY_ID)")
        self.key_id = key_id
        session_kwargs: Dict[str, Any] = {}
        if region:
            session_kwargs["region_name"] = region
        import boto3

        self._client = boto3.client("kms", **session_kwargs)

    def sign(self, message: bytes) -> bytes:
        digest = hashlib.sha256(message).digest()
        try:
            resp = self._client.sign(
                KeyId=self.key_id,
                Message=digest,
                MessageType="DIGEST",
                SigningAlgorithm="ECDSA_SHA_256",
            )
        except Exception as e:
            raise RuntimeError(f"KMS signing failed: {e}")
        signature = resp.get("Signature")
        if not signature:
            raise RuntimeError("KMS returned no Signature")
        return signature


class SoftEcdsaSigner:
    """
    Dev-only ECDSA signer using a local private key (non-FIPS).
    """

    def __init__(self, private_key_pem: bytes):
        self._pem_buf = bytearray(private_key_pem)
        self._key = serialization.load_pem_private_key(bytes(self._pem_buf), password=None)

    def zeroize(self) -> None:
        """Best-effort overwrite of in-memory private key material.

        Note: Python cannot strictly guarantee zeroization of all copies (GC, allocator).
        This provides an operator-triggered "clear state" signal and reduces exposure.
        """
        try:
            for i in range(len(self._pem_buf)):
                self._pem_buf[i] = 0
        except Exception:
            pass
        self._key = None

    def sign(self, message: bytes) -> bytes:
        if self._key is None:
            raise RuntimeError("Soft signer key material has been zeroized")
        digest = hashlib.sha256(message).digest()
        return self._key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))


def load_signer_for_worker() -> Signer:
    """
    Load an appropriate signer for the current environment:
    - PROD or FIPS: KMS/HSM is mandatory
    - Non-prod: soft key via APEX_DEV_LEDGER_PRIVATE_KEY_PEM
    """
    env = _get_apex_env_fn()

    if _APEX_FIPS_MODE:
        if not _KMS_KEY_ID:
            raise RuntimeError("APEX_FIPS_MODE enabled but no KMS/HSM key configured (APEX_KMS_KEY_ID/APEX_HSM_KEY_ID)")
        return KmsEcdsaSigner(key_id=_KMS_KEY_ID, region=_KMS_REGION or None)

    if env == _APEX_ENV_PROD:
        if not _KMS_KEY_ID:
            raise RuntimeError("APEX_KMS_KEY_ID (or APEX_HSM_KEY_ID) must be set in PROD")
        return KmsEcdsaSigner(key_id=_KMS_KEY_ID, region=_KMS_REGION or None)

    dev_key_pem = os.getenv("APEX_DEV_LEDGER_PRIVATE_KEY_PEM", "").encode("utf-8")
    if not dev_key_pem.strip():
        raise RuntimeError("APEX_DEV_LEDGER_PRIVATE_KEY_PEM must be set in non-prod for ledger signing")
    return SoftEcdsaSigner(private_key_pem=dev_key_pem)


# ── Entry hash & Merkle utilities ──────────────────────────────────────────────

def compute_entry_hash(payload: Dict[str, Any], prev_hash: Optional[str]) -> str:
    """
    Compute chained hash for ledger entry, binding payload + previous hash.
    """
    base_record = {
        "payload": payload,
        "prev_hash": prev_hash,
    }
    record_bytes = json.dumps(base_record, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(record_bytes).hexdigest()


def compute_merkle_root_hex(leaves_hex: List[str]) -> Optional[str]:
    """Compute a SHA-256 Merkle root from hex-encoded leaf hashes.

    - If the number of leaves is odd at any level, the last leaf is duplicated.
    - Returns hex root, or None if leaves_hex is empty.
    """
    if not leaves_hex:
        return None

    level = [bytes.fromhex(h) for h in leaves_hex]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level: List[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1]
            next_level.append(hashlib.sha256(left + right).digest())
        level = next_level
    return level[0].hex()


def compute_merkle_inclusion_proof_hex(leaves_hex: List[str], leaf_index: int) -> List[Dict[str, str]]:
    """Return an inclusion proof for a leaf within a SHA-256 Merkle tree.

    Proof format: list of {"sibling": <hex>, "sibling_position": "left"|"right"}
    where sibling_position denotes where the sibling sits relative to the running hash.
    """
    if leaf_index < 0 or leaf_index >= len(leaves_hex):
        raise ValueError("leaf_index out of range")

    level = [bytes.fromhex(h) for h in leaves_hex]
    idx = int(leaf_index)
    proof: List[Dict[str, str]] = []

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])

        sibling_idx = idx ^ 1
        sibling_position = "right" if (idx % 2 == 0) else "left"
        proof.append({"sibling": level[sibling_idx].hex(), "sibling_position": sibling_position})

        next_level: List[bytes] = []
        for i in range(0, len(level), 2):
            next_level.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        level = next_level
        idx = idx // 2

    return proof


# ── Key export helpers ─────────────────────────────────────────────────────────

def _public_key_spki_der_b64_from_private_key_pem(private_key_pem: bytes) -> str:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    pub = key.public_key()
    spki_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(spki_der).decode("ascii")


def _kms_public_key_spki_der_b64(key_id: str, region: Optional[str]) -> str:
    session_kwargs: Dict[str, Any] = {}
    if region:
        session_kwargs["region_name"] = region

    import boto3

    client = boto3.client("kms", **session_kwargs)
    resp = client.get_public_key(KeyId=key_id)
    der = resp.get("PublicKey")
    if not der:
        raise RuntimeError("KMS GetPublicKey returned empty PublicKey")
    return base64.b64encode(der).decode("ascii")


def get_signer_public_key_b64(key_id: Optional[str] = None) -> Optional[str]:
    """Best-effort signer public key export for third-party verification.

    Returns base64-encoded DER SubjectPublicKeyInfo.

    Rotation-aware behavior:
    - If `key_id` is provided and looks like a KMS key id/arn, this fetches that
      key's public key (PROD/FIPS).
    - Otherwise it falls back to the currently configured signer (KMS or dev PEM).
    """
    global _PUBLIC_KEY_CACHE_B64

    try:
        env = _get_apex_env_fn()
    except Exception:
        return None

    try:
        if _APEX_FIPS_MODE or env == _APEX_ENV_PROD:
            kid = (key_id or "").strip() or _KMS_KEY_ID
            if not kid:
                return None
            cached = _PUBLIC_KEY_CACHE_BY_KID.get(kid)
            if cached:
                return cached
            pub = _kms_public_key_spki_der_b64(kid, _KMS_REGION or None)
            _PUBLIC_KEY_CACHE_BY_KID[kid] = pub
            # Keep the legacy single-value cache as a best-effort shortcut.
            _PUBLIC_KEY_CACHE_B64 = pub
            return pub

        dev_key_pem = os.getenv("APEX_DEV_LEDGER_PRIVATE_KEY_PEM", "").encode("utf-8")
        if not dev_key_pem.strip():
            return None
        cached = _PUBLIC_KEY_CACHE_BY_KID.get("dev")
        if cached:
            return cached
        pub = _public_key_spki_der_b64_from_private_key_pem(dev_key_pem)
        _PUBLIC_KEY_CACHE_BY_KID["dev"] = pub
        _PUBLIC_KEY_CACHE_B64 = pub
        return pub
    except Exception:
        return None
