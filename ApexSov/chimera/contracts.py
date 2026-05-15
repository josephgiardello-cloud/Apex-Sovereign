from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple


@dataclass(frozen=True)
class ContractVersion:
    major: int
    minor: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}"


@dataclass(frozen=True)
class ChatTurn:
    tenant_id: str
    session_id: str
    model: str
    messages: Sequence[Dict[str, Any]]


class ChatProvider(Protocol):
    contract_version: ContractVersion

    async def complete(self, turn: ChatTurn) -> Dict[str, Any]:
        ...


class EmbeddingProvider(Protocol):
    contract_version: ContractVersion

    async def embed(self, text: str) -> List[float]:
        ...


class ToolExecutor(Protocol):
    contract_version: ContractVersion

    async def execute(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        ...


class TraceSink(Protocol):
    contract_version: ContractVersion

    async def emit(self, event: Dict[str, Any]) -> None:
        ...


class LedgerSink(Protocol):
    contract_version: ContractVersion

    async def append(self, entry: Dict[str, Any]) -> int:
        ...


def check_contract_compat(required: ContractVersion, provided: ContractVersion) -> Tuple[bool, str]:
    if required.major != provided.major:
        return False, f"major_mismatch required={required} provided={provided}"
    if provided.minor < required.minor:
        return False, f"minor_too_old required={required} provided={provided}"
    return True, "compatible"
