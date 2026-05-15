from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from .contracts import ContractVersion, check_contract_compat


@dataclass(frozen=True)
class AdapterSpec:
    name: str
    required_contract: ContractVersion
    provided_contract: ContractVersion
    source_repo: str


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: Dict[str, AdapterSpec] = {}

    def register(self, spec: AdapterSpec) -> None:
        ok, reason = check_contract_compat(spec.required_contract, spec.provided_contract)
        if not ok:
            raise ValueError(f"adapter_incompatible name={spec.name} reason={reason}")
        self._adapters[spec.name] = spec

    def get(self, name: str) -> AdapterSpec:
        if name not in self._adapters:
            raise KeyError(f"adapter_not_registered name={name}")
        return self._adapters[name]

    def as_dict(self) -> Dict[str, str]:
        return {k: f"{v.source_repo}@{v.provided_contract}" for k, v in self._adapters.items()}
