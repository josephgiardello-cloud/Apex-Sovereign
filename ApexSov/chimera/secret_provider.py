"""Apex Sovereign - secret provider abstraction."""

import os


class SecretProvider:
    """Simple secret abstraction for upstream providers."""

    async def get_openai_key(self) -> str:
        return os.getenv("OPENAI_API_KEY", "")

    async def get_anthropic_key(self) -> str:
        return os.getenv("ANTHROPIC_API_KEY", "")


def build_secret_provider() -> SecretProvider:
    return SecretProvider()
