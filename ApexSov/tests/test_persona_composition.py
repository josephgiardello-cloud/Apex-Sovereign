from __future__ import annotations

import unittest

from dadbot_sovereign_ui import _compose_request_messages


class PersonaCompositionTests(unittest.TestCase):
    def test_injects_system_prompt_before_chat_history(self) -> None:
        messages = [
            {"role": "system", "content": "ignore-me"},
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
            {"role": "tool", "content": "internal"},
        ]

        composed = _compose_request_messages(messages, "  You are concise.  ")

        self.assertEqual(
            composed,
            [
                {"role": "system", "content": "You are concise."},
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "hi"},
            ],
        )

    def test_skips_empty_content_and_missing_persona_prompt(self) -> None:
        messages = [
            {"role": "user", "content": ""},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": "next"},
        ]

        composed = _compose_request_messages(messages, "   ")

        self.assertEqual(
            composed,
            [
                {"role": "assistant", "content": "ok"},
                {"role": "user", "content": "next"},
            ],
        )


if __name__ == "__main__":
    unittest.main()
