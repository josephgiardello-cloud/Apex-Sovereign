from __future__ import annotations

import unittest

from dadbot_sovereign_ui import _build_persona_prompt, _compose_request_messages, _sanitize_persona_profile


class PersonaCompositionTests(unittest.TestCase):
    def test_build_persona_prompt_includes_expected_sections(self) -> None:
        prompt = _build_persona_prompt(
            {
                "role": "Incident commander",
                "tone": "Steady",
                "style": "Short bullets",
                "goals": "Stabilize systems and keep operators informed",
                "guardrails": "Avoid guessing root cause",
                "system_instructions": "Always provide rollback criteria.",
            }
        )

        self.assertIn("Role: Incident commander", prompt)
        self.assertIn("Tone: Steady", prompt)
        self.assertIn("Style: Short bullets", prompt)
        self.assertIn("Primary goals: Stabilize systems and keep operators informed", prompt)
        self.assertIn("Behavior boundaries: Avoid guessing root cause", prompt)
        self.assertIn("Additional instructions: Always provide rollback criteria.", prompt)

    def test_sanitize_persona_profile_generates_prompt_when_missing(self) -> None:
        profile = _sanitize_persona_profile({"name": "Ops Agent", "role": "Ops responder", "prompt": ""})

        self.assertEqual(profile["name"], "Ops Agent")
        self.assertEqual(profile["role"], "Ops responder")
        self.assertTrue(profile["prompt"].startswith("Role: Ops responder"))

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
