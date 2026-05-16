from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from avatar_runtime import AvatarEngine, build_comfyui_view_url, replace_tokens


class AvatarRuntimeTests(unittest.TestCase):
    def test_replace_tokens_recurses_nested_objects(self) -> None:
        payload = {
            "a": "__SOURCE_IMAGE__",
            "b": [{"x": "__DRIVING_AUDIO__"}, "keep"],
            "c": {"y": "__OUTPUT_BASENAME__"},
        }

        out = replace_tokens(
            payload,
            {
                "__SOURCE_IMAGE__": "img.png",
                "__DRIVING_AUDIO__": "audio.wav",
                "__OUTPUT_BASENAME__": "clip-123",
            },
        )

        self.assertEqual(out["a"], "img.png")
        self.assertEqual(out["b"][0]["x"], "audio.wav")
        self.assertEqual(out["c"]["y"], "clip-123")

    def test_build_comfyui_view_url_formats_query(self) -> None:
        url = build_comfyui_view_url(
            "http://127.0.0.1:8188",
            {
                "filename": "avatar.mp4",
                "subfolder": "liveportrait",
                "type": "output",
            },
        )
        self.assertIn("/view?", url)
        self.assertIn("filename=avatar.mp4", url)
        self.assertIn("subfolder=liveportrait", url)
        self.assertIn("type=output", url)

    def test_stub_wave_writer_creates_audio_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wav_path = Path(tmp) / "clip.wav"
            AvatarEngine._write_stub_wave(wav_path, "hello world")
            self.assertTrue(wav_path.exists())
            self.assertGreater(wav_path.stat().st_size, 64)


if __name__ == "__main__":
    unittest.main()
