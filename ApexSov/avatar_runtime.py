from __future__ import annotations

import json
import math
import os
import subprocess
import time
import uuid
import wave
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import requests


def replace_tokens(payload: Any, token_map: Dict[str, str]) -> Any:
    if isinstance(payload, dict):
        return {key: replace_tokens(value, token_map) for key, value in payload.items()}
    if isinstance(payload, list):
        return [replace_tokens(item, token_map) for item in payload]
    if isinstance(payload, str):
        out = payload
        for token, value in token_map.items():
            out = out.replace(token, value)
        return out
    return payload


def build_comfyui_view_url(comfyui_url: str, asset: Dict[str, str]) -> str:
    base = comfyui_url.rstrip("/")
    query = urlencode(
        {
            "filename": str(asset.get("filename") or ""),
            "subfolder": str(asset.get("subfolder") or ""),
            "type": str(asset.get("type") or "output"),
        }
    )
    return f"{base}/view?{query}"


class AvatarEngine:
    def __init__(
        self,
        apex_url: str = "http://127.0.0.1:8000",
        comfyui_url: str = "http://127.0.0.1:8188",
        portrait_image: str = "",
        workflow_path: str = "",
        output_dir: str = "avatar_outputs",
        tts_backend: str = "piper",
        piper_exe: str = "",
        piper_model: str = "",
    ) -> None:
        self.apex_url = apex_url.rstrip("/")
        self.comfyui_url = comfyui_url.rstrip("/")
        self.portrait_image = portrait_image
        self.workflow_path = workflow_path
        self.output_dir = Path(output_dir)
        self.tts_backend = tts_backend
        self.piper_exe = piper_exe or str(os.getenv("APEX_TTS_PIPER_EXE", "")).strip()
        self.piper_model = piper_model or str(os.getenv("APEX_TTS_PIPER_MODEL", "")).strip()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def text_to_speech(self, text: str, output_stem: Optional[str] = None) -> Path:
        stem = output_stem or f"avatar-{uuid.uuid4().hex[:10]}"
        wav_path = (self.output_dir / f"{stem}.wav").resolve()
        clean_text = (text or "").strip()
        if not clean_text:
            clean_text = "No content provided."

        if self.tts_backend == "piper" and self.piper_exe and self.piper_model:
            cmd = [self.piper_exe, "-m", self.piper_model, "-f", str(wav_path)]
            subprocess.run(
                cmd,
                input=clean_text,
                text=True,
                capture_output=True,
                check=True,
            )
            return wav_path

        self._write_stub_wave(wav_path, clean_text)
        return wav_path

    def run_liveportrait(self, source_image: str, driving_audio: str, output_stem: Optional[str] = None) -> str:
        image_path = Path(source_image).resolve()
        audio_path = Path(driving_audio).resolve()
        if not image_path.exists():
            raise FileNotFoundError(f"Avatar source image not found: {image_path}")
        if not audio_path.exists():
            raise FileNotFoundError(f"Driving audio not found: {audio_path}")

        workflow = self._load_workflow_template()
        stem = output_stem or f"avatar-{uuid.uuid4().hex[:10]}"
        resolved = replace_tokens(
            workflow,
            {
                "__SOURCE_IMAGE__": str(image_path),
                "__DRIVING_AUDIO__": str(audio_path),
                "__OUTPUT_BASENAME__": stem,
            },
        )

        prompt_id = self._submit_comfyui_prompt(resolved)
        output_asset = self._wait_for_output_asset(prompt_id)
        if not output_asset:
            raise RuntimeError("LivePortrait workflow finished without video/image output asset.")
        return build_comfyui_view_url(self.comfyui_url, output_asset)

    def create_avatar_clip(self, text: str) -> Dict[str, str]:
        stem = f"avatar-{uuid.uuid4().hex[:10]}"
        audio_path = self.text_to_speech(text, output_stem=stem)
        video_url = self.run_liveportrait(self.portrait_image, str(audio_path), output_stem=stem)
        return {
            "audio_path": str(audio_path),
            "video_url": video_url,
        }

    def _load_workflow_template(self) -> Dict[str, Any]:
        workflow_path = self.workflow_path or str(
            os.getenv("APEX_LIVEPORTRAIT_WORKFLOW", "workflows/liveportrait_audio_template.json")
        ).strip()
        path = Path(workflow_path).resolve()
        if not path.exists():
            raise FileNotFoundError(
                "LivePortrait workflow template missing. "
                "Set APEX_LIVEPORTRAIT_WORKFLOW to a ComfyUI JSON with __SOURCE_IMAGE__, __DRIVING_AUDIO__, __OUTPUT_BASENAME__ tokens."
            )
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("LivePortrait workflow template must be a JSON object.")
        return raw

    def _submit_comfyui_prompt(self, workflow: Dict[str, Any]) -> str:
        resp = requests.post(
            f"{self.comfyui_url}/prompt",
            json={"prompt": workflow},
            timeout=30,
        )
        resp.raise_for_status()
        payload = resp.json()
        prompt_id = str(payload.get("prompt_id") or "").strip()
        if not prompt_id:
            raise RuntimeError("ComfyUI did not return a prompt_id.")
        return prompt_id

    def _wait_for_output_asset(self, prompt_id: str, timeout_seconds: int = 120) -> Optional[Dict[str, str]]:
        started = time.time()
        while (time.time() - started) < timeout_seconds:
            resp = requests.get(f"{self.comfyui_url}/history/{prompt_id}", timeout=20)
            resp.raise_for_status()
            history = resp.json()
            prompt_data = history.get(prompt_id)
            if isinstance(prompt_data, dict):
                asset = self._extract_output_asset(prompt_data)
                if asset:
                    return asset
            time.sleep(1.5)
        raise TimeoutError("Timed out waiting for ComfyUI LivePortrait output.")

    @staticmethod
    def _extract_output_asset(prompt_data: Dict[str, Any]) -> Optional[Dict[str, str]]:
        outputs = prompt_data.get("outputs")
        if not isinstance(outputs, dict):
            return None

        for node_data in outputs.values():
            if not isinstance(node_data, dict):
                continue
            for key in ("videos", "images", "gifs"):
                assets = node_data.get(key)
                if isinstance(assets, list) and assets:
                    first = assets[0]
                    if isinstance(first, dict):
                        return {
                            "filename": str(first.get("filename") or ""),
                            "subfolder": str(first.get("subfolder") or ""),
                            "type": str(first.get("type") or "output"),
                        }
        return None

    @staticmethod
    def _write_stub_wave(path: Path, text: str) -> None:
        sample_rate = 22050
        seconds = max(1.0, min(12.0, len(text) / 24.0))
        frequency = 190.0
        amplitude = 12000
        total_samples = int(sample_rate * seconds)

        with wave.open(str(path), "wb") as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(sample_rate)

            frames = bytearray()
            for i in range(total_samples):
                sample = int(amplitude * math.sin(2.0 * math.pi * frequency * (i / sample_rate)))
                frames += int(sample).to_bytes(2, byteorder="little", signed=True)
            wav.writeframes(bytes(frames))
