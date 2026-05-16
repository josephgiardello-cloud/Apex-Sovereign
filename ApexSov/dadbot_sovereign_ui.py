from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import streamlit as st
import streamlit.components.v1 as components


@dataclass
class SovereignConfig:
    base_url: str
    tenant_id: str
    session_id: str
    device_id: str
    bearer_token: str
    model: str
    timeout_seconds: float
    persona_name: str
    persona_prompt: str


def _maybe_generate_avatar_response(text: str, cfg: SovereignConfig) -> Optional[str]:
    source = str(st.session_state.get("avatar_source") or "")
    enabled = bool(st.session_state.get("avatar_enabled", False))
    auto_generate = bool(st.session_state.get("avatar_auto_generate", False))
    if not enabled or source != "Generated (TTS + LivePortrait)" or not auto_generate:
        return None

    portrait_image = str(st.session_state.get("avatar_portrait_image") or "").strip()
    workflow_path = str(st.session_state.get("avatar_workflow_path") or "").strip()
    comfyui_url = str(st.session_state.get("avatar_comfyui_url") or "http://127.0.0.1:8188").strip()
    tts_backend = str(st.session_state.get("avatar_tts_backend") or "piper").strip()
    piper_exe = str(st.session_state.get("avatar_piper_exe") or "").strip()
    piper_model = str(st.session_state.get("avatar_piper_model") or "").strip()

    if not portrait_image:
        return "Avatar generation skipped: set a portrait image path in sidebar settings."

    try:
        from avatar_runtime import AvatarEngine

        engine = AvatarEngine(
            apex_url=cfg.base_url,
            comfyui_url=comfyui_url,
            portrait_image=portrait_image,
            workflow_path=workflow_path,
            output_dir="avatar_outputs",
            tts_backend=tts_backend,
            piper_exe=piper_exe,
            piper_model=piper_model,
        )
        result = engine.create_avatar_clip(text)
        st.session_state["avatar_last_audio"] = str(result.get("audio_path") or "")
        st.session_state["avatar_last_video"] = str(result.get("video_url") or "")
        st.session_state["avatar_last_error"] = ""
        return None
    except Exception as exc:
        error_text = f"Avatar generation failed: {exc}"
        st.session_state["avatar_last_error"] = error_text
        return error_text


def _default_base_url() -> str:
    return str(os.getenv("DADBOT_SOVEREIGN_BASE_URL", "http://127.0.0.1:8000")).strip()


def _default_tenant_id() -> str:
    return str(os.getenv("DADBOT_SOVEREIGN_TENANT_ID", "family-default")).strip()


def _default_model_name() -> str:
    return str(
        os.getenv("APEX_UI_DEFAULT_MODEL")
        or os.getenv("DADBOT_SOVEREIGN_MODEL")
        or "apex-qwen"
    ).strip()


def _persona_storage_path() -> Path:
    configured = str(os.getenv("APEX_UI_PERSONA_PATH", "")).strip()
    if configured:
        return Path(configured)
    return Path(__file__).with_name("personas.json")


def _build_persona_prompt(profile: Dict[str, str]) -> str:
    role = str(profile.get("role") or "General assistant").strip()
    tone = str(profile.get("tone") or "Clear and balanced").strip()
    style = str(profile.get("style") or "Short, practical responses").strip()
    goals = str(profile.get("goals") or "Help the user solve the task safely and effectively.").strip()
    domain_facts = str(profile.get("domain_facts") or "").strip()
    guardrails = str(profile.get("guardrails") or "Do not fabricate facts. Ask for clarification when context is missing.").strip()
    system_instructions = str(profile.get("system_instructions") or "").strip()

    sections = [
        f"Role: {role}",
        f"Tone: {tone}",
        f"Style: {style}",
        f"Primary goals: {goals}",
        f"Operating facts and context: {domain_facts or 'Use only user-provided context and clearly mark uncertainty.'}",
        f"Behavior boundaries: {guardrails}",
    ]
    if system_instructions:
        sections.append(f"Additional instructions: {system_instructions}")
    return "\n".join(sections)


def _sanitize_persona_profile(profile: Dict[str, Any]) -> Dict[str, str]:
    normalized = {
        "name": str(profile.get("name") or "Custom Persona").strip() or "Custom Persona",
        "role": str(profile.get("role") or "General assistant").strip(),
        "tone": str(profile.get("tone") or "Clear and balanced").strip(),
        "style": str(profile.get("style") or "Short, practical responses").strip(),
        "goals": str(profile.get("goals") or "Help the user solve the task safely and effectively.").strip(),
        "domain_facts": str(profile.get("domain_facts") or "").strip(),
        "guardrails": str(
            profile.get("guardrails") or "Do not fabricate facts. Ask for clarification when context is missing."
        ).strip(),
        "system_instructions": str(profile.get("system_instructions") or "").strip(),
    }

    explicit_prompt = str(profile.get("prompt") or "").strip()
    normalized["prompt"] = explicit_prompt if explicit_prompt else _build_persona_prompt(normalized)
    return normalized


def _save_persona_library(library: Dict[str, Dict[str, str]]) -> None:
    path = _persona_storage_path()
    payload = {"personas": library}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _load_persona_library() -> Dict[str, Dict[str, str]]:
    path = _persona_storage_path()
    if not path.exists():
        return {}

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    if not isinstance(raw, dict):
        return {}

    loaded = raw.get("personas")
    if not isinstance(loaded, dict):
        return {}

    sanitized: Dict[str, Dict[str, str]] = {}
    for persona_id, profile in loaded.items():
        if not isinstance(persona_id, str) or not isinstance(profile, dict):
            continue
        sanitized_id = persona_id.strip()
        if not sanitized_id:
            continue
        sanitized[sanitized_id] = _sanitize_persona_profile(profile)
    return sanitized


def _default_persona_library() -> Dict[str, Dict[str, str]]:
    return {
        "neutral-operator": {
            "name": "Neutral Operator",
            "role": "Precise neutral assistant",
            "tone": "Calm, objective, and direct",
            "style": "Concise, structured recommendations",
            "goals": "Give practical guidance with minimal ambiguity.",
            "domain_facts": "General-purpose assistant for governance and engineering requests.",
            "guardrails": "Avoid speculation. State uncertainty clearly.",
            "system_instructions": "",
        },
        "warm-dad": {
            "name": "Warm Dad Mentor",
            "role": "Supportive fatherly mentor",
            "tone": "Warm, grounded, reassuring",
            "style": "Encouraging language with concrete next steps",
            "goals": "Help the user move forward with confidence and safety.",
            "domain_facts": "Family and personal productivity support context.",
            "guardrails": "Never shame the user. Keep advice practical and safe.",
            "system_instructions": "",
        },
        "socratic-coach": {
            "name": "Socratic Coach",
            "role": "Reflective coach",
            "tone": "Curious and constructive",
            "style": "Ask up to three targeted questions, then propose a plan",
            "goals": "Clarify intent before execution while keeping momentum.",
            "domain_facts": "Discovery-first coaching context for ambiguous tasks.",
            "guardrails": "Do not over-question. Transition quickly to action.",
            "system_instructions": "",
        },
        "technical-architect": {
            "name": "Technical Architect",
            "role": "Senior systems architect",
            "tone": "Analytical and pragmatic",
            "style": "Tradeoff-first explanations with implementation specifics",
            "goals": "Maximize correctness, reliability, and maintainability.",
            "domain_facts": "Systems design and implementation context.",
            "guardrails": "Call out risks and assumptions explicitly.",
            "system_instructions": "",
        },
    }


def _persona_builder_questions() -> List[Dict[str, str]]:
    return [
        {
            "key": "name",
            "label": "Persona name",
            "question": "What should we call this persona?",
            "fallback": "Custom Persona",
        },
        {
            "key": "role",
            "label": "Core role",
            "question": "What is this persona's core role or job?",
            "fallback": "General assistant",
        },
        {
            "key": "tone",
            "label": "Tone",
            "question": "What tone should it use? (for example: direct, warm, tactical)",
            "fallback": "Clear and balanced",
        },
        {
            "key": "style",
            "label": "Response style",
            "question": "How should it format responses? (for example: bullet points, step-by-step, concise)",
            "fallback": "Short, practical responses",
        },
        {
            "key": "goals",
            "label": "Primary goals",
            "question": "What outcomes should this persona optimize for?",
            "fallback": "Help the user solve the task safely and effectively.",
        },
        {
            "key": "domain_facts",
            "label": "Facts and context",
            "question": "What facts, constraints, or domain context should it always operate within?",
            "fallback": "Use only user-provided context and clearly mark uncertainty.",
        },
        {
            "key": "guardrails",
            "label": "Guardrails",
            "question": "Any strict boundaries or things it must avoid?",
            "fallback": "Do not fabricate facts. Ask for clarification when context is missing.",
        },
        {
            "key": "system_instructions",
            "label": "Extra instructions",
            "question": "Any additional instructions? (You can say 'none')",
            "fallback": "",
        },
    ]


def _start_persona_builder() -> None:
    st.session_state["persona_builder_active"] = True
    st.session_state["persona_builder_step"] = 0
    st.session_state["persona_builder_answers"] = {}

    messages: List[Dict[str, str]] = st.session_state.setdefault(
        "messages",
        [{"role": "assistant", "content": "Console online. Send a prompt when ready."}],
    )
    messages.append(
        {
            "role": "assistant",
            "content": (
                "Persona Builder is now active. I will ask focused questions and then create a new persona for you. "
                "Reply naturally; short answers are fine."
            ),
        }
    )
    questions = _persona_builder_questions()
    if questions:
        messages.append({"role": "assistant", "content": questions[0]["question"]})


def _stop_persona_builder() -> None:
    st.session_state["persona_builder_active"] = False
    st.session_state["persona_builder_step"] = 0
    st.session_state["persona_builder_answers"] = {}


def _handle_persona_builder_turn(user_text: str) -> str:
    questions = _persona_builder_questions()
    step = int(st.session_state.get("persona_builder_step", 0))
    answers = dict(st.session_state.get("persona_builder_answers") or {})

    if step >= len(questions):
        _stop_persona_builder()
        return "Persona Builder was already complete. It has been reset."

    question = questions[step]
    answer = user_text.strip() or question.get("fallback", "")
    if answer.lower() == "none" and question["key"] == "system_instructions":
        answer = ""
    answers[question["key"]] = answer
    st.session_state["persona_builder_answers"] = answers

    next_step = step + 1
    st.session_state["persona_builder_step"] = next_step

    if next_step < len(questions):
        return questions[next_step]["question"]

    profile = _sanitize_persona_profile(answers)
    persona_id = f"persona-{uuid.uuid4().hex[:8]}"
    library = st.session_state.get("persona_library") or {}
    library[persona_id] = profile
    st.session_state["persona_library"] = library
    st.session_state["active_persona_id"] = persona_id
    st.session_state["persona_editor_id"] = persona_id
    _sync_persona_editor_from_library(persona_id)
    _save_persona_library(library)
    _stop_persona_builder()

    return (
        f"Persona created: **{profile['name']}** and set as active. "
        "You can refine it in Persona Studio or start chatting with it now."
    )


def _ensure_persona_state() -> None:
    if not bool(st.session_state.get("persona_library_loaded", False)):
        loaded = _load_persona_library()
        if loaded:
            st.session_state["persona_library"] = loaded
        else:
            default_library = {
                persona_id: _sanitize_persona_profile(profile)
                for persona_id, profile in _default_persona_library().items()
            }
            st.session_state["persona_library"] = default_library
            _save_persona_library(default_library)
        st.session_state["persona_library_loaded"] = True

    library = st.session_state.get("persona_library")
    if not isinstance(library, dict) or not library:
        fallback = {
            persona_id: _sanitize_persona_profile(profile)
            for persona_id, profile in _default_persona_library().items()
        }
        st.session_state["persona_library"] = fallback
        _save_persona_library(fallback)

    library = st.session_state["persona_library"]
    active = str(st.session_state.get("active_persona_id") or "").strip()
    if active not in library:
        st.session_state["active_persona_id"] = next(iter(library.keys()))

    editor_id = str(st.session_state.get("persona_editor_id") or "").strip()
    if editor_id not in library:
        st.session_state["persona_editor_id"] = st.session_state["active_persona_id"]
        editor_id = st.session_state["persona_editor_id"]

    loaded = str(st.session_state.get("persona_editor_loaded_id") or "").strip()
    if loaded != editor_id:
        _sync_persona_editor_from_library(editor_id)


def _sync_persona_editor_from_library(persona_id: str) -> None:
    library = st.session_state.get("persona_library") or {}
    profile = _sanitize_persona_profile(library.get(persona_id) or {})
    st.session_state["persona_editor_name"] = str(profile.get("name") or "Custom Persona")
    st.session_state["persona_editor_role"] = str(profile.get("role") or "")
    st.session_state["persona_editor_tone"] = str(profile.get("tone") or "")
    st.session_state["persona_editor_style"] = str(profile.get("style") or "")
    st.session_state["persona_editor_goals"] = str(profile.get("goals") or "")
    st.session_state["persona_editor_domain_facts"] = str(profile.get("domain_facts") or "")
    st.session_state["persona_editor_guardrails"] = str(profile.get("guardrails") or "")
    st.session_state["persona_editor_system_instructions"] = str(profile.get("system_instructions") or "")
    st.session_state["persona_editor_prompt"] = str(profile.get("prompt") or "")
    st.session_state["persona_editor_loaded_id"] = persona_id


def _active_persona_profile() -> Dict[str, str]:
    library = st.session_state.get("persona_library") or {}
    active_id = str(st.session_state.get("active_persona_id") or "").strip()
    profile = _sanitize_persona_profile(library.get(active_id) or {})
    return {
        "id": active_id,
        "name": str(profile.get("name") or "Neutral Operator"),
        "prompt": str(profile.get("prompt") or ""),
    }


def _compose_request_messages(messages: List[Dict[str, str]], persona_prompt: str) -> List[Dict[str, str]]:
    request_messages: List[Dict[str, str]] = []
    system_prompt = str(persona_prompt or "").strip()
    if system_prompt:
        request_messages.append({"role": "system", "content": system_prompt})

    for msg in messages:
        role = str(msg.get("role") or "").strip()
        content = str(msg.get("content") or "")
        if role in {"user", "assistant"} and content:
            request_messages.append({"role": role, "content": content})

    return request_messages


def _inject_design_system() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Fraunces:opsz,wght@9..144,500;9..144,700&family=JetBrains+Mono:wght@400;500&display=swap');

        :root {
            --bg-main: #eff2f5;
            --bg-card: #ffffff;
            --text-main: #0f172a;
            --text-subtle: #475569;
            --accent: #0b7285;
            --accent-strong: #0b4f5c;
            --accent-soft: #d7ecf2;
            --danger-soft: #ffe8df;
            --line: #ccd5e1;
            --ink-inverse: #f8fafc;
        }

        .stApp {
            background:
                radial-gradient(1200px 520px at 8% -10%, #d6e9f0 0%, transparent 58%),
                radial-gradient(920px 500px at 96% -18%, #efe2cf 0%, transparent 54%),
                var(--bg-main);
            color: var(--text-main);
            font-family: 'Manrope', sans-serif;
        }

        .block-container {
            padding-top: 1.05rem;
            max-width: 980px;
        }

        h1, h2, h3, .stMarkdown p {
            color: var(--text-main);
        }

        .app-shell {
            background: linear-gradient(148deg, #ffffff 0%, #f8fbff 100%);
            border: 1px solid var(--line);
            border-radius: 20px;
            padding: 1.08rem 1.15rem;
            margin-bottom: .85rem;
            box-shadow: 0 16px 40px rgba(13, 25, 43, 0.08);
        }

        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: .8rem;
            margin-bottom: .55rem;
        }

        .header-actions {
            margin-top: .1rem;
            margin-bottom: .55rem;
        }

        .brand-kicker {
            margin: 0;
            font-family: 'JetBrains Mono', monospace;
            font-size: .73rem;
            letter-spacing: .04em;
            color: #34506a;
            text-transform: uppercase;
        }

        .headline {
            margin: 0;
            font-family: 'Fraunces', serif;
            font-size: 1.5rem;
            font-weight: 700;
            letter-spacing: -0.015em;
        }

        .subline {
            margin: .35rem 0 0 0;
            color: var(--text-subtle);
            font-size: .92rem;
        }

        .chip {
            display: inline-block;
            border-radius: 999px;
            padding: .2rem .62rem;
            background: var(--accent-soft);
            color: var(--accent-strong);
            font-family: 'JetBrains Mono', monospace;
            font-size: .72rem;
            margin-right: .34rem;
            margin-top: .34rem;
            border: 1px solid #bae7df;
        }

        .status-row {
            display: flex;
            gap: .45rem;
            flex-wrap: wrap;
            margin-top: .72rem;
        }

        .status-pill {
            border: 1px solid var(--line);
            border-radius: 999px;
            padding: .24rem .62rem;
            background: #fff;
            font-family: 'JetBrains Mono', monospace;
            font-size: .72rem;
            box-shadow: 0 1px 0 rgba(18, 24, 38, 0.03);
        }

        .good {
            border-color: #97d7c8;
            background: #ecf9f6;
            color: #006357;
        }

        .warn {
            border-color: #f0d299;
            background: #fff6e6;
            color: #805300;
        }

        .bad {
            border-color: #f2b4a2;
            background: var(--danger-soft);
            color: #7f2f1f;
        }

        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #e9f0f6 0%, #e6edf4 100%);
            border-right: 1px solid var(--line);
        }

        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
        [data-testid="stSidebar"] label {
            color: #102236 !important;
        }

        [data-testid="stSidebar"] [data-baseweb="input"] {
            background: #f9fbfd;
            border-radius: 12px;
        }

        [data-testid="stSidebar"] [data-baseweb="select"] {
            border-radius: 12px;
        }

        .avatar-shell {
            border: 1px solid #b9c7d8;
            border-radius: 18px;
            overflow: hidden;
            background: radial-gradient(circle at 20% 20%, #f7feff 0%, #e7f1fb 45%, #e4ecf4 100%);
            margin-bottom: .65rem;
            box-shadow: 0 10px 24px rgba(20, 26, 40, 0.08);
        }

        .avatar-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: .55rem .68rem;
            border-bottom: 1px solid #c4d2e0;
            font-size: .73rem;
            color: #1f334b;
            font-family: 'JetBrains Mono', monospace;
            letter-spacing: .02em;
        }

        .avatar-dot {
            width: 9px;
            height: 9px;
            border-radius: 999px;
            background: #12b981;
            box-shadow: 0 0 0 0 rgba(18, 185, 129, 0.5);
            animation: pulseDot 1.8s infinite;
        }

        .avatar-body {
            min-height: 180px;
            display: grid;
            place-items: center;
            position: relative;
        }

        .avatar-ring {
            width: 86px;
            height: 86px;
            border-radius: 999px;
            border: 2px solid #7bd5c7;
            box-shadow: 0 0 0 0 rgba(72, 187, 165, 0.35);
            animation: ringBreath 2.2s infinite;
        }

        .avatar-label {
            position: absolute;
            bottom: 18px;
            font-size: .74rem;
            color: #223b56;
            font-family: 'JetBrains Mono', monospace;
        }

        .menu-note {
            font-size: .8rem;
            color: #4f647e;
            margin-top: .15rem;
            margin-bottom: .4rem;
        }

        /* Improve contrast for Streamlit top chrome (Deploy + main menu). */
        [data-testid="stHeader"] {
            background: rgba(246, 249, 252, 0.95) !important;
            border-bottom: 1px solid #c7d3e0 !important;
        }

        [data-testid="stHeader"] button,
        [data-testid="stHeader"] [role="button"] {
            background: #f8fafc !important;
            color: #0f172a !important;
            border: 1px solid #b7c4d4 !important;
            border-radius: 10px !important;
            font-weight: 700 !important;
        }

        /* Normalize Deploy-row controls to equal sizing and spacing. */
        [data-testid="stToolbar"] {
            display: flex !important;
            align-items: center !important;
            gap: 10px !important;
        }

        [data-testid="stToolbar"] > div {
            display: flex !important;
            align-items: center !important;
            justify-content: flex-end !important;
            gap: 10px !important;
            width: 100% !important;
        }

        [data-testid="stToolbar"] > div > div {
            display: flex !important;
            align-items: center !important;
            gap: 10px !important;
            margin: 0 !important;
            padding: 0 !important;
        }

        [data-testid="stToolbar"] button,
        [data-testid="stToolbar"] [role="button"],
        .apex-toolbar-btn {
            min-width: 112px !important;
            width: 112px !important;
            height: 34px !important;
            padding: 0 10px !important;
            display: inline-flex !important;
            align-items: center !important;
            justify-content: center !important;
            box-sizing: border-box !important;
        }

        [data-testid="stToolbar"] > * {
            margin: 0 !important;
        }

        [data-testid="stHeader"] button:hover,
        [data-testid="stHeader"] [role="button"]:hover {
            background: #eaf1f7 !important;
            color: #0b1320 !important;
            border-color: #8ea5bd !important;
        }

        [data-testid="stHeader"] button svg,
        [data-testid="stHeader"] [role="button"] svg {
            fill: #0f172a !important;
            color: #0f172a !important;
        }

        /* Force high-contrast action controls in header/chat/popover. */
        .stButton > button,
        [data-testid="stPopoverButton"] {
            background: #f8fafc !important;
            color: #0f172a !important;
            border: 1px solid #b7c4d4 !important;
            border-radius: 12px !important;
            font-weight: 700 !important;
        }

        .stButton > button:hover,
        [data-testid="stPopoverButton"]:hover {
            background: #eaf1f7 !important;
            border-color: #8ea5bd !important;
            color: #0b1320 !important;
        }

        .stButton > button:focus,
        [data-testid="stPopoverButton"]:focus {
            box-shadow: 0 0 0 2px rgba(11, 114, 133, 0.25) !important;
            outline: none !important;
        }

        [data-testid="stPopover"] {
            background: #fbfdff !important;
            border: 1px solid #c7d3e0 !important;
            border-radius: 14px !important;
        }

        [data-testid="stPopover"] p,
        [data-testid="stPopover"] label,
        [data-testid="stPopover"] span,
        [data-testid="stPopover"] div {
            color: #122033 !important;
        }

        [data-testid="stChatInput"] {
            border-top: 0;
            padding-top: .5rem;
        }

        /* Refined chat surface: remove playful icons, add modern bubble treatment. */
        [data-testid="stChatMessageAvatar"],
        [data-testid="stChatMessageAvatarAssistant"],
        [data-testid="stChatMessageAvatarUser"] {
            display: none !important;
        }

        [data-testid="stChatMessage"] {
            margin-bottom: 0.55rem !important;
        }

        [aria-label="Chat message from assistant"] [data-testid="stChatMessageContent"] {
            background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
            border: 1px solid #d2dce8;
            border-radius: 14px;
            padding: 0.72rem 0.86rem;
            box-shadow: 0 6px 14px rgba(15, 23, 42, 0.05);
        }

        [aria-label="Chat message from user"] {
            justify-content: flex-end !important;
        }

        [aria-label="Chat message from user"] [data-testid="stChatMessageContent"] {
            background: linear-gradient(180deg, #e8f4ff 0%, #dcedff 100%);
            border: 1px solid #bdd5ee;
            border-radius: 14px;
            padding: 0.72rem 0.86rem;
            box-shadow: 0 6px 14px rgba(11, 79, 92, 0.09);
            max-width: 78%;
            margin-left: auto;
        }

        [aria-label="Chat message from assistant"] [data-testid="stChatMessageContent"] p,
        [aria-label="Chat message from user"] [data-testid="stChatMessageContent"] p {
            font-size: 0.95rem;
            line-height: 1.45;
            margin: 0.1rem 0;
            color: #122033;
        }

        @keyframes pulseDot {
            0% { box-shadow: 0 0 0 0 rgba(18, 185, 129, 0.5); }
            70% { box-shadow: 0 0 0 8px rgba(18, 185, 129, 0); }
            100% { box-shadow: 0 0 0 0 rgba(18, 185, 129, 0); }
        }

        @keyframes ringBreath {
            0% { transform: scale(0.95); opacity: .65; }
            50% { transform: scale(1.03); opacity: 1; }
            100% { transform: scale(0.95); opacity: .65; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _render_avatar_holder() -> None:
    enabled = st.sidebar.checkbox("Enable live avatar", value=True, key="avatar_enabled")
    source = st.sidebar.selectbox(
        "Avatar source",
        options=["Placeholder", "WebRTC Embed", "Stream URL", "Image URL", "Generated (TTS + LivePortrait)"],
        index=0,
        key="avatar_source",
    )

    st.sidebar.markdown(
        """
        <div class='avatar-shell'>
          <div class='avatar-head'><span>LIVE AVATAR</span><span class='avatar-dot'></span></div>
          <div class='avatar-body'>
            <div class='avatar-ring'></div>
            <div class='avatar-label'>awaiting source</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not enabled:
        st.sidebar.caption("Avatar paused.")
        return

    if source == "WebRTC Embed":
        embed_url = st.sidebar.text_input(
            "WebRTC/Embed URL",
            value="",
            key="avatar_webrtc_url",
            placeholder="https://your-avatar-host/embed",
        )
        height = st.sidebar.slider("Embed height", min_value=180, max_value=520, value=280, step=20)
        if embed_url.strip():
            iframe = (
                "<iframe src='"
                + embed_url.strip().replace("'", "")
                + "' style='width:100%;height:"
                + str(height)
                + "px;border:0;border-radius:14px;background:#0f172a;' allow='camera; microphone; autoplay; fullscreen'></iframe>"
            )
            st.sidebar.markdown(iframe, unsafe_allow_html=True)
            st.sidebar.caption("Embedded avatar surface loaded.")
        else:
            st.sidebar.caption("Paste a WebRTC/embed URL to load the live avatar canvas.")
    elif source == "Stream URL":
        stream_url = st.sidebar.text_input("Stream URL", value="", key="avatar_stream_url")
        if stream_url.strip():
            st.sidebar.video(stream_url.strip())
        else:
            st.sidebar.caption("Add a stream URL to render a live avatar feed.")
    elif source == "Image URL":
        image_url = st.sidebar.text_input("Image URL", value="", key="avatar_image_url")
        if image_url.strip():
            st.sidebar.image(image_url.strip(), use_container_width=True)
        else:
            st.sidebar.caption("Add an image URL for an avatar portrait.")
    elif source == "Generated (TTS + LivePortrait)":
        st.sidebar.caption("Pipeline: Apex response -> TTS -> LivePortrait -> video")
        st.sidebar.checkbox("Auto-generate on assistant replies", value=False, key="avatar_auto_generate")
        st.sidebar.text_input("ComfyUI URL", value="http://127.0.0.1:8188", key="avatar_comfyui_url")
        st.sidebar.text_input(
            "Workflow JSON path",
            value="workflows/liveportrait_audio_template.json",
            key="avatar_workflow_path",
        )
        st.sidebar.text_input("Portrait image path", value="", key="avatar_portrait_image")
        st.sidebar.selectbox(
            "TTS backend",
            options=["piper", "stub"],
            index=0,
            key="avatar_tts_backend",
            help="Use 'stub' for testing without Piper installed.",
        )
        st.sidebar.text_input("Piper executable", value="", key="avatar_piper_exe")
        st.sidebar.text_input("Piper model", value="", key="avatar_piper_model")

        last_video = str(st.session_state.get("avatar_last_video") or "").strip()
        last_audio = str(st.session_state.get("avatar_last_audio") or "").strip()
        last_error = str(st.session_state.get("avatar_last_error") or "").strip()
        if last_error:
            st.sidebar.error(last_error)
        if last_video:
            st.sidebar.caption("Latest generated avatar clip")
            st.sidebar.video(last_video)
        if last_audio:
            st.sidebar.caption("Latest generated audio")
            st.sidebar.audio(last_audio)
        if not (last_video or last_audio or last_error):
            st.sidebar.caption("No generated clip yet. Ask the assistant a question to generate one.")
    else:
        st.sidebar.caption("Placeholder mode active. Switch source to stream or image when ready.")


def _inject_deploy_row_actions() -> None:
    components.html(
        """
        <script>
        (function() {
            const doc = window.parent.document;
            const toolbar = doc.querySelector('[data-testid="stToolbar"]');
            if (!toolbar) return;

            let host = doc.getElementById('apex-top-actions');
            if (!host) {
                host = doc.createElement('div');
                host.id = 'apex-top-actions';
                toolbar.prepend(host);
            }

            host.style.position = 'relative';
            host.style.display = 'flex';
            host.style.gap = '10px';
            host.style.alignItems = 'center';
            host.style.marginRight = '0';
            host.style.justifyContent = 'flex-end';
            host.style.pointerEvents = 'auto';
            host.style.zIndex = '10000';

            host.innerHTML = `
                <button id="apex-new-session-btn" class="apex-toolbar-btn">New Session</button>
                <button id="apex-menu-btn" class="apex-toolbar-btn">Menu</button>
            `;

            function findButtonByText(label) {
                return [...doc.querySelectorAll('button')].find(
                    (b) => ((b.textContent || '').trim() === label)
                );
            }

            function hideProxy(label) {
                const btn = findButtonByText(label);
                if (!btn) return;
                const wrap = btn.closest('[data-testid="stButton"]');
                if (wrap) {
                    wrap.style.display = 'none';
                } else {
                    btn.style.display = 'none';
                }
            }

            function hideAllProxyButtons() {
                const proxyButtons = [...doc.querySelectorAll('button')].filter(
                    (b) => ((b.textContent || '').trim().startsWith('Proxy::'))
                );
                for (const btn of proxyButtons) {
                    let node = btn;
                    for (let i = 0; i < 8 && node; i += 1) {
                        if (node.getAttribute && node.getAttribute('data-testid') === 'stElementContainer') {
                            node.style.display = 'none';
                            break;
                        }
                        node = node.parentElement;
                    }
                    btn.style.display = 'none';
                }
            }

            hideProxy('Proxy::NewSession');
            hideProxy('Proxy::ToggleMenu');
            hideAllProxyButtons();

            const newBtn = doc.getElementById('apex-new-session-btn');
            const menuBtn = doc.getElementById('apex-menu-btn');
            if (newBtn) {
                newBtn.onclick = () => {
                    const proxy = findButtonByText('Proxy::NewSession');
                    if (proxy) proxy.click();
                };
            }
            if (menuBtn) {
                menuBtn.onclick = () => {
                    const proxy = findButtonByText('Proxy::ToggleMenu');
                    if (proxy) proxy.click();
                };
            }

            const liveButtons = [...toolbar.querySelectorAll('button')].filter((b) => {
                const text = ((b.textContent || '').trim());
                const isInjected = b.id === 'apex-new-session-btn' || b.id === 'apex-menu-btn';
                const isProxy = text === 'Proxy::NewSession' || text === 'Proxy::ToggleMenu';
                return !isInjected && !isProxy;
            });

            for (const btn of liveButtons) {
                if (!host.contains(btn)) {
                    host.appendChild(btn);
                }
            }
        })();
        </script>
        """,
        height=0,
        width=0,
    )


def _build_headers(cfg: SovereignConfig) -> Dict[str, str]:
    headers = {
        "x-tenant-id": cfg.tenant_id,
        "x-session-id": cfg.session_id,
        "x-device-id": cfg.device_id,
        "x-request-id": str(uuid.uuid4()),
    }
    if cfg.bearer_token:
        headers["Authorization"] = f"Bearer {cfg.bearer_token}"
    return headers


def _check_endpoint(base_url: str, path: str, timeout: float) -> Tuple[Optional[int], str]:
    url = f"{base_url.rstrip('/')}{path}"
    try:
        resp = requests.get(url, timeout=timeout)
        return resp.status_code, (resp.text or "")[:400]
    except Exception as exc:
        return None, str(exc)


def _call_stream(cfg: SovereignConfig, messages: List[Dict[str, str]]) -> Tuple[bool, str, int]:
    url = f"{cfg.base_url.rstrip('/')}/v1/stream"
    payload = {
        "model": cfg.model,
        "messages": messages,
        "stream": True,
    }
    headers = _build_headers(cfg)

    try:
        with requests.post(
            url,
            json=payload,
            headers=headers,
            stream=True,
            timeout=cfg.timeout_seconds,
        ) as resp:
            text_parts: List[str] = []
            for chunk in resp.iter_content(chunk_size=None):
                if not chunk:
                    continue
                text_parts.append(chunk.decode("utf-8", errors="ignore"))
            body = "".join(text_parts)
            if resp.status_code >= 400:
                return False, body or resp.text or "Request failed", resp.status_code
            return True, body, resp.status_code
    except Exception as exc:
        return False, str(exc), 0


def _extract_structured_error(text: str) -> Optional[Dict[str, Any]]:
    raw = (text or "").strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    err = parsed.get("error")
    if isinstance(err, dict):
        return err
    return None


def _status_class(code: Optional[int], path: str) -> str:
    if code is None:
        return "status-bad"
    if path == "/healthz":
        return "status-good" if code == 200 else "status-bad"
    if code == 200:
        return "status-good"
    if code in {401, 403, 422, 503}:
        return "status-warn"
    return "status-bad"


def _status_label(code: Optional[int]) -> str:
    return "UNREACHABLE" if code is None else str(code)


def _status_pill_class(path: str, code: Optional[int]) -> str:
    return f"status-pill {_status_class(code, path).replace('status-', '')}"


def _render_sidebar() -> SovereignConfig:
    _ensure_persona_state()
    _render_avatar_holder()
    st.sidebar.markdown("---")
    tenant_id = st.sidebar.text_input("Tenant", value=_default_tenant_id())
    default_session = st.session_state.setdefault("session_id", f"session-{uuid.uuid4().hex[:8]}")
    session_id = st.sidebar.text_input("Session ID", value=default_session)
    model = st.sidebar.text_input("Model", value=_default_model_name())
    active_persona = _active_persona_profile()
    st.sidebar.caption(f"Active persona: {active_persona['name']}")

    with st.sidebar.expander("Connection", expanded=False):
        base_url = st.text_input("Base URL", value=_default_base_url())
        device_id = st.text_input("Device ID", value="sovereign-console-ui")
        bearer_token = st.text_input("Bearer Token", value="", type="password")
        timeout_seconds = st.slider("Request timeout (seconds)", min_value=5, max_value=120, value=45)

    with st.sidebar.expander("Developer subsystem", expanded=False):
        st.caption("Observability")
        for path in ("/healthz", "/readyz", "/governance_status"):
            code, body = _check_endpoint(base_url, path, timeout=4.0)
            st.caption(f"{path}: {_status_label(code)}")
            if st.checkbox(f"Show {path}", key=f"show_body_{path}"):
                st.code(body or "<empty>", language="json")

        st.caption("Transport details")
        preview_headers: Dict[str, str] = {
            "x-tenant-id": tenant_id,
            "x-session-id": session_id,
            "x-device-id": device_id,
            "x-request-id": "<generated-per-request>",
        }
        if bearer_token:
            preview_headers["Authorization"] = "Bearer ***"
        st.code(json.dumps(preview_headers, indent=2), language="json")

    return SovereignConfig(
        base_url=base_url,
        tenant_id=tenant_id,
        session_id=session_id,
        device_id=device_id,
        bearer_token=bearer_token,
        model=model,
        timeout_seconds=float(timeout_seconds),
        persona_name=active_persona["name"],
        persona_prompt=active_persona["prompt"],
    )


def _render_header(cfg: SovereignConfig) -> None:
    checks = [
        ("/healthz",) + _check_endpoint(cfg.base_url, "/healthz", timeout=2.5),
        ("/readyz",) + _check_endpoint(cfg.base_url, "/readyz", timeout=2.5),
        ("/governance_status",) + _check_endpoint(cfg.base_url, "/governance_status", timeout=2.5),
    ]
    st.markdown("<div class='header-actions'></div>", unsafe_allow_html=True)
    proxy_cols = st.columns([1, 1, 8])
    with proxy_cols[0]:
        if st.button("Proxy::NewSession", key="proxy_new_session"):
            st.session_state["messages"] = [{"role": "assistant", "content": "New session started."}]
            st.rerun()
    with proxy_cols[1]:
        if st.button("Proxy::ToggleMenu", key="proxy_toggle_menu"):
            current = bool(st.session_state.get("show_top_menu", False))
            st.session_state["show_top_menu"] = not current
            st.rerun()

    if bool(st.session_state.get("show_top_menu", False)):
        with st.container(border=True):
            st.markdown("<p class='menu-note'>Quick controls</p>", unsafe_allow_html=True)
            menu_cols = st.columns([1.5, 1.5, 5])
            with menu_cols[0]:
                if st.button("Copy transport headers", use_container_width=True, key="menu_copy_headers"):
                    st.code(json.dumps(_build_headers(cfg), indent=2), language="json")
            with menu_cols[1]:
                if st.button("Close menu", use_container_width=True, key="menu_close_panel"):
                    st.session_state["show_top_menu"] = False
                    st.rerun()

            st.markdown("<p class='menu-note'>Persona Studio</p>", unsafe_allow_html=True)
            library = st.session_state.get("persona_library") or {}
            persona_ids = list(library.keys())
            editor_id = st.selectbox(
                "Persona profile",
                options=persona_ids,
                format_func=lambda persona_id: str((library.get(persona_id) or {}).get("name") or persona_id),
                key="persona_editor_id",
            )
            if str(st.session_state.get("persona_editor_loaded_id") or "") != editor_id:
                _sync_persona_editor_from_library(editor_id)

            st.text_input("Persona name", key="persona_editor_name")
            persona_form_cols = st.columns([1, 1])
            with persona_form_cols[0]:
                st.text_input("Role", key="persona_editor_role")
                st.text_input("Tone", key="persona_editor_tone")
                st.text_input("Style", key="persona_editor_style")
            with persona_form_cols[1]:
                st.text_area("Primary goals", key="persona_editor_goals", height=110)
                st.text_area("Facts and context", key="persona_editor_domain_facts", height=110)
                st.text_area("Behavior boundaries", key="persona_editor_guardrails", height=110)
            st.text_area("Additional instructions", key="persona_editor_system_instructions", height=110)

            generated_prompt = _build_persona_prompt(
                {
                    "role": str(st.session_state.get("persona_editor_role") or ""),
                    "tone": str(st.session_state.get("persona_editor_tone") or ""),
                    "style": str(st.session_state.get("persona_editor_style") or ""),
                    "goals": str(st.session_state.get("persona_editor_goals") or ""),
                    "domain_facts": str(st.session_state.get("persona_editor_domain_facts") or ""),
                    "guardrails": str(st.session_state.get("persona_editor_guardrails") or ""),
                    "system_instructions": str(st.session_state.get("persona_editor_system_instructions") or ""),
                }
            )
            st.text_area("Compiled system prompt preview", value=generated_prompt, height=170, disabled=True)

            persona_action_cols = st.columns([1.3, 1.3, 1.3, 1.3, 1.6])
            with persona_action_cols[0]:
                if st.button("Use persona", use_container_width=True, key="menu_use_persona"):
                    st.session_state["active_persona_id"] = editor_id
                    st.rerun()
            with persona_action_cols[1]:
                if st.button("Save changes", use_container_width=True, key="menu_save_persona"):
                    profile = _sanitize_persona_profile(
                        {
                            "name": str(st.session_state.get("persona_editor_name") or "").strip() or "Custom Persona",
                            "role": str(st.session_state.get("persona_editor_role") or ""),
                            "tone": str(st.session_state.get("persona_editor_tone") or ""),
                            "style": str(st.session_state.get("persona_editor_style") or ""),
                            "goals": str(st.session_state.get("persona_editor_goals") or ""),
                            "domain_facts": str(st.session_state.get("persona_editor_domain_facts") or ""),
                            "guardrails": str(st.session_state.get("persona_editor_guardrails") or ""),
                            "system_instructions": str(st.session_state.get("persona_editor_system_instructions") or ""),
                            "prompt": generated_prompt,
                        }
                    )
                    library[editor_id] = profile
                    st.session_state["persona_library"] = library
                    _save_persona_library(library)
                    if st.session_state.get("active_persona_id") == editor_id:
                        st.rerun()
            with persona_action_cols[2]:
                if st.button("New persona", use_container_width=True, key="menu_new_persona"):
                    new_id = f"persona-{uuid.uuid4().hex[:8]}"
                    library[new_id] = _sanitize_persona_profile({"name": "New Persona"})
                    st.session_state["persona_library"] = library
                    _save_persona_library(library)
                    st.session_state["persona_editor_id"] = new_id
                    _sync_persona_editor_from_library(new_id)
                    st.rerun()
            with persona_action_cols[3]:
                disable_delete = len(persona_ids) <= 1
                if st.button(
                    "Delete persona",
                    use_container_width=True,
                    key="menu_delete_persona",
                    disabled=disable_delete,
                ):
                    if editor_id in library and len(library) > 1:
                        del library[editor_id]
                        st.session_state["persona_library"] = library
                        _save_persona_library(library)
                        replacement = next(iter(library.keys()))
                        if st.session_state.get("active_persona_id") == editor_id:
                            st.session_state["active_persona_id"] = replacement
                        st.session_state["persona_editor_id"] = replacement
                        _sync_persona_editor_from_library(replacement)
                        st.rerun()
            with persona_action_cols[4]:
                if st.button("Build persona in chat", use_container_width=True, key="menu_build_persona_chat"):
                    _start_persona_builder()
                    st.session_state["show_top_menu"] = False
                    st.rerun()

            show_runtime = st.checkbox("Show runtime status", value=False, key="menu_show_runtime")
            if show_runtime:
                st.markdown(
                    (
                        f"<span class='chip'>tenant:{cfg.tenant_id}</span>"
                        f"<span class='chip'>session:{cfg.session_id}</span>"
                        f"<span class='chip'>model:{cfg.model}</span>"
                        f"<span class='chip'>persona:{cfg.persona_name}</span>"
                    ),
                    unsafe_allow_html=True,
                )
                pills = []
                for path, code, _ in checks:
                    pills.append(f"<span class='{_status_pill_class(path, code)}'>{path}:{_status_label(code)}</span>")
                st.markdown(f"<div class='status-row'>{''.join(pills)}</div>", unsafe_allow_html=True)

        st.caption("Apex Sovereign")


def _render_chat(cfg: SovereignConfig) -> None:
    messages: List[Dict[str, str]] = st.session_state.setdefault(
        "messages",
        [
            {
                "role": "assistant",
                "content": "Console online. Send a prompt when ready.",
            }
        ],
    )

    st.caption("Conversation")

    for msg in messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    builder_active = bool(st.session_state.get("persona_builder_active", False))
    prompt = st.chat_input(
        "Answer the persona builder question..."
        if builder_active
        else "Send a governed prompt..."
    )
    if not prompt:
        return

    messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        if builder_active:
            reply = _handle_persona_builder_turn(prompt)
            st.markdown(reply)
            messages.append({"role": "assistant", "content": reply})
        else:
            with st.spinner("Streaming through Sovereign..."):
                request_messages = _compose_request_messages(messages, cfg.persona_prompt)
                ok, text, status = _call_stream(cfg, request_messages)

            if ok:
                structured_error = _extract_structured_error(text)
                if structured_error is not None:
                    st.warning("Sovereign returned a structured stream error payload.")
                    st.code(json.dumps(structured_error, indent=2), language="json")
                    messages.append({"role": "assistant", "content": f"Error payload:\n```json\n{json.dumps(structured_error, indent=2)}\n```"})
                else:
                    st.markdown(text)
                    messages.append({"role": "assistant", "content": text})
                    avatar_error = _maybe_generate_avatar_response(text, cfg)
                    if avatar_error:
                        st.info(avatar_error)
            else:
                st.error(f"Sovereign request failed (status={status or 'n/a'})")
                st.code(text or "<empty error>")


def _render_transport_panel(cfg: SovereignConfig) -> None:
    st.subheader("Transport")
    headers = _build_headers(cfg)
    st.code(json.dumps(headers, indent=2), language="json")
    st.caption("Header preview for the current request context.")


def main() -> None:
    st.set_page_config(page_title="Sovereign Chat Console", layout="wide")
    _inject_design_system()
    _ensure_persona_state()
    cfg = _render_sidebar()
    _render_header(cfg)
    _inject_deploy_row_actions()
    _render_chat(cfg)


if __name__ == "__main__":
    main()
