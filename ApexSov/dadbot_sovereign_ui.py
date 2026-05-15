from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
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
        options=["Placeholder", "WebRTC Embed", "Stream URL", "Image URL"],
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
    _render_avatar_holder()
    st.sidebar.markdown("---")
    tenant_id = st.sidebar.text_input("Tenant", value=_default_tenant_id())
    default_session = st.session_state.setdefault("session_id", f"session-{uuid.uuid4().hex[:8]}")
    session_id = st.sidebar.text_input("Session ID", value=default_session)
    model = st.sidebar.text_input("Model", value=_default_model_name())

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
            show_runtime = st.checkbox("Show runtime status", value=False, key="menu_show_runtime")
            if show_runtime:
                st.markdown(
                    (
                        f"<span class='chip'>tenant:{cfg.tenant_id}</span>"
                        f"<span class='chip'>session:{cfg.session_id}</span>"
                        f"<span class='chip'>model:{cfg.model}</span>"
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

    prompt = st.chat_input("Send a governed prompt...")
    if not prompt:
        return

    messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        with st.spinner("Streaming through Sovereign..."):
            ok, text, status = _call_stream(cfg, messages)

        if ok:
            structured_error = _extract_structured_error(text)
            if structured_error is not None:
                st.warning("Sovereign returned a structured stream error payload.")
                st.code(json.dumps(structured_error, indent=2), language="json")
                messages.append({"role": "assistant", "content": f"Error payload:\n```json\n{json.dumps(structured_error, indent=2)}\n```"})
            else:
                st.markdown(text)
                messages.append({"role": "assistant", "content": text})
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
    cfg = _render_sidebar()
    _render_header(cfg)
    _inject_deploy_row_actions()
    _render_chat(cfg)


if __name__ == "__main__":
    main()
