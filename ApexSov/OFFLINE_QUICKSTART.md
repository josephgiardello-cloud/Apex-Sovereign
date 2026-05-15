# Offline Quickstart

This runbook starts Apex Sovereign with local-first defaults using existing project code.

## 1) Start dependencies

1. Start Redis on localhost:6379.
2. Start an OpenAI-compatible local model server on localhost.

Example with Ollama:

```powershell
ollama serve
.
\setup_ollama_qwen.ps1
```

This pulls `qwen2.5:7b`, creates the stable `apex-qwen` alias, and lists the resulting local models.

## 2) Configure offline profile

1. Duplicate `.env.offline.example` to `.env.offline`.
2. Edit values if your local ports differ.

Required keys:

- `APEX_REDIS_URL`
- `APEX_OPENAI_URL`
- `APEX_UPSTREAM_PROVIDERS_JSON`
- `APEX_DRIFT_BACKEND` (`redis` is easiest local mode)
- `APEX_NO_INTERNET=true`

## 3) Launch offline runtime

From the `ApexSov` folder:

Optional contract verification before launch:

```powershell
py -3 verify_chimera.py
```

```powershell
py -3 run_offline.py --host 127.0.0.1 --port 8000
```

Dev reload mode:

```powershell
py -3 run_offline.py --reload
```

Run launcher with built-in Chimera verification:

```powershell
py -3 run_offline.py --verify-chimera
```

The launcher loads `.env.offline` if present, applies safe local defaults, then starts `BaseT8:app`.

One-command bootstrap (preflight + startup + readiness gate):

```powershell
py -3 bootstrap_offline.py
```

Bootstrap now runs Chimera verification by default before preflight.

Bootstrap with dev reload:

```powershell
py -3 bootstrap_offline.py --reload
```

Skip contract verification only for local debugging:

```powershell
py -3 bootstrap_offline.py --skip-chimera-verify
```

## 3.1) Run preflight manually

Dependency checks only (Redis + local model server):

```powershell
py -3 preflight_offline.py
```

Dependency checks plus Apex endpoint checks:

```powershell
py -3 preflight_offline.py --check-apex --apex-url http://127.0.0.1:8000
```

## 4) Validate

- Liveness: `GET /healthz`
- Readiness: `GET /readyz`
- Governance status: `GET /governance_status`

## 5) Notes

- Public upstream endpoints still require `OPENAI_API_KEY`.
- Local endpoints can run without an API key.
- Recommended local model id for Apex clients/UI: `apex-qwen`
- If you enable vector drift with Qdrant, set `APEX_DRIFT_BACKEND=vector` and configure Qdrant env vars.
