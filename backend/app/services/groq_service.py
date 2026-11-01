"""
Groq LLM Service for NetCoop AI.
Enriches deterministic diagnostic findings with deep contextual reasoning,
root cause analysis, and production remediation steps using Llama-3.3-70B on Groq.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from typing import Any, Optional
from app.core.config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are NetCoop AI, an expert Network Reliability Engineer and Network Architect.
Your role is to analyze multi-agent diagnostic findings, real telemetry metrics, and topology evidence to generate:
1. A concise, authoritative Executive Summary of network health and identified incidents.
2. In-depth technical Root Cause Analysis explaining the physical/logical mechanisms behind observed telemetry anomalies.
3. Concrete, production-grade Remediation Recommendations and step-by-step verification commands (e.g. Cisco IOS/Linux CLI checks).

Always ground your analysis strictly in the provided evidence without hallucinating unobserved faults.
Return your output formatted as valid JSON matching the requested structure.
"""

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

# Tracks which model last succeeded so the UI can display it.
last_model_used: Optional[str] = None


def _candidate_models() -> list[str]:
    models = [settings.groq_model.strip()]
    models += [m.strip() for m in settings.groq_fallback_models.split(",") if m.strip()]
    return list(dict.fromkeys(m for m in models if m))


def _post_chat(api_key: str, payload: dict[str, Any]) -> dict[str, Any]:
    req = urllib.request.Request(
        GROQ_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "NetCoop-AI-Diagnostic/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=45) as resp:
        return json.loads(resp.read().decode("utf-8"))


def call_groq_llm(
    prompt: str,
    system_instruction: str = SYSTEM_PROMPT,
    temperature: float = 0.2,
    max_tokens: int = 4000,
) -> Optional[str]:
    """
    Invokes the Groq API (stdlib HTTP only). Tries the configured model first and
    falls back through GROQ_FALLBACK_MODELS when a model is retired/unavailable.
    """
    global last_model_used
    api_key = settings.groq_api_key.strip()
    if not api_key:
        print("[GROQ WARNING] GROQ_API_KEY is empty in settings! Check backend/.env")
        return None

    for model in _candidate_models():
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }
        print(f"[GROQ] Requesting model '{model}' (key {api_key[:8]}...)")
        try:
            try:
                data = _post_chat(api_key, payload)
            except urllib.error.HTTPError as http_err:
                # Some models reject response_format; retry once without it.
                if http_err.code == 400:
                    payload.pop("response_format", None)
                    data = _post_chat(api_key, payload)
                else:
                    raise
            content = data["choices"][0]["message"].get("content") or ""
            if not content.strip():
                print(f"[GROQ] Model '{model}' returned empty content; trying next.")
                continue
            last_model_used = model
            print(f"[GROQ] Success with model '{model}'.")
            return content
        except urllib.error.HTTPError as http_err:
            body = http_err.read().decode("utf-8") if http_err.fp else ""
            print(f"[GROQ ERROR] {model}: HTTP {http_err.code} {body[:300]}")
            if http_err.code in (401, 403):
                return None  # bad key - no point trying other models
            continue  # 404 model_not_found, 429 rate limit, 5xx -> try next model
        except Exception as exc:  # noqa: BLE001
            print(f"[GROQ ERROR] {model}: {exc}")
            continue

    print("[GROQ] All candidate models failed; using deterministic analysis only.")
    return None


def _parse_json_loose(text: str) -> Optional[dict[str, Any]]:
    """Parses JSON even if the model wrapped it in prose or ``` fences."""
    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except Exception:  # noqa: BLE001
            return None
    return None


def _compact_findings(findings: list[dict[str, Any]], limit: int = 6) -> list[dict[str, Any]]:
    """Strips UUIDs/timestamps/nesting so the prompt fits free-tier token limits."""
    out = []
    for f in findings[:limit]:
        out.append({
            "code": f.get("finding_code"),
            "severity": f.get("severity"),
            "confidence": f.get("confidence"),
            "summary": f.get("summary"),
            "devices": f.get("affected_devices", [])[:5],
            "evidence": [
                {
                    "metric": e.get("metric_name"),
                    "value": e.get("observed_value"),
                    "unit": e.get("unit"),
                    "expected": e.get("expected_value"),
                    "device": e.get("device_id"),
                }
                for e in (f.get("evidence") or [])[:4]
            ],
        })
    return out


def _compact_telemetry(telemetry: Any, max_chars: int = 3500) -> str:
    text = json.dumps(telemetry, separators=(",", ":"), default=str)
    return text if len(text) <= max_chars else text[:max_chars] + "...(truncated)"


def enrich_diagnosis_with_groq(
    telemetry: list[dict[str, Any]],
    deterministic_findings: list[dict[str, Any]],
    raw_status: str,
    raw_severity: str
) -> Optional[dict[str, Any]]:
    """
    Submits deterministic evidence to the Groq LLM to enrich the
    executive summary, root cause explanations, and operator verification commands.
    """
    prompt = f"""Analyze these network telemetry observations and multi-agent diagnostic findings.

TELEMETRY (compact JSON):
{_compact_telemetry(telemetry)}

AGENT FINDINGS (compact JSON):
{json.dumps(_compact_findings(deterministic_findings), separators=(",", ":"), default=str)}

CURRENT DIAGNOSIS STATUS: {raw_status}
CURRENT OVERALL SEVERITY: {raw_severity}

Respond ONLY with a JSON object with these keys (max 3 remediation actions, be concise):
{{
  "ai_executive_summary": "High-level assessment of network condition and impact",
  "ai_root_cause_explanation": "Engineering breakdown of why this occurred based on metrics",
  "remediation_actions": [
    {{
      "title": "Short title",
      "action": "Concrete command or configuration change",
      "verification_steps": ["step 1", "step 2"],
      "rationale": "Why this fixes the fault"
    }}
  ]
}}
"""
    result_text = call_groq_llm(prompt, max_tokens=2000)
    if not result_text:
        return None

    parsed = _parse_json_loose(result_text)
    if parsed is None:
        logger.error("Failed to parse Groq response JSON.")
        return None
    parsed["model_used"] = last_model_used
    return parsed
