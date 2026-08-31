"""Optional LLM analyst layer.

This is the *last* stage of NEMOS and the least authoritative. It does not
detect anything. Detection has already happened by the time this module runs;
its only job is to explain findings NEMOS already made, in prose, to a human.

The ordering matters and is deliberate. An LLM asked "is this traffic
malicious?" will answer, fluently and often wrongly, because that is what
generating text does. NEMOS never asks it that. It receives an evidence bundle
that deterministic rules, a statistical baseline and an Isolation Forest have
already produced, and it is asked only to summarise what is there.

Three properties keep this from becoming the weakest link:

**Evidence in, prose out.** The prompt carries a JSON bundle and an explicit
instruction to use nothing else. The model has no tools, no network access
beyond the single provider call, and no ability to query NEMOS.

**Responses are inspected, not trusted.** Every IP address and technique ID in
the response is checked against the evidence bundle. If the model invented one,
the response is rejected rather than shown -- an analyst acting on a fabricated
address is worse off than one who got no summary at all.

**Absence is normal.** No provider configured is the default state, not an
error. Every other layer works exactly the same without it.

Enable with ``NEMOS_LLM_PROVIDER`` plus the provider's API key. Nothing is sent
anywhere until you do.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from collections.abc import Mapping

log = logging.getLogger(__name__)

#: Supported providers and their endpoints. The host is fixed per provider so a
#: misconfigured environment cannot redirect evidence to an arbitrary server.
PROVIDERS = {
    "anthropic": {
        "url": "https://api.anthropic.com/v1/messages",
        "key_env": "ANTHROPIC_API_KEY",
        "default_model": "claude-sonnet-4-5",
    },
    "openai": {
        "url": "https://api.openai.com/v1/chat/completions",
        "key_env": "OPENAI_API_KEY",
        "default_model": "gpt-4o-mini",
    },
    "ollama": {
        # Local models. Loopback only -- see _validate_ollama_url.
        "url": "http://127.0.0.1:11434/api/chat",
        "key_env": "",
        "default_model": "llama3.1",
    },
}

MAX_EVIDENCE_BYTES = 24_000
MAX_RESPONSE_CHARS = 4_000

SYSTEM_PROMPT = """You are assisting a network security analyst using NEMOS, a \
defensive network monitoring tool.

You will receive a JSON evidence bundle produced by NEMOS. Your job is to \
explain what it contains, in plain language, for an analyst deciding what to \
investigate next.

Rules you must follow:

1. Use ONLY the information in the evidence bundle. You have no other source.
2. Never invent an IP address, port, hostname, timestamp, technique ID, malware \
name, tool name, threat-actor name or numeric value. If it is not in the \
bundle, it does not exist.
3. Do not assert that an attack occurred. NEMOS observes traffic patterns, not \
intent. Say "consistent with", "resembles", or "the evidence shows".
4. If the evidence is insufficient to answer, say so plainly. That is a correct \
and useful answer.
5. A risk score is analyst triage priority, not a probability of compromise. An \
anomaly score means traffic is statistically unusual, not that it is hostile.
6. Recommend investigation steps, never containment actions. NEMOS does not act \
on the network and neither should your advice assume someone will.

Be concise. Prefer four short paragraphs over a long essay."""


class AnalystUnavailable(RuntimeError):
    """Raised when no provider is configured, or the call cannot be made."""


@dataclass(frozen=True, slots=True)
class AnalystConfig:
    provider: str = ""
    model: str = ""
    api_key: str = ""
    base_url: str = ""
    timeout: float = 30.0
    max_tokens: int = 800

    @property
    def configured(self) -> bool:
        return bool(self.provider and self.base_url)

    @classmethod
    def from_env(cls) -> AnalystConfig:
        provider = os.getenv("NEMOS_LLM_PROVIDER", "").strip().lower()
        if not provider:
            return cls()
        spec = PROVIDERS.get(provider)
        if spec is None:
            log.error(
                "unknown NEMOS_LLM_PROVIDER %r; known providers: %s",
                provider, ", ".join(sorted(PROVIDERS)),
            )
            return cls()
        key = os.getenv(spec["key_env"], "").strip() if spec["key_env"] else ""
        if spec["key_env"] and not key:
            log.error(
                "NEMOS_LLM_PROVIDER=%s requires %s to be set; AI analyst disabled",
                provider, spec["key_env"],
            )
            return cls()

        base_url = os.getenv("NEMOS_LLM_URL", "").strip() or spec["url"]
        if provider == "ollama" and not _validate_ollama_url(base_url):
            log.error(
                "NEMOS_LLM_URL for ollama must point at a loopback address; AI analyst disabled"
            )
            return cls()
        if provider != "ollama" and base_url != spec["url"]:
            # Redirecting a hosted provider elsewhere would send evidence about
            # the monitored network to an unintended endpoint.
            log.error("NEMOS_LLM_URL cannot override the endpoint for %s; AI analyst disabled", provider)
            return cls()

        try:
            timeout = float(os.getenv("NEMOS_LLM_TIMEOUT", "30"))
        except ValueError:
            timeout = 30.0
        return cls(
            provider=provider,
            model=os.getenv("NEMOS_LLM_MODEL", "").strip() or spec["default_model"],
            api_key=key,
            base_url=base_url,
            timeout=max(1.0, min(120.0, timeout)),
        )


def _validate_ollama_url(url: str) -> bool:
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    host = (parts.hostname or "").strip("[]")
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def collect_evidence(incident: Mapping[str, Any] | None = None,
                     alerts: list[Mapping[str, Any]] | None = None,
                     assessment: Mapping[str, Any] | None = None,
                     baseline: Mapping[str, Any] | None = None,
                     flows: list[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Assemble the bundle the model is allowed to see.

    Only NEMOS-produced facts go in. Flows are truncated because a bundle large
    enough to exceed the context window would be silently cut somewhere
    arbitrary, and a model reasoning over half a bundle it thinks is whole is
    exactly the failure mode this design exists to avoid.
    """
    bundle: dict[str, Any] = {
        "produced_by": "NEMOS",
        "note": (
            "Every fact available is in this object. Nothing may be added from "
            "outside it."
        ),
    }
    if incident is not None:
        bundle["incident"] = dict(incident)
    if assessment is not None:
        bundle["assessment"] = dict(assessment)
    if baseline is not None:
        bundle["host_baseline"] = dict(baseline)
    if alerts:
        bundle["alerts"] = [dict(a) for a in alerts[:25]]
    if flows:
        bundle["flows"] = [dict(f) for f in flows[:40]]
        bundle["flow_note"] = (
            "Flows are unidirectional: source -> destination as observed. "
            f"Showing {min(len(flows), 40)} of {len(flows)}."
        )
    return bundle


def extract_referenced_facts(bundle: Mapping[str, Any]) -> tuple[set[str], set[str]]:
    """Return every IP address and ATT&CK technique the bundle actually contains."""
    text = json.dumps(bundle)
    addresses = set()
    for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            ipaddress.ip_address(candidate)
            addresses.add(candidate)
        except ValueError:
            continue
    techniques = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text))
    return addresses, techniques


def verify_response(answer: str, bundle: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """Check that the response invents no addresses or technique IDs.

    Deliberately narrow. It cannot catch every fabrication -- a model can still
    write a plausible wrong sentence about real evidence -- but addresses and
    technique IDs are the facts an analyst would act on directly, and they are
    exactly checkable.
    """
    known_addresses, known_techniques = extract_referenced_facts(bundle)
    problems = []

    for candidate in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", answer)):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate not in known_addresses:
            problems.append(f"response contains an IP address not present in the evidence: {candidate}")

    for technique in set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", answer)):
        if technique not in known_techniques:
            problems.append(f"response contains an ATT&CK technique not in the evidence: {technique}")

    return (not problems), problems


class Analyst:
    """Optional LLM explanation layer. Never required for detection."""

    def __init__(self, config: AnalystConfig | None = None, *, transport=None):
        self.config = config or AnalystConfig()
        self._transport = transport
        self._lock = threading.Lock()
        self.requests = 0
        self.failures = 0
        self.rejected = 0
        self.last_error = ""

    @property
    def available(self) -> bool:
        return self.config.configured

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "available": self.available,
                "provider": self.config.provider or None,
                "model": self.config.model or None,
                "reason": None if self.available else (
                    "no LLM provider configured (set NEMOS_LLM_PROVIDER); NEMOS "
                    "detection is unaffected"
                ),
                "requests": self.requests,
                "failures": self.failures,
                "rejected_for_unverifiable_claims": self.rejected,
                "last_error": self.last_error,
                "role": (
                    "Explains findings NEMOS has already made. It performs no "
                    "detection and cannot influence a risk score."
                ),
            }

    def explain(self, question: str, bundle: Mapping[str, Any]) -> dict[str, Any]:
        """Answer a question about an evidence bundle.

        Raises ``AnalystUnavailable`` when no provider is configured. Any
        provider or verification failure is returned as a structured result
        rather than an exception, so a caller can always render something.
        """
        if not self.available:
            raise AnalystUnavailable(
                "no LLM provider configured; set NEMOS_LLM_PROVIDER to enable the "
                "optional AI analyst. NEMOS detection does not require it."
            )

        payload = json.dumps(bundle, separators=(",", ":"), default=str)
        if len(payload.encode("utf-8")) > MAX_EVIDENCE_BYTES:
            return {
                "ok": False,
                "error": "evidence bundle too large to summarise",
                "detail": f"bundle exceeds {MAX_EVIDENCE_BYTES} bytes; narrow the request",
            }

        prompt = (
            f"Evidence bundle:\n```json\n{payload}\n```\n\n"
            f"Analyst question: {question.strip()}\n\n"
            "Answer using only the bundle above."
        )
        with self._lock:
            self.requests += 1
        try:
            answer = self._call(prompt)
        except Exception as exc:
            message = self._redact(str(exc))[:200]
            with self._lock:
                self.failures += 1
                self.last_error = message
            log.warning("AI analyst call failed: %s", message)
            return {
                "ok": False,
                "error": "the AI analyst is unavailable",
                "detail": message,
                "note": "NEMOS detection and alerting are unaffected.",
            }

        answer = answer.strip()[:MAX_RESPONSE_CHARS]
        verified, problems = verify_response(answer, bundle)
        if not verified:
            with self._lock:
                self.rejected += 1
            log.warning("AI analyst response rejected: %s", "; ".join(problems))
            return {
                "ok": False,
                "error": "the AI analyst response referenced facts not present in the evidence",
                "problems": problems,
                "note": (
                    "The response was discarded rather than shown. Use the "
                    "structured evidence directly."
                ),
            }
        return {
            "ok": True,
            "answer": answer,
            "provider": self.config.provider,
            "model": self.config.model,
            "verified": True,
            "disclaimer": (
                "Generated from NEMOS evidence only. It explains findings NEMOS "
                "made; it is not itself a detection."
            ),
        }

    def _redact(self, text: str) -> str:
        if self.config.api_key and len(self.config.api_key) >= 8:
            return text.replace(self.config.api_key, "***")
        return text

    def _call(self, prompt: str) -> str:
        if self._transport is not None:
            return self._transport(prompt, self.config)
        if self.config.provider == "anthropic":
            return self._call_anthropic(prompt)
        if self.config.provider == "openai":
            return self._call_openai(prompt)
        return self._call_ollama(prompt)

    def _post(self, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(  # noqa: S310 - host fixed by PROVIDERS
            self.config.base_url,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
        )
        for key, value in headers.items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:  # noqa: S310
                return json.loads(response.read(200_000).decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read(2000).decode("utf-8", "replace")
            except Exception:
                log.debug("could not read provider error body")
            raise AnalystUnavailable(f"provider returned {exc.code}: {detail[:200]}") from exc

    def _call_anthropic(self, prompt: str) -> str:
        data = self._post(
            {
                "x-api-key": self.config.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            {
                "model": self.config.model,
                "max_tokens": self.config.max_tokens,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        blocks = data.get("content") or []
        return "".join(b.get("text", "") for b in blocks if isinstance(b, dict))

    def _call_openai(self, prompt: str) -> str:
        data = self._post(
            {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
            {
                "model": self.config.model,
                "max_completion_tokens": self.config.max_tokens,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            },
        )
        choices = data.get("choices") or []
        if not choices:
            raise AnalystUnavailable("provider returned no choices")
        return (choices[0].get("message") or {}).get("content", "")

    def _call_ollama(self, prompt: str) -> str:
        data = self._post(
            {"Content-Type": "application/json"},
            {
                "model": self.config.model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            },
        )
        return (data.get("message") or {}).get("content", "")


__all__ = [
    "MAX_EVIDENCE_BYTES",
    "PROVIDERS",
    "SYSTEM_PROMPT",
    "Analyst",
    "AnalystConfig",
    "AnalystUnavailable",
    "collect_evidence",
    "extract_referenced_facts",
    "verify_response",
]
