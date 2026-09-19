"""Pumla shadow UsageAction + deterministic complexity helpers.

No credit charging lives here. The module only:
- classifies request/context complexity;
- estimates a broad time-saved range for completed actions;
- creates/starts/completes/fails UsageAction records through axelper-auth;
- builds trusted llm-gateway correlation headers.

All telemetry calls fail open so an auth/telemetry outage never breaks diagram work.
"""
import json
import logging
import uuid
from urllib import request as urlreq


METHODOLOGY_VERSION = "pumla-complexity-v1"


def _bool(value):
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def action_type_for(code):
    return "pumla.adjust" if str(code or "").strip() else "pumla.generate"


def complexity_for(code, prompt, doc_content=""):
    code = str(code or "")
    prompt = str(prompt or "")
    doc_content = str(doc_content or "")
    code_chars = len(code)
    prompt_chars = len(prompt)
    doc_chars = len(doc_content)
    total_chars = code_chars + prompt_chars + doc_chars
    code_lines = len(code.splitlines()) if code else 0

    # Deliberately deterministic and model-independent. These are context buckets,
    # not prices. Pricing will be calibrated later from measured actual/shadow COGS.
    if total_chars <= 2500 and doc_chars == 0:
        bucket = "small"
    elif total_chars <= 7000 and doc_chars <= 3000:
        bucket = "medium"
    elif total_chars <= 14000 and doc_chars <= 9000:
        bucket = "large"
    elif total_chars <= 26000:
        bucket = "very_large"
    else:
        bucket = "extreme"

    return {
        "class": bucket,
        "total_chars": total_chars,
        "code_chars": code_chars,
        "prompt_chars": prompt_chars,
        "doc_chars": doc_chars,
        "code_lines": code_lines,
        "has_document": bool(doc_content.strip()),
        "methodology_version": METHODOLOGY_VERSION,
    }


def time_saved_range(action_type, complexity_class):
    generate = {
        "small": (15, 30),
        "medium": (25, 45),
        "large": (40, 70),
        "very_large": (60, 100),
        "extreme": (90, 150),
    }
    adjust = {
        "small": (10, 20),
        "medium": (15, 30),
        "large": (25, 45),
        "very_large": (40, 60),
        "extreme": (60, 90),
    }
    table = adjust if action_type == "pumla.adjust" else generate
    return table.get(complexity_class, table["medium"])


def quote_preview(code, prompt, doc_content=""):
    action_type = action_type_for(code)
    complexity = complexity_for(code, prompt, doc_content)
    saved_min, saved_max = time_saved_range(action_type, complexity["class"])
    return {
        "action_type": action_type,
        "complexity": complexity,
        "estimated_minutes_saved_min": saved_min,
        "estimated_minutes_saved_max": saved_max,
        "credits_quote": None,
        "pricing_enabled": False,
    }


def new_logical_call_id():
    return str(uuid.uuid4())


def gateway_headers(service_key, user_id, action_id="", logical_call_id="", tier=""):
    headers = {"Content-Type": "application/json"}
    if service_key:
        headers["Authorization"] = "Bearer " + str(service_key)
    if user_id:
        headers["X-User-Id"] = str(user_id)
    if tier:
        headers["X-Tier"] = str(tier)
    if action_id:
        headers["X-Axelper-Action-Id"] = str(action_id)
    if logical_call_id:
        headers["X-Axelper-Logical-Call-Id"] = str(logical_call_id)
    return headers


class UsageActionClient:
    def __init__(self, auth_api, internal_key, enabled=True, timeout=2.5, opener=None):
        self.auth_api = str(auth_api or "").rstrip("/")
        self.internal_key = str(internal_key or "")
        self.enabled = bool(enabled) and bool(self.auth_api) and bool(self.internal_key)
        self.timeout = float(timeout)
        self.opener = opener or urlreq.urlopen

    @classmethod
    def from_env(cls, env, auth_api):
        return cls(
            auth_api=auth_api,
            internal_key=env.get("PUMLA_USAGE_ACTION_KEY", ""),
            enabled=_bool(env.get("PUMLA_USAGE_ACTION_ENABLED", "false")),
            timeout=float(env.get("PUMLA_USAGE_ACTION_TIMEOUT", "2.5")),
        )

    def _post(self, path, payload):
        if not self.enabled:
            return None
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urlreq.Request(
            self.auth_api + path,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Axelper-Usage-Key": self.internal_key,
            },
        )
        try:
            with self.opener(req, timeout=self.timeout) as resp:
                return json.loads(resp.read() or b"{}")
        except Exception as exc:
            logging.warning("Pumla UsageAction telemetry failed path=%s err=%s", path, type(exc).__name__)
            return None

    def quote(self, action_type, complexity_class):
        """Central PricingService quote (shadow-safe: read-only, no LLM,
        no UsageAction). Returns dict or None; caller fails open."""
        if not self.enabled:
            return None
        return self._post("/api/internal/pricing/quote", {
            "product": "pumla",
            "action_type": str(action_type or "")[:120],
            "complexity_class": str(complexity_class or "")[:80],
        })

    def begin(self, user_id, action_type, complexity, request_fingerprint=""):
        if not self.enabled:
            return ""
        action_id = str(uuid.uuid4())
        created = self._post("/api/internal/usage-actions", {
            "action_id": action_id,
            "user_id": str(user_id),
            "product": "pumla",
            "action_type": action_type,
            "idempotency_key": "pumla:%s:create" % action_id,
            "credits_quoted": 0,
            "methodology_version": METHODOLOGY_VERSION,
            "source": "pumla-web",
            "metadata": {
                "complexity": complexity,
                "request_fingerprint": str(request_fingerprint or "")[:32],
                "shadow_mode": True,
            },
        })
        if not created:
            return ""
        started = self._post("/api/internal/usage-actions/%s/start" % action_id, {
            "idempotency_key": "pumla:%s:start" % action_id,
        })
        return action_id if started else ""

    def complete(self, action_id, action_type, complexity_class):
        if not action_id:
            return None
        saved_min, saved_max = time_saved_range(action_type, complexity_class)
        return self._post("/api/internal/usage-actions/%s/complete" % action_id, {
            "idempotency_key": "pumla:%s:complete" % action_id,
            "estimated_minutes_saved_min": saved_min,
            "estimated_minutes_saved_max": saved_max,
            "methodology_version": METHODOLOGY_VERSION,
        })

    def fail(self, action_id, error_code="pumla_upstream_failed"):
        if not action_id:
            return None
        return self._post("/api/internal/usage-actions/%s/fail" % action_id, {
            "idempotency_key": "pumla:%s:fail" % action_id,
            "error_code": str(error_code or "pumla_upstream_failed")[:120],
        })
