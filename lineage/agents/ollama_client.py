"""Zero-Mock OpenAI-Compatible Client for Host Ollama (`qwen2.5:3b`).

Connects to `http://host.docker.internal:11434/v1/chat/completions` inside Kubernetes
containers (or `http://127.0.0.1:11434/v1` on host) and captures full verifiable
inference telemetry (`model`, `completion_id`, `system_fingerprint`, token usage, latency)
with zero secret material.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlparse, urlsplit, urlunsplit

import httpx

from lineage.common.crypto import redact_sensitive


class OllamaError(Exception):
    """Raised when OpenAI-compatible / Ollama inference fails or returns malformed output."""


def _load_llm_api_key(explicit_api_key: Optional[str] = None) -> str:
    if explicit_api_key is not None and str(explicit_api_key).strip():
        return str(explicit_api_key).strip()
    env_key = os.environ.get("LLM_API_KEY", "").strip()
    if env_key:
        return env_key
    key_file = os.environ.get("LLM_API_KEY_FILE", "").strip()
    if key_file and os.path.isfile(key_file):
        with open(key_file, "r", encoding="utf-8") as fh:
            file_key = fh.read().strip()
        if file_key:
            return file_key
    return "ollama"


def _should_trust_proxy_env(base_url: str) -> bool:
    try:
        host = (urlparse(base_url).hostname or "").strip().lower()
    except Exception:
        return False
    if not host or host in {"localhost", "host.docker.internal"} or host.endswith(".local") or host.endswith(".cluster.local"):
        return False
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return False
    except ValueError:
        pass
    return True


def _reject_nonfinite(val: str) -> Any:
    raise ValueError(f"Non-finite JSON constant {val!r} rejected in LLM response")


def _sanitize_endpoint_url(raw_url: str) -> str:
    """Strip any URL userinfo (`user:pass@`), query string (`?key=...`), or fragment from telemetry URLs."""
    try:
        sp = urlsplit(str(raw_url or "").strip())
        if not sp.scheme or not sp.hostname:
            return str(redact_sensitive(str(raw_url or "")))
        host_str = f"[{sp.hostname}]" if ":" in sp.hostname else sp.hostname
        netloc = f"{host_str}:{sp.port}" if sp.port is not None else host_str
        return urlunsplit((sp.scheme, netloc, sp.path, "", ""))
    except Exception:
        return str(redact_sensitive(str(raw_url or "")))


def _extract_json_object(raw_text: str) -> Dict[str, Any]:
    text = raw_text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text).strip()
    try:
        parsed = json.loads(text, parse_constant=_reject_nonfinite)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            parsed = json.loads(text[start : end + 1], parse_constant=_reject_nonfinite)
            if isinstance(parsed, dict):
                return parsed
        except Exception as exc:
            safe_snip = str(redact_sensitive(raw_text[:240]))
            raise OllamaError(
                f"LLM output contained malformed JSON object: {safe_snip!r}"
            ) from exc
    safe_snip = str(redact_sensitive(raw_text[:240]))
    raise OllamaError(f"LLM output did not contain a valid JSON object: {safe_snip!r}")


class OllamaClient:
    """Real HTTP client driving OpenAI-compatible LLMs (`qwen2.5:3b`, `qwen2.5:7b`, or cloud APIs)."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 60.0,
    ) -> None:
        raw_base = (
            base_url
            or os.environ.get("LLM_BASE_URL", "").strip()
            or os.environ.get("OLLAMA_BASE_URL", "").strip()
            or "http://host.docker.internal:11434/v1"
        )
        self.base_url = raw_base.rstrip("/")
        self.model = model or os.environ.get("LLM_MODEL", "qwen2.5:3b")
        self._api_key = _load_llm_api_key(api_key)
        self.timeout = float(timeout)

    def __repr__(self) -> str:
        safe_base = _sanitize_endpoint_url(self.base_url)
        return f"OllamaClient(base_url={safe_base!r}, model={self.model!r}, api_key='[REDACTED]')"

    def _scrub_secret_text(self, text: str) -> str:
        out = str(text or "")
        if self._api_key and self._api_key != "ollama" and self._api_key in out:
            out = out.replace(self._api_key, "[REDACTED_LLM_API_KEY]")
        return str(redact_sensitive(out))

    def _post_completions(self, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        t0 = time.perf_counter()
        clean_base = _sanitize_endpoint_url(self.base_url).rstrip("/")
        url = f"{clean_base}/chat/completions"
        safe_url = _sanitize_endpoint_url(url)
        req_headers = {"Authorization": f"Bearer {self._api_key}"}
        try:
            with httpx.Client(
                timeout=self.timeout,
                trust_env=_should_trust_proxy_env(self.base_url),
            ) as client:
                resp = client.post(url, json=payload, headers=req_headers)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            safe_err = self._scrub_secret_text(str(exc))
            raise OllamaError(f"LLM HTTP call to {safe_url} failed: {safe_err}") from None

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        usage = data.get("usage") or {}
        meta = {
            "endpoint": safe_url,
            "model": str(data.get("model", self.model)),
            "completion_id": str(data.get("id", "")),
            "system_fingerprint": str(data.get("system_fingerprint", "")),
            "prompt_tokens": int(usage.get("prompt_tokens", 0)),
            "completion_tokens": int(usage.get("completion_tokens", 0)),
            "total_tokens": int(usage.get("total_tokens", 0)),
            "latency_ms": elapsed_ms,
        }
        if not meta["completion_id"] and not meta["system_fingerprint"]:
            safe_data = self._scrub_secret_text(json.dumps(redact_sensitive(data)))
            raise OllamaError(f"Unexpected non-OpenAI-compatible response structure: {safe_data}")
        return data, meta

    def chat_json(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0,
        max_tokens: int = 256,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Invoke `qwen2.5:3b` in native JSON mode and parse the returned JSON object."""
        payload = {
            "model": self.model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }
        data, meta = self._post_completions(payload)
        choices = data.get("choices") or []
        if not choices:
            raise OllamaError("Ollama returned empty choices")
        content = str((choices[0].get("message") or {}).get("content") or "")
        try:
            parsed = _extract_json_object(content)
        except OllamaError as exc:
            raise OllamaError(self._scrub_secret_text(str(exc))) from None
        meta["raw_content"] = self._scrub_secret_text(content)
        return parsed, meta

    def chat_tool_call(
        self,
        system_prompt: str,
        user_prompt: str,
        tools_schema: List[Dict[str, Any]],
        temperature: float = 0.0,
        max_tokens: int = 220,
    ) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        """Invoke `qwen2.5:3b` with native OpenAI `tools` function-calling schema."""
        payload = {
            "model": self.model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "tools": tools_schema,
        }
        data, meta = self._post_completions(payload)
        choices = data.get("choices") or []
        if not choices:
            raise OllamaError("Ollama tool call returned empty choices")
        msg = choices[0].get("message") or {}
        tool_calls = msg.get("tool_calls") or []
        if tool_calls:
            fn_block = tool_calls[0].get("function") or {}
            fn_name = str(fn_block.get("name") or "")
            raw_args = fn_block.get("arguments") or "{}"
            try:
                args_dict = (
                    _extract_json_object(raw_args)
                    if isinstance(raw_args, str)
                    else dict(raw_args)
                )
            except OllamaError as exc:
                raise OllamaError(self._scrub_secret_text(str(exc))) from None
            meta["finish_reason"] = str(choices[0].get("finish_reason", "tool_calls"))
            meta["tool_call_id"] = str(tool_calls[0].get("id", ""))
            meta["invoked_tool"] = fn_name
            meta["invoked_arguments"] = args_dict
            return fn_name, args_dict, meta

        # Fallback if model emitted JSON tool call inside `content` or Ollama's OpenAI-compat
        # `<tool_call>` parser stripped `content` to `""` despite non-zero completion tokens.
        content = str(msg.get("content") or "")
        if not content.strip():
            tool_specs = [
                f"{t.get('function', {}).get('name')}({list((t.get('function', {}).get('parameters', {}).get('properties') or {}).keys())})"
                for t in tools_schema
                if isinstance(t, Mapping)
            ]
            obj, meta_json = self.chat_json(
                system_prompt=(
                    f"{system_prompt} Available tools: {', '.join(tool_specs)}. "
                    "Reply strictly in JSON with keys 'name' (tool name) and 'arguments' (JSON object)."
                ),
                user_prompt=user_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            meta = meta_json
        else:
            try:
                obj = _extract_json_object(content)
            except OllamaError as exc:
                raise OllamaError(self._scrub_secret_text(str(exc))) from None
        fn_name = str(obj.get("name") or obj.get("tool") or "")
        raw_args = obj.get("arguments") or obj.get("parameters") or obj
        if not fn_name and len(tools_schema) == 1:
            fn_name = str(tools_schema[0]["function"]["name"])
        args_dict = dict(raw_args) if isinstance(raw_args, Mapping) else {}
        meta["finish_reason"] = str(choices[0].get("finish_reason", "stop"))
        meta["invoked_tool"] = fn_name
        meta["invoked_arguments"] = args_dict
        return fn_name, args_dict, meta

    def chat_text(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0,
        max_tokens: int = 320,
    ) -> Tuple[str, Dict[str, Any]]:
        """Invoke `qwen2.5:3b` for grounded natural-language synthesis."""
        payload = {
            "model": self.model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        data, meta = self._post_completions(payload)
        choices = data.get("choices") or []
        if not choices:
            raise OllamaError("Ollama text synthesis returned empty choices")
        content = str((choices[0].get("message") or {}).get("content") or "").strip()
        if not content:
            raise OllamaError("Ollama returned empty text response")
        return content, meta
