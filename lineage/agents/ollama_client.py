"""Zero-Mock OpenAI-Compatible Client for Host Ollama (`qwen2.5:3b`).

Connects to `http://host.docker.internal:11434/v1/chat/completions` inside Kubernetes
containers (or `http://127.0.0.1:11434/v1` on host) and captures full verifiable
inference telemetry (`model`, `completion_id`, `system_fingerprint`, token usage, latency)
with zero secret material.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple

import httpx


class OllamaError(Exception):
    """Raised when Ollama inference fails or returns malformed structured output."""


def _reject_nonfinite(val: str) -> Any:
    raise ValueError(f"Non-finite JSON constant {val!r} rejected in LLM response")


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
            raise OllamaError(
                f"LLM output contained malformed JSON object: {raw_text[:240]!r}"
            ) from exc
    raise OllamaError(f"LLM output did not contain a valid JSON object: {raw_text[:240]!r}")


class OllamaClient:
    """Real HTTP client driving `qwen2.5:3b` for intent parsing, tool calling & synthesis."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 60.0,
    ) -> None:
        raw_base = base_url or os.environ.get(
            "OLLAMA_BASE_URL", "http://host.docker.internal:11434/v1"
        )
        self.base_url = raw_base.rstrip("/")
        self.model = model or os.environ.get("LLM_MODEL", "qwen2.5:3b")
        self.timeout = float(timeout)

    def _post_completions(self, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        t0 = time.perf_counter()
        url = f"{self.base_url}/chat/completions"
        try:
            resp = httpx.post(url, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            raise OllamaError(f"Ollama HTTP call to {url} failed: {exc}") from exc

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        usage = data.get("usage") or {}
        meta = {
            "endpoint": url,
            "model": str(data.get("model", self.model)),
            "completion_id": str(data.get("id", "")),
            "system_fingerprint": str(data.get("system_fingerprint", "")),
            "prompt_tokens": int(usage.get("prompt_tokens", 0)),
            "completion_tokens": int(usage.get("completion_tokens", 0)),
            "total_tokens": int(usage.get("total_tokens", 0)),
            "latency_ms": elapsed_ms,
        }
        if not meta["completion_id"] and not meta["system_fingerprint"]:
            raise OllamaError(f"Unexpected non-Ollama response structure: {data}")
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
        parsed = _extract_json_object(content)
        meta["raw_content"] = content
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
            args_dict = (
                _extract_json_object(raw_args)
                if isinstance(raw_args, str)
                else dict(raw_args)
            )
            meta["finish_reason"] = str(choices[0].get("finish_reason", "tool_calls"))
            meta["tool_call_id"] = str(tool_calls[0].get("id", ""))
            meta["invoked_tool"] = fn_name
            meta["invoked_arguments"] = args_dict
            return fn_name, args_dict, meta

        # Fallback if model emitted JSON tool call inside `content`
        content = str(msg.get("content") or "")
        obj = _extract_json_object(content)
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
