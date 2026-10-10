"""LLM client tests: catalog, model selection, error classification.

All network access is mocked; no real API key or OpenRouter access is needed.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import requests
from openai import (
    APIConnectionError,
    APIStatusError,
    AuthenticationError,
    BadRequestError,
    PermissionDeniedError,
    RateLimitError,
)

from gryphos.llm import GryphosLLM, LLMError, LLMOutputError, build_system_prompt
from gryphos.models import FinalDecision


@pytest.fixture
def llm():
    return GryphosLLM(
        api_key="sk-or-v1-" + "0" * 40,
        model="openrouter/free",
        request_timeout=5,
        max_retries=0,
        catalog_ttl=300,
    )


def fake_models_response(models):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"data": models}
    return resp


CATALOG = [
    {"id": "cohere/command-a", "name": "Cohere: Command A", "context_length": 256000,
     "pricing": {"prompt": "0", "completion": "0"}},
    {"id": "openrouter/free", "name": "OpenRouter Free", "context_length": 8000,
     "pricing": {"prompt": "0", "completion": "0"}},
    {"id": "vendor/paid-model", "name": "Paid Model", "context_length": 32000,
     "pricing": {"prompt": "0.000001", "completion": "0.000002"}},
]


def test_list_models_uses_exact_ids(llm):
    with patch("gryphos.llm.requests.get", return_value=fake_models_response(CATALOG)):
        models = llm.list_models()
    assert [m.id for m in models] == ["cohere/command-a", "openrouter/free", "vendor/paid-model"]
    assert models[0].name == "Cohere: Command A"
    assert models[0].is_free is True
    assert models[2].is_free is False


def test_catalog_cached_until_ttl(llm):
    with patch("gryphos.llm.requests.get", return_value=fake_models_response(CATALOG)) as get:
        llm.list_models()
        llm.list_models()
        assert get.call_count == 1
        llm.list_models(force_refresh=True)
        assert get.call_count == 2


def test_catalog_failure_raises_classified(llm):
    with patch("gryphos.llm.requests.get", side_effect=requests.ConnectionError("down")):
        with pytest.raises(LLMError) as exc:
            llm.list_models()
    assert exc.value.category == "catalog_unavailable"


def test_catalog_failure_serves_stale_cache(llm):
    with patch("gryphos.llm.requests.get", return_value=fake_models_response(CATALOG)):
        llm.list_models()
    with patch("gryphos.llm.requests.get", side_effect=requests.ConnectionError("down")):
        models = llm.list_models()  # stale but available
    assert len(models) == 3


def test_set_model_by_exact_id(llm):
    with patch("gryphos.llm.requests.get", return_value=fake_models_response(CATALOG)):
        changed, message = llm.set_model("cohere/command-a")
    assert changed is True
    assert llm.model == "cohere/command-a"
    assert "Command A" in message


def test_display_name_not_transformed_into_fake_id(llm):
    with patch("gryphos.llm.requests.get", return_value=fake_models_response(CATALOG)):
        changed, message = llm.set_model("Cohere: Command A")
    assert changed is False
    assert llm.model == "openrouter/free"  # preserved


def test_invalid_id_preserves_last_good(llm):
    llm.model = "cohere/command-a"
    llm.last_good_model = "cohere/command-a"
    with patch("gryphos.llm.requests.get", return_value=fake_models_response(CATALOG)):
        changed, message = llm.set_model("nope/nothere")
    assert changed is False
    assert llm.model == "cohere/command-a"
    assert "not in the current OpenRouter catalog" in message


def test_catalog_down_still_allows_selection_with_warning(llm):
    with patch("gryphos.llm.requests.get", side_effect=requests.ConnectionError("down")):
        changed, message = llm.set_model("some/model-x")
    assert changed is True
    assert "without catalog validation" in message


def test_set_model_requires_exact_shape(llm):
    for bad in ["", "nodslash", "has space/yes", "Cohere: Command A"]:
        changed, _ = llm.set_model(bad)
        assert changed is False


# --- decide / parse ---------------------------------------------------------

def completion(content: str):
    result = MagicMock()
    message = MagicMock()
    message.content = content
    choice = MagicMock()
    choice.message = message
    result.choices = [choice]
    return result


def test_decide_parses_valid_json(llm):
    with patch.object(llm.client.chat.completions, "create",
                      return_value=completion('{"kind":"final","message":"ok"}')):
        decision = llm.decide("obj", "127.0.0.1", [], 1, "sys")
    assert isinstance(decision, FinalDecision)


def test_decide_repairs_fenced_output_via_retry(llm):
    responses = [
        completion("I think we should scan now."),           # invalid
        completion('{"kind":"final","message":"repaired"}'),  # repair succeeds
    ]
    with patch.object(llm.client.chat.completions, "create", side_effect=responses) as create:
        decision = llm.decide("obj", "127.0.0.1", [], 1, "sys")
    assert decision.message == "repaired"
    assert create.call_count == 2


def test_decide_gives_up_after_bounded_repair(llm):
    responses = [completion("no json at all"), completion("still no json")]
    with patch.object(llm.client.chat.completions, "create", side_effect=responses):
        with pytest.raises(LLMOutputError) as exc:
            llm.decide("obj", "127.0.0.1", [], 1, "sys")
    assert exc.value.category == "invalid_output"


def test_decide_does_not_loop_forever(llm):
    with patch.object(llm.client.chat.completions, "create",
                      return_value=completion("garbage")) as create:
        with pytest.raises(LLMOutputError):
            llm.decide("obj", None, [], 1, "sys")
    assert create.call_count <= 2


def test_invalid_output_error_is_distinct_from_api_failure(llm):
    with patch.object(llm.client.chat.completions, "create",
                      return_value=completion("{}")), pytest.raises(LLMOutputError):
        llm.decide("obj", None, [], 1, "sys")


# --- error classification ---------------------------------------------------

def http_error(cls, status=500, message="boom"):
    request = MagicMock()
    response = MagicMock()
    response.status_code = status
    return cls(message, response=response, body=None)


def test_auth_error_classified(llm):
    with patch.object(llm.client.chat.completions, "create",
                      side_effect=http_error(AuthenticationError, 401)):
        with pytest.raises(LLMError) as exc:
            llm.decide("o", None, [], 1, "sys")
    assert exc.value.category == "auth"


def test_permission_error_classified(llm):
    with patch.object(llm.client.chat.completions, "create",
                      side_effect=http_error(PermissionDeniedError, 403)):
        with pytest.raises(LLMError) as exc:
            llm.decide("o", None, [], 1, "sys")
    assert exc.value.category == "permission"


def test_rate_limit_error_classified(llm):
    with patch.object(llm.client.chat.completions, "create",
                      side_effect=http_error(RateLimitError, 429)):
        with pytest.raises(LLMError) as exc:
            llm.decide("o", None, [], 1, "sys")
    assert exc.value.category == "rate_limit"
    assert exc.value.retryable is True


def test_timeout_error_classified(llm):
    with patch.object(llm.client.chat.completions, "create",
                      side_effect=APIConnectionError(request=MagicMock())):
        with pytest.raises(LLMError) as exc:
            llm.decide("o", None, [], 1, "sys")
    assert exc.value.category in {"connection", "timeout", "transient"}


def test_bad_request_context_length_detected(llm):
    err = http_error(BadRequestError, 400, "Error code: 400 - This model's maximum context length is 8000 tokens")
    with patch.object(llm.client.chat.completions, "create", side_effect=err):
        with pytest.raises(LLMError) as exc:
            llm.decide("o", None, [], 1, "sys")
    assert exc.value.category == "context_length"
    assert "context" in str(exc.value).lower()


def test_server_error_retryable_then_fails(llm):
    with patch.object(llm.client.chat.completions, "create",
                      side_effect=http_error(APIStatusError, 503)), \
         patch("gryphos.llm.time.sleep"), pytest.raises(LLMError) as exc:
        llm.decide("o", None, [], 1, "sys")
    assert exc.value.category == "server_error"


def test_error_message_does_not_leak_key(llm):
    secret = llm.api_key
    with patch.object(llm.client.chat.completions, "create",
                      side_effect=http_error(AuthenticationError, 401, "bad key " + secret)):
        with pytest.raises(LLMError) as exc:
            llm.decide("o", None, [], 1, "sys")
    assert secret not in str(exc.value)


# --- system prompt ----------------------------------------------------------

def test_system_prompt_lists_only_registered_tools(registry):
    prompt = build_system_prompt(registry)
    for name in registry:
        assert name in prompt
    assert "shell" not in prompt.lower() or "no shell" in prompt.lower() or "shell access" in prompt.lower()
    assert "You do not execute commands" in prompt


def test_system_prompt_rejects_invented_tools_message(registry):
    prompt = build_system_prompt(registry)
    assert "NEVER invent" in prompt or "never invent" in prompt.lower()


def test_evidence_bounded_in_payload(llm):
    evidence = [{"kind": "tool_result", "output": "X" * 10_000} for _ in range(20)]
    captured = {}

    def fake_create(**kwargs):
        captured["user"] = kwargs["messages"][1]["content"]
        return completion('{"kind":"final","message":"ok"}')

    with patch.object(llm.client.chat.completions, "create", side_effect=fake_create):
        llm.decide("o", None, evidence, 1, "sys")
    payload = json.loads(captured["user"])
    assert len(payload["evidence_so_far"]) <= 8
    assert "…" in payload["evidence_so_far"][-1]["output"]
