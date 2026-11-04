"""Mocked-Claude tests for the ThreatWeave agent: no network, no API key.

Responses are plain objects (not MagicMock) so a missing attribute fails loudly.
"""
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from threatweave import agent
from threatweave.cli import main
from threatweave.correlate import correlate
from threatweave.fixtures import load_demo
from threatweave.policy import FIELDS, load_policy
from threatweave.store import Store
from conftest import ROOT

POLICY = str(ROOT / "policies/business-context.yaml")


# --------------------------------------------------------------------------- helpers

def text(value):
    return SimpleNamespace(type="text", text=value)


def tool_use(name, tool_input, call_id="call_1"):
    return SimpleNamespace(type="tool_use", id=call_id, name=name, input=tool_input)


def response(*blocks, stop_reason="end_turn", model="claude-opus-5-5", stop_details=None):
    return SimpleNamespace(content=list(blocks), stop_reason=stop_reason, model=model,
                           stop_details=stop_details)


class FakeClient:
    """Records every create() call on both the plain and beta endpoints."""

    def __init__(self, *responses):
        self._responses = list(responses)
        self.calls = []
        self.messages = SimpleNamespace(create=self._make("messages"))
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._make("beta")))

    def _make(self, endpoint):
        def create(**kwargs):
            self.calls.append((endpoint, kwargs))
            item = self._responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        return create


@pytest.fixture
def demo_db(tmp_path):
    path = tmp_path / "agent.db"
    store = Store(path)
    try:
        load_demo(store)
        correlate(store, ROOT / "policies/correlation-rules.yaml")
    finally:
        store.close()
    return str(path)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("THREATWEAVE_CLAUDE_MODEL", "THREATWEAVE_CLAUDE_EFFORT",
                 "THREATWEAVE_CLAUDE_FALLBACKS", "THREATWEAVE_CLAUDE_DRAFT_EFFORT"):
        monkeypatch.delenv(name, raising=False)


def run(client, demo_db, question="Which fix group first?", **kwargs):
    with patch("threatweave.agent._client", return_value=client):
        return agent.run_investigation(question, demo_db, POLICY, **kwargs)


def tool_results(client, call_index=1):
    """Tool-result blocks sent back on a given request.

    The agent keeps one growing message list, so request n carries the tool
    results for turn n at position 2n (user, assistant, user, ...).
    """
    message = client.calls[call_index][1]["messages"][2 * call_index]
    assert message["role"] == "user"
    return message["content"]


# --------------------------------------------------------------------------- request shape

def test_request_uses_current_model_effort_fallbacks_and_strict_tools(demo_db):
    client = FakeClient(response(text("Done.")))
    record = run(client, demo_db)

    endpoint, kwargs = client.calls[0]
    assert endpoint == "beta"
    assert kwargs["model"] == "claude-opus-5-5"
    assert kwargs["betas"] == [agent.FALLBACK_BETA]
    assert kwargs["fallbacks"] == "default"
    assert kwargs["max_tokens"] == 16000
    assert kwargs["output_config"] == {"effort": "high"}
    assert kwargs["cache_control"] == {"type": "ephemeral"}
    assert "tool_choice" not in kwargs  # forced tool use is rejected on current models
    for tool in kwargs["tools"]:
        assert tool["strict"] is True
        assert tool["input_schema"]["additionalProperties"] is False
    assert {tool["name"] for tool in kwargs["tools"]} == agent.ALLOWED_AGENT_TOOLS
    assert record["status"] == "completed" and record["answer"] == "Done."
    assert record["requested_model"] == "claude-opus-5-5" and record["refusal_fallbacks"] is True


def test_model_without_server_fallbacks_uses_plain_endpoint(demo_db):
    client = FakeClient(response(text("Done."), model="claude-haiku-5-5"))
    run(client, demo_db, model="claude-haiku-5-5", effort="low")
    endpoint, kwargs = client.calls[0]
    assert endpoint == "messages"
    assert "fallbacks" not in kwargs and "betas" not in kwargs
    assert kwargs["model"] == "claude-haiku-5-5" and kwargs["output_config"] == {"effort": "low"}


def test_fallbacks_can_be_turned_off(demo_db, monkeypatch):
    monkeypatch.setenv("THREATWEAVE_CLAUDE_FALLBACKS", "off")
    client = FakeClient(response(text("Done.")))
    record = run(client, demo_db)
    assert client.calls[0][0] == "messages"
    assert record["refusal_fallbacks"] is False


def test_invalid_effort_is_a_configuration_error(demo_db, monkeypatch):
    monkeypatch.setenv("THREATWEAVE_CLAUDE_EFFORT", "extreme")
    with pytest.raises(agent.ClaudeUnavailable, match="THREATWEAVE_CLAUDE_EFFORT"):
        run(FakeClient(), demo_db)


def test_missing_api_key_is_a_clear_error(monkeypatch):
    pytest.importorskip("anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(agent.ClaudeUnavailable, match="ANTHROPIC_API_KEY"):
        agent._client()


# --------------------------------------------------------------------------- stop reasons

def test_refusal_returns_safe_record_and_runs_no_tools(demo_db):
    refused = response(stop_reason="refusal",
                       stop_details=SimpleNamespace(type="refusal", category="cyber", explanation="..."))
    client = FakeClient(refused)
    with patch("threatweave.agent._run_tool") as run_tool:
        record = run(client, demo_db)
    run_tool.assert_not_called()
    assert record["status"] == "refused"
    assert record["refusal_category"] == "cyber"
    assert "threatweave investigate" in record["answer"]
    assert len(client.calls) == 1


def test_max_tokens_returns_truncated_record(demo_db):
    client = FakeClient(response(text("Partial analysis"), stop_reason="max_tokens"))
    record = run(client, demo_db)
    assert record["status"] == "truncated"
    assert record["answer"].startswith("Partial analysis")
    assert "output limit" in record["answer"]


def test_served_model_is_recorded_when_a_fallback_answers(demo_db):
    client = FakeClient(response(text("Answered by fallback."), model="claude-opus-4-8"))
    record = run(client, demo_db)
    assert record["requested_model"] == "claude-opus-5-5"
    assert record["served_model"] == "claude-opus-4-8"


def test_assistant_content_is_passed_back_unchanged(demo_db):
    thinking = SimpleNamespace(type="thinking", thinking="", signature="sig")
    first = response(thinking, tool_use("get_overview", {}), stop_reason="tool_use")
    client = FakeClient(first, response(text("Done.")))
    run(client, demo_db)
    assistant_turn = client.calls[1][1]["messages"][1]
    assert assistant_turn == {"role": "assistant", "content": first.content}


# --------------------------------------------------------------------------- tool handling

def test_tool_result_is_wrapped_and_successful_call_logged(demo_db):
    client = FakeClient(response(tool_use("get_overview", {}), stop_reason="tool_use"),
                        response(text("Done.")))
    record = run(client, demo_db)
    result = tool_results(client)[0]
    assert "is_error" not in result
    assert json.loads(result["content"])["_security_context"]["instruction_execution_allowed"] is False
    assert record["tool_calls"] == [{"tool": "get_overview", "ok": True}]


def test_invalid_tool_input_returns_is_error_without_running_tool(demo_db):
    client = FakeClient(response(tool_use("get_asset_exposure", {"asset_uuid": 123}), stop_reason="tool_use"),
                        response(text("Done.")))
    with patch("threatweave.agent._run_tool") as run_tool:
        record = run(client, demo_db)
    run_tool.assert_not_called()
    result = tool_results(client)[0]
    assert result["is_error"] is True
    assert "asset_uuid" in json.loads(result["content"])["error"]
    assert record["tool_calls"] == [{"tool": "get_asset_exposure", "ok": False}]


def test_unknown_tool_is_flagged_as_error(demo_db):
    client = FakeClient(response(tool_use("execute_command", {"cmd": "rm -rf /"}), stop_reason="tool_use"),
                        response(text("Done.")))
    with patch("threatweave.agent._run_tool") as run_tool:
        run(client, demo_db)
    run_tool.assert_not_called()
    result = tool_results(client)[0]
    assert result["is_error"] is True and "not permitted" in result["content"]


def test_fix_group_limit_is_clamped(demo_db):
    client = FakeClient(response(tool_use("list_fix_groups", {"limit": 500}), stop_reason="tool_use"),
                        response(text("Done.")))
    with patch("threatweave.agent.list_fix_groups", return_value={"groups": []}) as tool:
        run(client, demo_db)
    assert tool.call_args.args[2] == 10


def test_per_turn_tool_budget_is_enforced(demo_db):
    calls = [tool_use("get_overview", {}, call_id=f"c{i}") for i in range(agent.MAX_TOOLS_PER_TURN + 1)]
    client = FakeClient(response(*calls, stop_reason="tool_use"), response(text("Done.")))
    run(client, demo_db)
    results = tool_results(client)
    assert len(results) == len(calls)  # every tool_use gets a result
    assert [r.get("is_error", False) for r in results] == [False] * agent.MAX_TOOLS_PER_TURN + [True]
    assert "budget" in results[-1]["content"]


def test_turn_budget_stops_the_loop(demo_db):
    looping = [response(tool_use("get_overview", {}, call_id=f"c{i}"), stop_reason="tool_use")
               for i in range(agent.MAX_TURNS)]
    client = FakeClient(*looping)
    record = run(client, demo_db)
    assert record["status"] == "budget_exhausted"
    assert len(client.calls) == agent.MAX_TURNS


def test_investigate_wrapper_returns_answer_text(demo_db):
    client = FakeClient(response(text("Plain answer.")))
    with patch("threatweave.agent._client", return_value=client):
        assert agent.investigate("q", demo_db, POLICY) == "Plain answer."


# --------------------------------------------------------------------------- API errors

def _status_error(cls, status):
    httpx2 = pytest.importorskip("httpx2")
    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    return cls("error", response=httpx2.Response(status, request=request), body=None)


def test_api_errors_map_to_safe_messages_without_the_key(demo_db, monkeypatch):
    anthropic = pytest.importorskip("anthropic")
    httpx2 = pytest.importorskip("httpx2")
    secret = "sk-ant-api03-" + "x" * 40
    monkeypatch.setenv("ANTHROPIC_API_KEY", secret)
    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    cases = [
        (_status_error(anthropic.AuthenticationError, 401), "API key"),
        (_status_error(anthropic.RateLimitError, 429), "rate limit"),
        (_status_error(anthropic.NotFoundError, 404), "Model not found"),
        (anthropic.APITimeoutError(request=request), "timed out"),
        (anthropic.APIConnectionError(request=request), "api.anthropic.com"),
    ]
    for error, expected in cases:
        with pytest.raises(agent.ClaudeUnavailable) as caught:
            run(FakeClient(error), demo_db)
        assert expected in str(caught.value)
        assert secret not in str(caught.value)
        assert caught.value.__cause__ is None  # SDK exception not chained into the message


# --------------------------------------------------------------------------- draft_rule

def draft(client, request_text="Prioritize payment systems in production"):
    with patch("threatweave.agent._client", return_value=client):
        return agent.draft_rule(request_text, load_policy(POLICY))


def test_draft_rule_uses_structured_output_and_stays_unapproved():
    rule = {"id": "TW-NEW-01", "name": "Payments in production",
            "when": {"environment": "production", "business_tag": "payments"},
            "then": {"score_add": 12}}
    client = FakeClient(response(text(json.dumps(rule))))
    result = draft(client)
    assert result == {"draft_rule": rule, "approved": False, "preview_required": True}
    kwargs = client.calls[0][1]
    assert kwargs["output_config"]["effort"] == "medium"
    assert kwargs["output_config"]["format"] == {"type": "json_schema", "schema": agent.DRAFT_RULE_SCHEMA}
    assert "tools" not in kwargs


def test_draft_rule_schema_matches_policy_vocabulary():
    schema = agent.DRAFT_RULE_SCHEMA
    assert set(schema["properties"]["when"]["properties"]) == FIELDS
    assert schema["additionalProperties"] is False
    assert schema["properties"]["when"]["additionalProperties"] is False
    assert schema["properties"]["then"]["additionalProperties"] is False


def test_draft_rule_still_rejects_unsafe_values():
    rule = {"id": "TW-NEW-01", "name": "Too strong", "when": {"environment": "production"},
            "then": {"score_add": 99}}
    with pytest.raises(ValueError, match="score_add"):
        draft(FakeClient(response(text(json.dumps(rule)))))


def test_draft_rule_refusal_is_a_clear_error():
    with pytest.raises(agent.ClaudeUnavailable, match="declined"):
        draft(FakeClient(response(stop_reason="refusal")))


# --------------------------------------------------------------------------- CLI

def test_cli_ask_without_key_exits_2_with_hint(demo_db, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert main(["--db", demo_db, "ask", "Which fix first?"]) == 2
    error = json.loads(capsys.readouterr().err)
    assert "threatweave investigate" in error["hint"]


def test_cli_ask_missing_database_exits_1(tmp_path, capsys):
    assert main(["--db", str(tmp_path / "missing.db"), "ask", "q"]) == 1
    assert "does not exist" in capsys.readouterr().err
    assert not (tmp_path / "missing.db").exists()


def test_cli_ask_prints_structured_record(demo_db, capsys):
    client = FakeClient(response(tool_use("get_overview", {}), stop_reason="tool_use"),
                        response(text("Investigate OpenSSH first.")))
    with patch("threatweave.agent._client", return_value=client):
        assert main(["--db", demo_db, "ask", "Which fix first?", "--effort", "medium"]) == 0
    record = json.loads(capsys.readouterr().out)
    assert record["answer"] == "Investigate OpenSSH first."
    assert record["status"] == "completed" and record["read_only"] is True
    assert client.calls[0][1]["output_config"] == {"effort": "medium"}


def test_cli_ask_refusal_exits_3(demo_db, capsys):
    client = FakeClient(response(stop_reason="refusal"))
    with patch("threatweave.agent._client", return_value=client):
        assert main(["--db", demo_db, "ask", "q"]) == 3
    assert json.loads(capsys.readouterr().out)["status"] == "refused"


def test_cli_draft_rule_prints_unapproved_draft(capsys):
    rule = {"id": "TW-NEW-02", "name": "Internet exposure", "when": {"internet_exposure": "confirmed"},
            "then": {"priority_floor": "high"}}
    with patch("threatweave.agent._client", return_value=FakeClient(response(text(json.dumps(rule))))):
        assert main(["draft-rule", "Raise internet-exposed assets"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["approved"] is False and output["draft_rule"] == rule
