"""Agent LLM-layer tests: response parsing and 400 handling (mocked
httpx - no vLLM needed). Regression guards for the two production
incidents: context overflow and conflated 400 kinds."""
import json
from unittest.mock import patch

import pytest

import agent
from agent import ContextTooLongError, _parse_array, _chat


def _think(inner):
    """Wrap text in reasoning tags; assembled from parts so the tags
    cannot be stripped from this file in transit."""
    return "<" + "think" + ">" + inner + "</" + "think" + ">"


class TestParseArray:
    def test_clean_array(self):
        text = '[{"user":"a","verdict":"benign","reason":"ok"}]'
        assert _parse_array(text)[0]["user"] == "a"

    def test_think_block_stripped(self):
        arr = '[{"user":"a","verdict":"benign","reason":"ok"}]'
        text = _think("I should analyze this carefully...") + arr
        out = _parse_array(text)
        assert len(out) == 1 and out[0]["user"] == "a"

    def test_think_then_prose_then_array(self):
        arr = '[{"user":"b","verdict":"suspicious","reason":"r"}]'
        text = _think("hmm") + "Here is my answer: " + arr
        assert _parse_array(text)[0]["user"] == "b"

    def test_unterminated_think(self):
        # truncated mid-reasoning: nothing parseable
        text = "<" + "think" + ">analyzing... never finished "
        assert _parse_array(text) == []

    def test_json_fenced(self):
        text = "```json\n[{\"user\":\"a\",\"verdict\":\"benign\",\"reason\":\"ok\"}]\n```"
        assert _parse_array(text)[0]["user"] == "a"

    def test_doubled_braces(self):
        text = "{{\"user\":\"a\",\"verdict\":\"benign\",\"reason\":\"ok\"}}"
        assert _parse_array(text)[0]["user"] == "a"


class _FakeResponse:
    def __init__(self, status_code, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload

    def json(self):
        return self._payload


def _ok(content):
    return _FakeResponse(200, payload={"choices": [{"message": {"content": content}}]})


class TestChat400Handling:
    def test_context_overflow_raises_immediately(self):
        # input too long -> ContextTooLongError, no variant roulette
        err = {"error": {"message": "This model's maximum context length is 8192 "
                                    "tokens. However, your request has 9636 input tokens."}}
        with patch.object(agent.httpx, "post",
                          return_value=_FakeResponse(400, text=json.dumps(err))):
            with pytest.raises(ContextTooLongError):
                _chat("prompt", agent.TRIAGE_SCHEMA, 1024)

    def test_max_tokens_overflow_shrinks_and_retries(self):
        err = {"error": {"message": "'max_tokens' is too large: 2816. This model's "
                                    "maximum context length is 8192 tokens and your "
                                    "request has 6944 input tokens (2816 > 8192 - 6944)."}}
        responses = [
            _FakeResponse(400, text=json.dumps(err)),
            _ok('[{"user":"a","verdict":"benign","reason":"ok"}]'),
        ]
        with patch.object(agent.httpx, "post", side_effect=responses):
            out = _chat("prompt", agent.TRIAGE_SCHEMA, 2816)
            assert json.loads(out[out.find("["):])[0]["user"] == "a"

    def test_kwarg_rejected_then_plain_ok(self):
        err = {"error": {"message": "Extra inputs are not permitted "
                                    "[body='chat_template_kwargs']"}}
        responses = [
            _FakeResponse(400, text=json.dumps(err)),
            _ok('[{"user":"a","verdict":"benign","reason":"ok"}]'),
        ]
        with patch.object(agent.httpx, "post", side_effect=responses):
            out = _chat("prompt", agent.TRIAGE_SCHEMA, 1024)
            assert "a" in out

    def test_empty_content_tries_next_variant(self):
        responses = [
            _ok(""),
            _ok('[{"user":"a","verdict":"benign","reason":"ok"}]'),
        ]
        with patch.object(agent.httpx, "post", side_effect=responses):
            out = _chat("prompt", agent.TRIAGE_SCHEMA, 1024)
            assert "[" in out

    def test_no_json_tries_next_variant(self):
        responses = [
            _ok("Sorry, I cannot help with that."),
            _ok('[{"user":"a","verdict":"benign","reason":"ok"}]'),
        ]
        with patch.object(agent.httpx, "post", side_effect=responses):
            out = _chat("prompt", agent.TRIAGE_SCHEMA, 1024)
            assert "[" in out


class TestVerdictHelpers:
    def test_clean_verdict(self):
        assert agent._clean_verdict("MALICIOUS") == "malicious"
        assert agent._clean_verdict("weird") == "not_analyzed"
        assert agent._clean_verdict(None) == "not_analyzed"

    def test_clamp_score(self):
        assert agent._clamp_score(150) == 100
        assert agent._clamp_score(-5) == 0
        assert agent._clamp_score("42") == 42
        assert agent._clamp_score(None) == 0