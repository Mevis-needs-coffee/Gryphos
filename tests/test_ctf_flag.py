"""Flag detection, heuristic verification, and the gated HTTP verifier (offline)."""

from __future__ import annotations

import pytest

from gryphos.ctf.flag import (
    FlagFormat,
    HeuristicFlagVerifier,
    HttpFlagVerifier,
    detect_flags,
    verify_flag,
)


class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


# --- detection --------------------------------------------------------------

def test_detect_default_flag():
    assert detect_flags("prefix flag{abc_123} suffix") == ["flag{abc_123}"]


def test_detect_ctf_and_case():
    found = detect_flags("CTF{MixedCase} and picoCTF{p1co}")
    assert "CTF{MixedCase}" in found
    assert "picoCTF{p1co}" in found


def test_detect_deduplicates():
    assert detect_flags("flag{same} flag{same}") == ["flag{same}"]


def test_detect_none():
    assert detect_flags("no flags here") == []


def test_explicit_format_used(tmp_path):
    fmt = FlagFormat(r"KEY-[0-9a-f]{8}")
    assert fmt.find("value KEY-deadbeef here") == ["KEY-deadbeef"]
    assert fmt.find("flag{nope}") == []


def test_invalid_format_regex_rejected():
    with pytest.raises(ValueError):
        FlagFormat("([unclosed")


# --- heuristic verifier -----------------------------------------------------

def test_heuristic_accepts_formatted_flag():
    v = HeuristicFlagVerifier().verify("flag{this_is_a_flag}")
    assert v.status == "verified"
    assert v.conclusive is False
    assert v.verifier == "heuristic-format"


def test_heuristic_rejects_unformatted():
    assert HeuristicFlagVerifier().verify("not-a-flag").status == "format_invalid"


def test_heuristic_rejects_empty():
    assert HeuristicFlagVerifier().verify("   ").status == "format_invalid"


def test_verdict_to_candidate_carries_status():
    v = HeuristicFlagVerifier().verify("flag{ok}")
    cand = v.to_candidate(source="file x")
    assert cand.value == "flag{ok}"
    assert cand.status == "verified"
    assert cand.source == "file x"


def test_verify_flag_default_is_heuristic_even_with_submit_config():
    submit = {"url": "https://example.test/submit", "token": "t"}
    v = verify_flag("flag{local}", submit=submit, allow_remote=False)
    assert v.verifier == "heuristic-format"


# --- http verifier (injected transport) -------------------------------------

def test_http_verifier_accepts():
    def post(url, payload, headers, timeout):
        assert payload["flag"] == "flag{remote}"
        return FakeResponse(200, '{"success": true}')

    v = HttpFlagVerifier("https://ctf.test/submit", token="tok", http_post=post)  # noqa: S106
    verdict = v.verify("flag{remote}")
    assert verdict.status == "verified"
    assert verdict.conclusive is True


def test_http_verifier_rejects():
    def post(url, payload, headers, timeout):
        return FakeResponse(200, '{"success": false}')

    v = HttpFlagVerifier("https://ctf.test/submit", http_post=post)
    assert v.verify("flag{bad}").status == "incorrect"


def test_http_verifier_network_error_is_unverified():
    def post(url, payload, headers, timeout):
        raise ConnectionError("boom")

    v = HttpFlagVerifier("https://ctf.test/submit", http_post=post)
    verdict = v.verify("flag{x}")
    assert verdict.status == "unverified"


def test_http_verifier_requires_http_url():
    with pytest.raises(ValueError):
        HttpFlagVerifier("ftp://nope")


def test_verify_flag_remote_when_enabled():
    submit = {"url": "https://ctf.test/submit", "token": "t"}

    def post(url, payload, headers, timeout):
        return FakeResponse(200, "correct!")

    v = verify_flag("flag{remote}", submit=submit, allow_remote=True, http_post=post)
    assert v.status == "verified"
    assert v.conclusive is True
