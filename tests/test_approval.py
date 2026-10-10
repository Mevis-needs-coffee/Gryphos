"""Approval enforcement tests."""

from gryphos.approval import ApprovalManager, ApprovalRequest, action_fingerprint


def make_request(target="127.0.0.1", tool="nmap_basic", args=None) -> ApprovalRequest:
    return ApprovalRequest(
        tool=tool,
        target=target,
        args=args if args is not None else {"target": target},
        purpose="test",
        display="display",
        network_active=True,
        timeout=10,
        output_limit=1000,
        risk="low",
        side_effects="probes",
    )


def test_default_deny_without_decision():
    mgr = ApprovalManager()
    assert mgr.authorize(make_request()) is False


def test_approved_single_use():
    mgr = ApprovalManager()
    req = make_request()
    mgr.record(req, approved=True)
    assert mgr.authorize(req) is True    # consumes
    assert mgr.authorize(req) is False   # reuse denied


def test_declined_denies():
    mgr = ApprovalManager()
    req = make_request()
    mgr.record(req, approved=False)
    assert mgr.authorize(req) is False


def test_modified_args_need_new_approval():
    mgr = ApprovalManager()
    original = make_request(target="127.0.0.1")
    mgr.record(original, approved=True)
    modified = make_request(target="127.0.0.1", args={"target": "127.0.0.1", "port": 8080})
    assert original.fingerprint != modified.fingerprint
    assert mgr.authorize(modified) is False


def test_modified_target_needs_new_approval():
    mgr = ApprovalManager()
    a = make_request(target="127.0.0.1")
    b = make_request(target="192.168.56.10")
    assert a.fingerprint != b.fingerprint
    mgr.record(a, approved=True)
    assert mgr.authorize(b) is False


def test_fingerprint_stable_across_key_order():
    f1 = action_fingerprint("t", "1.2.3.4", {"a": 1, "b": 2})
    f2 = action_fingerprint("t", "1.2.3.4", {"b": 2, "a": 1})
    assert f1 == f2


def test_fingerprint_changes_with_tool():
    f1 = action_fingerprint("t", "1.2.3.4", {})
    f2 = action_fingerprint("t2", "1.2.3.4", {})
    assert f1 != f2


def test_record_carries_fingerprint():
    req = make_request()
    rec = req.to_record()
    assert rec["fingerprint"] == req.fingerprint
    assert rec["tool"] == "nmap_basic"


def test_reason_is_display_only_and_not_fingerprinted():
    base = make_request()
    with_reason = ApprovalRequest(
        tool="nmap_basic", target="127.0.0.1", args={"target": "127.0.0.1"},
        purpose="p", display="d", network_active=True, timeout=10, output_limit=1000,
        risk="low", side_effects="s", reason="totally different rationale",
    )
    assert base.fingerprint == with_reason.fingerprint
