"""ScopeStorm unit tests -- pure logic, no network.

Run either way:
    python tests/test_scopestorm.py      # plain, zero deps
    pytest tests/                         # if pytest is installed
"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scopestorm as s


def _roe(**over):
    data = {"engagement_id": "E", "client": "C", "authorized_hosts": ["localhost"]}
    data.update(over)
    p = tempfile.mktemp(suffix=".json")
    Path(p).write_text(json.dumps(data), encoding="utf-8")
    return s.RulesOfEngagement.load(p)


# ---- scope enforcement --------------------------------------------------
def test_authorizes_in_scope():
    _roe().authorizes("http://localhost:8000/x")  # no raise


def test_refuse_out_of_scope():
    try:
        _roe().authorizes("http://evil.com/")
    except ValueError:
        return
    raise AssertionError("expected out-of-scope refusal")


def test_refuse_non_http_and_creds():
    for bad in ("ftp://localhost/", "http://u:p@localhost/"):
        try:
            _roe().authorizes(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected refusal for {bad}")


def test_window_open_when_empty():
    assert _roe().in_allowed_window() is True


# ---- helpers ------------------------------------------------------------
def test_parse_headers():
    assert s.parse_headers(["A: b"]) == {"A": "b"}
    try:
        s.parse_headers(["nope"])
    except ValueError:
        return
    raise AssertionError("expected header parse error")


def test_render_tokens():
    assert s.render_tokens("x/{{seq}}", 9) == "x/9"
    assert s.render_tokens("plain", 1) == "plain"
    assert len(s.render_tokens("{{uuid}}", 1)) == 32


def test_percentile():
    assert s.percentile([1, 2, 3, 4, 5], 95) >= 4


def test_user_agent():
    assert s.user_agent("E") == "ScopeStorm/1.0 (engagement=E)"


def test_patterns_within_caps():
    for fn in s.PATTERNS.values():
        for t in range(0, 61, 5):
            assert 1 <= fn(t, 60, 8) <= 8


def test_knee_sample():
    assert s.knee_sample([10] * 15 + [500] * 15, 100) == 15
    assert s.knee_sample([10] * 30, 100) is None


# ---- operator alias / optionality --------------------------------------
def test_operator_alias_precedence():
    assert _roe(operator="real@me", operator_alias="rt-7").operator_label == "rt-7"
    assert _roe(operator="real@me").operator_label == "real@me"
    assert _roe().operator_label == "unspecified"            # both optional


def test_alias_hides_real_operator_in_report():
    roe = _roe(operator="real@me.com", operator_alias="rt-7")
    m = s.Metrics()
    m.add_success(200, 10)
    cfg = {"url": "http://localhost/", "method": "GET", "pattern": "constant",
           "duration": 1, "concurrency": 1, "rps": 1}
    rep = s.build_report(roe, cfg, m, 1.0, None)
    assert rep["operator"] == "rt-7"
    assert "real@me.com" not in json.dumps(rep)


# ---- report knee --------------------------------------------------------
def test_report_includes_knee():
    roe = _roe(abort_p95_latency_ms=100)
    m = s.Metrics()
    for v in [10] * 15 + [500] * 15:
        m.add_success(200, v)
    cfg = {"url": "http://x/", "method": "GET", "pattern": "ramp-up",
           "duration": 30, "concurrency": 3, "rps": 5}
    rep = s.build_report(roe, cfg, m, 30.0, None)
    assert rep["degradation_knee"]["sample_index"] == 15


# ---- audit chain --------------------------------------------------------
def test_audit_verify_and_tamper():
    d = tempfile.mkdtemp()
    ap = os.path.join(d, "a.jsonl")
    al = s.AuditLog(ap, "ENG-X")
    al.record("test_start", x=1)
    al.record("test_end", y=2)
    assert s.AuditLog(ap, "ENG-X").verify() is True
    lines = Path(ap).read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[0]); obj["x"] = 999
    lines[0] = json.dumps(obj)
    Path(ap).write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert s.AuditLog(ap, "ENG-X").verify() is False


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  [PASS] {t.__name__}")
            passed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"  [FAIL] {t.__name__}: {exc}")
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
