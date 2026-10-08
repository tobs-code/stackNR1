"""OPA-Client fail-closed: nur exakt allow==True ohne Violations gilt."""
import httpx
import pytest

from control_stack.policy.client import OPAClient, PolicyError


def _client(allow=None, viol=[], status=200, raw=None, exc=None):
    def h(req):
        if exc:
            raise exc
        if "authz" in req.url.path:
            body = allow
        else:
            body = viol
        if raw is not None and "authz" in req.url.path:
            return httpx.Response(status, text=raw)
        return httpx.Response(status, json={"result": body})
    return OPAClient("http://opa", transport=httpx.MockTransport(h))


def test_allow_granted():
    d = _client(True, []).decide({"action": "x"})
    assert d.granted is True


@pytest.mark.parametrize("allow,viol", [
    (False, []), (True, ["stale-state"]), (None, []), ("yes", []),
    (True, "stale-state"), (True, [123]),
])
def test_anything_else_is_not_granted_or_raises(allow, viol):
    c = _client(allow, viol)
    try:
        d = c.decide({"action": "x"})
        assert d.granted is False
    except PolicyError:
        pass


def test_http_error_fail_closed():
    with pytest.raises(PolicyError):
        _client(True, [], status=500).decide({})


def test_invalid_json_fail_closed():
    with pytest.raises(PolicyError):
        _client(raw="kein json {{{").decide({})


def test_missing_result_schema_fail_closed():
    def h(req):
        return httpx.Response(200, json={"oops": 1})
    c = OPAClient("http://opa", transport=httpx.MockTransport(h))
    with pytest.raises(PolicyError):
        c.decide({})


def test_unreachable_fail_closed():
    def h(req):
        raise httpx.ConnectError("down")
    c = OPAClient("http://opa", transport=httpx.MockTransport(h))
    with pytest.raises(PolicyError):
        c.decide({})
