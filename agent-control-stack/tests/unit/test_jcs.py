"""JCS-Vorbehalt (Rev. 4): Referenzvektoren für den erlaubten Typbereich
+ Ablehnung von Floats/non-str-Keys. Keine volle RFC-8785-Behauptung."""
import pytest

from control_stack.contracts import canon


def test_reference_vectors():
    assert canon({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert canon({"z": [3, 2, {"y": True, "x": None}]}) == b'{"z":[3,2,{"x":null,"y":true}]}'
    assert canon({"ä": "ü"}) == '{"ä":"ü"}'.encode("utf-8")  # UTF-8, kein ASCII-Escape
    assert canon({}) == b"{}"


def test_restricted_types_enforced():
    with pytest.raises(TypeError):
        canon({"a": 1.5})
    with pytest.raises(TypeError):
        canon({"a": float("nan")})
    with pytest.raises(TypeError):
        canon({1: "x"})
    with pytest.raises(TypeError):
        canon({"a": object()})
