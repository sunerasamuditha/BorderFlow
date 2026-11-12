from borderflow.envelope import KeyPair, KeyRegistry, build_envelope, verify_envelope
from borderflow.labels import Label


def setup():
    a, b = KeyPair.generate("A"), KeyPair.generate("B")
    reg = KeyRegistry()
    reg.register(a)
    reg.register(b)
    return a, b, reg


def test_valid_envelope_verifies():
    a, _, reg = setup()
    content = {"text": "hello"}
    env = build_envelope(a, Label.of({"A", "B"}, {"U"}), content, "result")
    check = verify_envelope(reg, env, content, expected_sender="A")
    assert check.valid and check.label == Label.of({"A", "B"}, {"U"})


def test_tampered_content_and_label_are_detected():
    a, _, reg = setup()
    content = {"text": "hello"}
    env = build_envelope(a, Label.of({"A"}, {"U"}), content, "result")
    assert verify_envelope(reg, env, {"text": "HELLO"}).reason == "digest-mismatch"
    forged = dict(env, w=[])
    assert verify_envelope(reg, forged, content).reason == "bad-signature"


def test_impersonation_is_detected():
    a, b, reg = setup()
    content = {"text": "x"}
    env = build_envelope(b, Label.of(None, []), content, "result")
    assert verify_envelope(reg, env, content, expected_sender="A").reason == "unexpected-signer"
    env2 = dict(env, snd="A")
    assert not verify_envelope(reg, env2, content).valid


def test_integral_floats_do_not_break_signatures():
    a, _, reg = setup()
    env = build_envelope(a, Label.of(None, ["U"]), {"data": {"n": 10}}, "result")
    roundtrip = dict(env, v=1.0, seq=0.0)
    assert verify_envelope(reg, roundtrip, {"data": {"n": 10.0}}).valid
