from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .labels import Label

ENVELOPE_KEY = "bf"
EXTENSION_URI = "https://example.org/a2a/ext/borderflow/v1"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _normalize(obj):
    if isinstance(obj, float) and obj.is_integer():
        return int(obj)
    if isinstance(obj, dict):
        return {k: _normalize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_normalize(v) for v in obj]
    return obj


def canonical(obj) -> bytes:
    return json.dumps(_normalize(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(content) -> str:
    return "sha256:" + b64url(hashlib.sha256(canonical(content)).digest())


@dataclass
class KeyPair:
    principal: str
    private_key: ec.EllipticCurvePrivateKey = field(repr=False)

    @staticmethod
    def generate(principal: str) -> "KeyPair":
        return KeyPair(principal, ec.generate_private_key(ec.SECP256R1()))

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self.private_key.public_key()

    def sign(self, data: bytes) -> bytes:
        der = self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_raw(public_key: ec.EllipticCurvePublicKey, data: bytes, signature: bytes) -> bool:
    if len(signature) != 64:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    try:
        public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


class KeyRegistry:
    def __init__(self) -> None:
        self._keys: dict[str, ec.EllipticCurvePublicKey] = {}

    def register(self, keypair: KeyPair) -> None:
        self._keys[keypair.principal] = keypair.public_key

    def get(self, principal: str) -> Optional[ec.EllipticCurvePublicKey]:
        return self._keys.get(principal)


def sign_detached_jws(keypair: KeyPair, payload: dict) -> str:
    header = {"alg": "ES256", "kid": keypair.principal}
    signing_input = b64url(canonical(header)) + "." + b64url(canonical(payload))
    signature = keypair.sign(signing_input.encode("ascii"))
    return b64url(canonical(header)) + ".." + b64url(signature)


def verify_detached_jws(registry: KeyRegistry, jws: str, payload: dict) -> Optional[str]:
    try:
        header_b64, empty, sig_b64 = jws.split(".")
        if empty:
            return None
        header = json.loads(b64url_decode(header_b64))
        if header.get("alg") != "ES256":
            return None
        key = registry.get(header.get("kid", ""))
        if key is None:
            return None
        signing_input = header_b64 + "." + b64url(canonical(payload))
        if verify_raw(key, signing_input.encode("ascii"), b64url_decode(sig_b64)):
            return header["kid"]
        return None
    except (ValueError, KeyError, json.JSONDecodeError):
        return None


def build_envelope(keypair: KeyPair, label: Label, content, channel: str, ctx: str = "", seq: int = 0) -> dict:
    body = {
        "v": 1,
        "ch": channel,
        "ctx": ctx,
        "seq": seq,
        "snd": keypair.principal,
        **label.to_json(),
        "d": digest(content),
    }
    return {**body, "sig": sign_detached_jws(keypair, body)}


@dataclass
class EnvelopeCheck:
    valid: bool
    label: Optional[Label]
    sender: Optional[str]
    reason: str


def verify_envelope(registry: KeyRegistry, envelope: Optional[dict], content, expected_sender: Optional[str] = None) -> EnvelopeCheck:
    if not envelope:
        return EnvelopeCheck(False, None, None, "absent")
    body = {k: v for k, v in envelope.items() if k != "sig"}
    signer = verify_detached_jws(registry, envelope.get("sig", ""), body)
    if signer is None:
        return EnvelopeCheck(False, None, None, "bad-signature")
    if body.get("snd") != signer:
        return EnvelopeCheck(False, None, None, "sender-mismatch")
    if expected_sender is not None and signer != expected_sender:
        return EnvelopeCheck(False, None, signer, "unexpected-signer")
    if body.get("d") != digest(content):
        return EnvelopeCheck(False, None, signer, "digest-mismatch")
    return EnvelopeCheck(True, Label.from_json(body), signer, "ok")


def envelope_size(envelope: dict) -> int:
    return len(canonical(envelope))
