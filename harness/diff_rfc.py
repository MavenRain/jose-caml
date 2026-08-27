#!/usr/bin/env python3
"""Differential gate: recompute the RFC vectors with python's own
hashlib/hmac and require the recomputed values to appear verbatim in the
OCaml test sources. That pins the constants the OCaml suites enforce to
an independent implementation."""

import base64
import hashlib
import hmac
import pathlib
import sys

here = pathlib.Path(__file__).resolve().parent
root = here.parent

fail = 0


def must_contain(path: pathlib.Path, needle: str, label: str) -> None:
    global fail
    if needle not in path.read_text():
        print(f"diff_rfc: {label}: recomputed value not found in {path.name}")
        print(f"  wanted: {needle}")
        fail = 1
    else:
        print(f"diff_rfc: {label} ok")


def hs256(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


test_hmac = root / "test" / "test_hmac.ml"
must_contain(test_hmac, hs256(b"\x0b" * 20, b"Hi There"), "rfc4231 tc1")
must_contain(
    test_hmac, hs256(b"Jefe", b"what do ya want for nothing?"), "rfc4231 tc2"
)
must_contain(test_hmac, hs256(b"\xaa" * 20, b"\xdd" * 50), "rfc4231 tc3")
must_contain(
    test_hmac,
    hs256(
        b"\xaa" * 131,
        b"Test Using Larger Than Block-Size Key - Hash Key First",
    ),
    "rfc4231 tc6",
)

# RFC 7515 A.1: recompute the signature from the A.1 key and signing
# input, then require both the key fragments and the recomputed
# signature to sit in test_jwt.ml.
a1_key = base64.urlsafe_b64decode(
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T"
    "-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow" + "=="
)
a1_h64 = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
a1_p64 = (
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
)
a1_sig = (
    base64.urlsafe_b64encode(
        hmac.new(a1_key, f"{a1_h64}.{a1_p64}".encode(), hashlib.sha256).digest()
    )
    .rstrip(b"=")
    .decode()
)
test_jwt = root / "test" / "test_jwt.ml"
must_contain(test_jwt, a1_sig, "rfc7515 a1 signature")
must_contain(test_jwt, a1_h64, "rfc7515 a1 header")
must_contain(test_jwt, "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T", "rfc7515 a1 key")

sys.exit(fail)
