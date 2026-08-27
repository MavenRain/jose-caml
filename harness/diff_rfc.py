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

# M9 limbs: recompute the 255-bit modexp vector with python pow() and
# require modulus, base, and result to sit verbatim in test_limbs.ml,
# plus the toy-RSA verify pair.
test_limbs = root / "test" / "test_limbs.ml"
m9_m = 2**255 - 19
m9_b = int("4a7c559911fa2016c34479067b47d02be2b17b0b1b0d8a2d6d312bc939b204d1", 16)
must_contain(test_limbs, format(m9_m, "x"), "m9 modexp modulus")
must_contain(test_limbs, format(m9_b, "x"), "m9 modexp base")
must_contain(test_limbs, format(pow(m9_b, 65537, m9_m), "064x"), "m9 modexp result")
must_contain(test_limbs, str(pow(65, 17, 3233)), "m9 rsa toy sign")
must_contain(test_limbs, str(pow(2790, 2753, 3233)), "m9 rsa toy verify")

# M10 RFC 7515 A.2: redo the whole RSASSA-PKCS1-v1_5 verify with python
# pow() -- signature^e mod n must equal the exact EM built from python's
# own sha256 of the signing input -- then require every 64-char fragment
# of the constants to sit verbatim in test_rsa.ml. The EM check makes
# the pinned vector self-authenticating: a mistyped constant cannot
# satisfy it.


def b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


a2_h64 = "eyJhbGciOiJSUzI1NiJ9"
a2_p64 = (
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
)
a2_n64 = (
    "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp"
    "-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOW"
    "vG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUs"
    "LA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9k"
    "G4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2"
    "PAcDTW9gb54h4FRWyuXpoQ"
)
a2_e64 = "AQAB"
a2_s64 = (
    "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
    "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
    "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
    "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
    "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
    "p0igcN_IoypGlUPQGe77Rw"
)
a2_n = int.from_bytes(b64u(a2_n64), "big")
a2_e = int.from_bytes(b64u(a2_e64), "big")
a2_s = int.from_bytes(b64u(a2_s64), "big")
a2_k = len(b64u(a2_n64))
a2_di = bytes.fromhex("3031300d060960864801650304020105000420")
a2_hash = hashlib.sha256(f"{a2_h64}.{a2_p64}".encode()).digest()
a2_em = (
    b"\x00\x01"
    + b"\xff" * (a2_k - len(a2_di) - 32 - 3)
    + b"\x00"
    + a2_di
    + a2_hash
)
if pow(a2_s, a2_e, a2_n).to_bytes(a2_k, "big") != a2_em:
    print("diff_rfc: rfc7515 a2 rsa verify FAILED to recompute")
    fail = 1
else:
    print("diff_rfc: rfc7515 a2 rsa verify ok")

test_rsa = root / "test" / "test_rsa.ml"
for name, value in (("n", a2_n64), ("s", a2_s64)):
    for i in range(0, len(value), 64):
        must_contain(test_rsa, value[i : i + 64], f"rfc7515 a2 {name}[{i}]")
must_contain(test_rsa, a2_h64, "rfc7515 a2 header")
must_contain(test_rsa, a2_e64, "rfc7515 a2 e")

# M11 RFC 7515 A.3: redo the whole ECDSA P-256 verify with python
# integers (affine point math, pow(-1) inverses): u1*G + u2*Q must land
# on x == r mod n. Then require the constants to sit verbatim in
# test_p256.ml, including the derived off-curve and boundary constants
# the negative tests use, so those negatives are pinned to independently
# recomputed values too.


def enc(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


p256_p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
p256_n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
p256_b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
p256_gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
p256_gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def ec_on_curve(x: int, y: int) -> bool:
    return (y * y - (x * x * x - 3 * x + p256_b)) % p256_p == 0


def ec_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p256_p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 - 3) * pow(2 * y1, -1, p256_p) % p256_p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p256_p) % p256_p
    x3 = (lam * lam - x1 - x2) % p256_p
    return (x3, (lam * (x1 - x3) - y1) % p256_p)


def ec_mul(k: int, P):
    R = None
    while k:
        if k & 1:
            R = ec_add(R, P)
        P = ec_add(P, P)
        k >>= 1
    return R


a3_h64 = "eyJhbGciOiJFUzI1NiJ9"
a3_p64 = a2_p64
a3_x64 = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
a3_y64 = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
a3_s64 = (
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
    "pmWQxfKTUJqPP3-Kg6NU1Q"
)
a3_qx = int.from_bytes(b64u(a3_x64), "big")
a3_qy = int.from_bytes(b64u(a3_y64), "big")
a3_sig = b64u(a3_s64)
a3_r = int.from_bytes(a3_sig[:32], "big")
a3_s = int.from_bytes(a3_sig[32:], "big")
a3_e = (
    int.from_bytes(
        hashlib.sha256(f"{a3_h64}.{a3_p64}".encode()).digest(), "big"
    )
    % p256_n
)
a3_ok = (
    len(a3_sig) == 64
    and ec_on_curve(a3_qx, a3_qy)
    and 0 < a3_r < p256_n
    and 0 < a3_s < p256_n
)
if a3_ok:
    a3_w = pow(a3_s, -1, p256_n)
    a3_point = ec_add(
        ec_mul(a3_e * a3_w % p256_n, (p256_gx, p256_gy)),
        ec_mul(a3_r * a3_w % p256_n, (a3_qx, a3_qy)),
    )
    a3_ok = a3_point is not None and a3_point[0] % p256_n == a3_r
if not a3_ok:
    print("diff_rfc: rfc7515 a3 ecdsa verify FAILED to recompute")
    fail = 1
else:
    print("diff_rfc: rfc7515 a3 ecdsa verify ok")

a3_off_y = a3_qy ^ 1
if ec_on_curve(a3_qx, a3_off_y):
    print("diff_rfc: a3 flipped y is unexpectedly ON the curve")
    fail = 1

test_p256 = root / "test" / "test_p256.ml"
for i in range(0, len(a3_s64), 64):
    must_contain(test_p256, a3_s64[i : i + 64], f"rfc7515 a3 sig[{i}]")
must_contain(test_p256, a3_h64, "rfc7515 a3 header")
must_contain(test_p256, a3_x64, "rfc7515 a3 x")
must_contain(test_p256, a3_y64, "rfc7515 a3 y")
must_contain(
    test_p256, enc(a3_off_y.to_bytes(32, "big")), "a3 off-curve y"
)
must_contain(
    test_p256, enc(p256_p.to_bytes(32, "big")), "p-256 field prime"
)
must_contain(
    test_p256, enc(p256_n.to_bytes(32, "big")), "p-256 group order"
)

sys.exit(fail)
