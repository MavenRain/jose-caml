# jose-caml: design

A misuse-proof JOSE / OIDC ID-token verification library in OCaml. The type
system makes the classic JWT identity CVEs unrepresentable:

- Claims are phantom-typed `unverified` vs `verified`. Identity-bearing
  accessors (`subject`, `issuer`, ...) exist only on `verified` claims, and
  only the full verification pipeline can produce a `verified` value.
- The algorithm is fixed at key-construction time. A key is `hs256 Key.t`,
  `rs256 Key.t`, or `es256 Key.t`. There is no key for `alg: none`, so an
  unsigned token cannot verify. A token whose header names a different
  algorithm than the key is rejected before any crypto runs, so RS256/HS256
  confusion does not get to the MAC.
- Audience, issuer, and expiry are mandatory witnesses. `Expect.make` does
  not typecheck without `~iss` and `~aud`; `verify` does not typecheck
  without `~now`; a token without an `exp` claim is rejected. You cannot
  extract a subject from a token that skipped any of these checks.

Ships with two harnesses:

1. A compile-fail harness: OCaml snippets that encode each misuse (read a
   claim before verification, build an expectation without an audience,
   verify with a mismatched key type). The gate proves each snippet is
   rejected by the type checker, and proves a control snippet compiles, so
   the failures are not vacuous.
2. A runtime CVE-corpus harness: token vectors that replay the known JOSE
   CVE classes (alg=none, RS256->HS256 confusion, embedded jwk header, kid
   injection, psychic ECDSA signatures, non-canonical base64url, duplicate
   claims). Each vector must be rejected with the expected typed error.
   An optional script cross-checks the corpus against node `jose` /
   `jsonwebtoken` when node is present.

Identity teams triage these exact bug classes constantly. This library
deletes the class instead of patching instances.

## 1. Dependencies

Stdlib-only core, plus two of our own pinned libraries (karamel-710 switch):

- `ctlk_topos` (git+file pin): the CTLK-in-topos model-checker kernel, for
  the `model/` layer. Not yet in `jose_caml.opam` depends: it becomes an
  opam dependency when the `model/` layer lands at M13.
- `sha2` (git+file pin): SHA-256 / SHA-512, for HMAC, RSA digest info, and
  the ECDSA message digest.

Bignum (`limbs`) and P-256 verification are ported from tinysvid `sig/`
(same author, same conventions) and adapted: JOSE ES256 signatures are raw
`r || s` (64 bytes), not DER.

## 2. Threat model: the CVE corpus this design deletes

| Class | Instance | Where it dies here |
|---|---|---|
| alg=none accepted | CVE-2015-9235 (jwt-simple), pyjwt, many | `Alg.of_string "none"` is `Error Alg_unsupported`; no `none Key.t` exists |
| RS256->HS256 key confusion | CVE-2016-5431, CVE-2016-10555 | header alg must equal the key's phantom alg before crypto; `Key.hs256` rejects PEM/DER-shaped secrets |
| Embedded jwk header trusted | CVE-2018-0114 (node-jose) | any `jwk`, `jku`, `x5u`, `x5c`, `x5t` header member is a typed reject; keys come only from the caller's keyset |
| kid injection (path/SQL) | Auth0 advisories, many | `kid` is an opaque string, only ever compared for equality against the caller's keyset entries |
| Psychic signatures (r=0 or s=0) | CVE-2022-21449 (Java) | ES256 rejects r=0, s=0, r>=n_order, s>=n_order before point math |
| Signature stripping / empty sig | many | the compact form must have exactly 3 parts; an empty signature part fails base64url length rules for every algorithm |
| Non-canonical base64url | jwt bypass class | decoder rejects padding, non-alphabet bytes, and non-zero trailing bits |
| Duplicate JSON keys | claim-smuggling class | the JSON parser rejects duplicate object keys at any depth |
| Missing exp / eternal tokens | operational class | `exp` is mandatory; absent `exp` is `Missing_claim "exp"` |
| aud not checked | cross-service replay | `Expect.make` requires `~aud`; `verify` requires an `Expect.t` |
| crit bypass | RFC 7515 4.1.11 | any `crit` member is `Crit_unsupported` (we implement no extensions) |
| compression bombs | `zip` header | `zip` member is a typed reject |

## 3. API shape (lib/)

```ocaml
module Alg : sig
  type t = HS256 | RS256 | ES256          (* closed; "none" never parses *)
  val of_string : string -> (t, Error.t) result
end

module Key : sig
  type hs256  and rs256  and es256        (* phantom, uninhabited *)
  type 'alg t                             (* abstract *)
  val hs256 : secret:string -> (hs256 t, Error.t) result
    (* rejects secrets under 32 bytes and PEM/DER-shaped secrets *)
  val rs256 : n:string -> e:string -> (rs256 t, Error.t) result
    (* big-endian magnitudes, as in JWK; bounds checked *)
  val es256 : x:string -> y:string -> (es256 t, Error.t) result
    (* 32-byte coordinates; point must be on the curve *)
end

module Claims : sig
  type unverified  and verified           (* phantom *)
  type 'v t
  val subject   : verified t -> string option
  val issuer    : verified t -> string
  val audiences : verified t -> string list
  val expires   : verified t -> Time.t
  val jti       : verified t -> string option
  val claim     : verified t -> string -> Json.t option
  (* no accessor takes [unverified t]; only [Jwt.verify] makes [verified t] *)
end

module Expect : sig
  type t
  val make : iss:Issuer.t -> aud:Audience.t -> ?skew:Skew.t -> unit -> t
end

module Jwt : sig
  val verify :
    key:'alg Key.t -> expect:Expect.t -> now:Time.t -> string ->
    (Claims.verified Claims.t, Error.t) result
  val kid_hint : string -> string option  (* opaque kid, for keyset lookup *)
end
```

The pipeline order inside `Jwt.verify` is fixed and is the shared
`verify_core` state machine (section 4): split -> header parse (alg equals
key alg, no crit, no embedded key material, no zip) -> signature check ->
payload JSON -> claims parse -> iss equal -> aud member -> exp present and
`now < exp + skew` -> nbf/iat sanity -> admit. Every early exit is a typed
error naming the check that failed.

`verified` is produced in exactly one place. Rejected tokens never surface
partial claims.

## 4. Model-driven method

Same method as tinysvid / x402-caml / tf-audit: `model/` holds a CTLK model
over the `ctlk_topos` kernel, and the transition guard logic is one shared
OCaml file (`lib/verify_core.ml`, copy_files into the model library) so the
model checks the same code that runs in the library.

States: the pipeline position plus what the adversary controlled in the
token (alg field, signature validity, claim set). Adversary actions build
the token; the verifier steps the pipeline. Target properties:

- P1 safety: `AG (admitted -> sig_ok /\ alg_matched /\ aud_ok /\ iss_ok /\ fresh)`.
- P2 alg=none: `AG (alg_none -> AG (not admitted))`.
- P3 confusion: `AG (alg_mismatch -> AX rejected)` (rejection precedes crypto).
- P4 no resurrection: `AG (rejected -> AG (not admitted))`.
- P5 knowledge: after admit, the relying party *knows* the audience and
  issuer matched (K_verifier over the view that hides the adversary's
  private choices).
- P6 stripping: a token whose signature the adversary did not forge is
  admitted on no path (EF admitted fails from every forged-free tamper
  state).

`test/test_correspondence.ml` pins model transitions to library behavior on
a shared vector set.

## 5. Strictness profile

- JSON: objects/arrays/strings/ints/bools/null; depth-bounded; duplicate
  keys rejected; ints must fit OCaml's int (63-bit) with no leading zeros,
  no fraction, no exponent; standard whitespace only. This is a verifier,
  not a general JSON tool; anything outside the profile is a typed reject.
- base64url: RFC 7515 flavor; no padding, no line breaks, canonical
  trailing bits, length mod 4 <> 1.
- Sizes: token <= 16 KiB, header <= 4 KiB, JSON depth <= 32. Caps are
  constants in one module.
- Time: `Time.t` is seconds since epoch (int). `Skew.t` is bounded to
  [0, 600] s at construction.
- HS256 secrets: >= 32 bytes (RFC 7518 3.2), and never PEM/DER-shaped.
- Comparison of MACs is constant-time (fold XOR).

## 6. Milestones

| M | What | Status |
|---|---|---|
| M1 | scaffold: dune-project, licenses, gates.sh, DESIGN.md | DONE |
| M2 | `b64url.ml` strict base64url + tests | DONE |
| M3 | `json.ml` strict JSON, duplicate-key reject + tests | DONE |
| M4 | `error.ml`, `alg.ml`, `header.ml` (crit/jwk/jku/zip rejects) + tests | DONE |
| M5 | `hmac.ml` (RFC 4231 vectors, python3 differential) + `key.ml` HS256 | DONE |
| M6 | `jws.ml` compact verify for HS256; RFC 7515 A.1 vector | DONE |
| M7 | `time.ml`, `claims.ml`, `expect.ml`, `jwt.ml`: phantom admit pipeline | DONE |
| M8 | compile-fail harness (misuse snippets + compiling control) | DONE |
| M9 | `limbs.ml` bignum port + arbitrary-modulus modexp + tests | DONE |
| M10 | `rsax.ml` PKCS#1 v1.5 verify, `Key.rs256`, RFC 7515 A.2 vector | DONE |
| M11 | `p256.ml` port, ES256 raw r||s, RFC 7515 A.3 vector, psychic rejects | TODO |
| M12 | `jwk.ml` / JWKS: typed JWK parse, opaque-kid lookup, RFC 7517 vectors | TODO |
| M13 | `verify_core.ml` extraction + CTLK model + P1..P6 + correspondence gate | TODO |
| M14 | runtime CVE-corpus harness (section 2 table, one vector per row) | TODO |
| M15 | `oidc.ml` ID-token layer: nonce witness, azp rule, multi-aud | TODO |
| M16 | node differential script (`jose`, `jsonwebtoken`), skipped w/o node | TODO |
| M17 | hardening: caps enforced everywhere, random-mutation sweep on valid tokens | TODO |
| M18 | README + pitch, ZxCaml artifact of a verifier CLI + size table | TODO |

## 7. Gates

`./gates.sh`: dune build (0 warnings) + every test suite + model check +
correspondence + compile-fail harness + CVE corpus. Each milestone lands
BUILT+GATED+MUTATION-CONFIRMED (behavioral mutants, KILLED(compile) is
vacuous) before review. Nothing is committed by the assistant.
