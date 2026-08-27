(* jose-caml: misuse-proof JOSE / OIDC token verification.

   The signature below is the whole public API. What it does not export
   is the point: there is no way to read an identity claim from a token
   that did not pass signature, issuer, audience, and expiry checks, no
   way to build a key for "none", and no way to verify a token whose
   header algorithm differs from the key's. *)

module Error : sig
  type t =
    | B64_invalid of string
    | Json_invalid of string
    | Token_shape of string
    | Alg_unsupported of string
    | Alg_mismatch of { token : string; key : string }
    | Header_rejected_member of string
    | Crit_unsupported
    | Typ_rejected of string
    | Header_malformed of string
    | Sig_invalid
    | Key_rejected of string
    | Missing_claim of string
    | Claim_malformed of string
    | Iss_mismatch
    | Aud_mismatch
    | Expired of { exp : int; now : int }
    | Not_yet_valid of { nbf : int; now : int }
    | Iat_in_future of { iat : int; now : int }
    | Time_invalid of string
    | Expect_invalid of string

  val to_string : t -> string
end

module B64url : sig
  (* Strict base64url: no padding, canonical trailing bits, no bytes
     outside the alphabet, length mod 4 <> 1. *)
  val encode : string -> string
  val decode : string -> (string, Error.t) result
end

module Json : sig
  (* Strict minimal JSON: duplicate keys rejected at every depth,
     nesting capped, canonical 63-bit integers only. *)
  type t =
    | Jnull
    | Jbool of bool
    | Jint of int
    | Jstring of string
    | Jlist of t list
    | Jobj of (string * t) list

  val parse : string -> (t, string) result
  val emit : t -> string
  val member : string -> t -> t option
  val as_string : t -> string option
  val as_int : t -> int option
end

module Alg : sig
  (* Closed. "none" is not a member. *)
  type t = HS256 | RS256 | ES256

  val of_string : string -> (t, Error.t) result
  val to_string : t -> string
  val equal : t -> t -> bool
end

module Hmac : sig
  val sha256 : key:string -> string -> string
  val equal_ct : string -> string -> bool
end

module Time : sig
  (* Seconds since the Unix epoch, supplied by the caller. The library
     never reads a clock. *)
  type t

  val of_epoch_seconds : int -> (t, Error.t) result
  val seconds : t -> int

  module Skew : sig
    type t

    val of_seconds : int -> (t, Error.t) result
    val zero : t
    val seconds : t -> int
  end
end

module Key : sig
  (* The algorithm is part of the key's type. Constructing a key is the
     only place an algorithm is chosen; tokens do not get a vote. *)
  type hs256
  type rs256
  type es256
  type 'alg t

  (* Rejects secrets shorter than 32 bytes (RFC 7518 3.2) and secrets
     that look like asymmetric key material (PEM, DER, base64 DER), so
     an RS256 public key cannot be smuggled in as a MAC secret. *)
  val hs256 : secret:string -> (hs256 t, Error.t) result

  val alg : 'alg t -> Alg.t
end

module Expect : sig
  (* What the relying party expects. [make] does not typecheck without
     an issuer and an audience: they are mandatory witnesses. *)
  type issuer
  type audience
  type t

  val issuer : string -> (issuer, Error.t) result
  val audience : string -> (audience, Error.t) result
  val make : iss:issuer -> aud:audience -> ?skew:Time.Skew.t -> unit -> t
end

module Claims : sig
  (* Phantom-typed claims. Every accessor demands [verified], and only
     [Jwt.verify] produces a [verified t]. *)
  type unverified
  type verified
  type 'v t

  val subject : verified t -> string option
  val issuer : verified t -> string
  val audiences : verified t -> string list
  val expires : verified t -> Time.t
  val jti : verified t -> string option
  val claim : verified t -> string -> Json.t option
end

module Jwt : sig
  (* The pipeline: shape and caps, header policy (no jwk/jku/x5u/x5c/
     x5t/zip/cty, no crit), alg equals the key's alg, signature, then
     iss equality, aud membership, mandatory exp, nbf/iat sanity, and
     only then admission. *)
  val verify :
    key:'alg Key.t ->
    expect:Expect.t ->
    now:Time.t ->
    string ->
    (Claims.verified Claims.t, Error.t) result

  (* Signature-and-header check only. Returns no payload: claim access
     always goes through [verify]. *)
  val check_signature : key:'alg Key.t -> string -> (unit, Error.t) result

  (* The kid from the (unverified) header, as an opaque keyset lookup
     hint. Never interpreted, never trusted. *)
  val kid_hint : string -> string option
end
