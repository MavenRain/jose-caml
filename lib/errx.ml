(* The one error type. Every rejection names the check that failed, so a
   caller (and the CVE corpus harness) can pin the exact reason. *)

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
  | Jwk_invalid of string
  | Missing_claim of string
  | Claim_malformed of string
  | Iss_mismatch
  | Aud_mismatch
  | Expired of { exp : int; now : int }
  | Not_yet_valid of { nbf : int; now : int }
  | Iat_in_future of { iat : int; now : int }
  | Time_invalid of string
  | Expect_invalid of string

let to_string (e : t) : string =
  match e with
  | B64_invalid s -> "base64url: " ^ s
  | Json_invalid s -> "json: " ^ s
  | Token_shape s -> "token shape: " ^ s
  | Alg_unsupported s -> "unsupported alg: " ^ s
  | Alg_mismatch { token; key } ->
    "alg mismatch: token says " ^ token ^ ", key is " ^ key
  | Header_rejected_member m -> "rejected header member: " ^ m
  | Crit_unsupported -> "crit is not supported"
  | Typ_rejected s -> "rejected typ: " ^ s
  | Header_malformed s -> "malformed header: " ^ s
  | Sig_invalid -> "signature invalid"
  | Key_rejected s -> "key rejected: " ^ s
  | Jwk_invalid s -> "jwk: " ^ s
  | Missing_claim c -> "missing claim: " ^ c
  | Claim_malformed c -> "malformed claim: " ^ c
  | Iss_mismatch -> "issuer mismatch"
  | Aud_mismatch -> "audience mismatch"
  | Expired { exp; now } ->
    "expired: exp " ^ string_of_int exp ^ " at now " ^ string_of_int now
  | Not_yet_valid { nbf; now } ->
    "not yet valid: nbf " ^ string_of_int nbf ^ " at now " ^ string_of_int now
  | Iat_in_future { iat; now } ->
    "iat in the future: iat " ^ string_of_int iat ^ " at now "
    ^ string_of_int now
  | Time_invalid s -> "time: " ^ s
  | Expect_invalid s -> "expectation: " ^ s
