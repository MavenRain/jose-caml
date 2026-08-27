(* The closed algorithm enum. "none" is not a member and never will be:
   an unsigned token has no algorithm to name a key for, so it cannot be
   verified. Parsing anything outside the enum is a typed reject. *)

type t = HS256 | RS256 | ES256

let to_string (a : t) : string =
  match a with
  | HS256 -> "HS256"
  | RS256 -> "RS256"
  | ES256 -> "ES256"

let of_string (s : string) : (t, Errx.t) result =
  match () with
  | () when String.equal s "HS256" -> Ok HS256
  | () when String.equal s "RS256" -> Ok RS256
  | () when String.equal s "ES256" -> Ok ES256
  | () -> Error (Errx.Alg_unsupported s)

let equal (a : t) (b : t) : bool =
  match (a, b) with
  | HS256, HS256 | RS256, RS256 | ES256, ES256 -> true
  | HS256, (RS256 | ES256) | RS256, (HS256 | ES256) | ES256, (HS256 | RS256)
    -> false
