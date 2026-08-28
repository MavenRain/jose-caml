(* The public face. jose.mli is the only signature that matters to a
   consumer: it hides Clx.admit, key material, and everything else that
   would let a caller mint a verified value without the pipeline. *)

module Error = Errx
module B64url = B64x
module Json = Jsonx
module Alg = Algx
module Hmac = Hmacx
module Time = Timex
module Key = Keyx

module Jwk = struct
  type t = Jwkx.any =
    | Hs256 of Keyx.hs256 Keyx.t
    | Rs256 of Keyx.rs256 Keyx.t
    | Es256 of Keyx.es256 Keyx.t

  let parse = Jwkx.parse
  let of_json = Jwkx.of_json
  let alg = Jwkx.alg
end

module Jwks = struct
  type t = Jwkx.set

  let parse = Jwkx.set_parse
  let find = Jwkx.find
  let keys = Jwkx.keys
  let dropped = Jwkx.dropped
end

module Expect = Expx
module Claims = Clx

module Jwt = struct
  let verify = Jwtx.verify
  let check_signature = Jwsx.check_signature
  let kid_hint = Jwsx.kid_hint
end
