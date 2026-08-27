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
module Expect = Expx
module Claims = Clx

module Jwt = struct
  let verify = Jwtx.verify
  let check_signature = Jwsx.check_signature
  let kid_hint = Jwsx.kid_hint
end
