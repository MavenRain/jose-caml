(* What the relying party expects. There is no way to build an [t]
   without an issuer and an audience: they are the mandatory witnesses
   the verification pipeline consumes. *)

type issuer = string
type audience = string

let printable (s : string) : bool =
  (not (String.equal s ""))
  && String.for_all (fun c -> Char.code c >= 32 && Char.code c <> 127) s

let issuer (s : string) : (issuer, Errx.t) result =
  if printable s then Ok s
  else Error (Errx.Expect_invalid "issuer must be non-empty printable")

let audience (s : string) : (audience, Errx.t) result =
  if printable s then Ok s
  else Error (Errx.Expect_invalid "audience must be non-empty printable")

type t = { iss : string; aud : string; skew : int }

let make ~(iss : issuer) ~(aud : audience) ?(skew = Timex.Skew.zero) () : t =
  { iss; aud; skew = Timex.Skew.seconds skew }

let iss (e : t) : string = e.iss
let aud (e : t) : string = e.aud
let skew (e : t) : int = e.skew
