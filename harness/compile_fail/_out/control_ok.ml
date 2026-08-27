(* Control: the intended use compiles. If this breaks, the bad_*.ml
   rejections prove nothing. *)
let ( let* ) = Result.bind

let demo ~(secret : string) ~(token : string) ~(now : Jose.Time.t) :
    (string option, Jose.Error.t) result =
  let* key = Jose.Key.hs256 ~secret in
  let* iss = Jose.Expect.issuer "https://issuer.example" in
  let* aud = Jose.Expect.audience "svc" in
  let expect = Jose.Expect.make ~iss ~aud () in
  let* claims = Jose.Jwt.verify ~key ~expect ~now token in
  Ok (Jose.Claims.subject claims)
