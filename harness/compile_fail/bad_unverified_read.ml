(* Misuse: read an identity claim from unverified claims. *)
let bad (c : Jose.Claims.unverified Jose.Claims.t) : string option =
  Jose.Claims.subject c
