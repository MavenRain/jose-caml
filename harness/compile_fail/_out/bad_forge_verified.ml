(* Misuse: coerce unverified claims to verified without the pipeline. *)
let bad (c : Jose.Claims.unverified Jose.Claims.t) :
    Jose.Claims.verified Jose.Claims.t =
  c
