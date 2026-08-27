(* Misuse: pass raw bytes where a constructed key is required. *)
let bad (expect : Jose.Expect.t) (now : Jose.Time.t) =
  Jose.Jwt.verify ~key:"secret" ~expect ~now "token"
