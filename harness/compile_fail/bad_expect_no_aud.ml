(* Misuse: build an expectation without an audience witness. *)
let bad (iss : Jose.Expect.issuer) : Jose.Expect.t = Jose.Expect.make ~iss ()
