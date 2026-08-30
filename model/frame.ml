(* Adversary/verifier frame over the shared Verify_core machine. The
   adversary forges one token from a finite menu (algorithm choice,
   tampered-or-not, and whether iss/aud/exp would satisfy the relying
   party); the verifier then steps the copied Verify_core pipeline, one
   check per transition. Strict is the shipped design. Lax is the
   negative control: it parses and accepts alg=none and skips the
   signature check for it (the classic alg-confusion verifier), which
   must make the attack states reachable. *)

type alg_choice = A_match | A_none | A_wrong

type tok = {
  alg : alg_choice;
  tampered : bool; (* content changed after honest signing: sig invalid *)
  iss_ok : bool;
  aud_ok : bool;
  fresh : bool; (* exp present and in the future *)
}

type mode = Strict | Lax

type state = No_token | Running of tok * Verify_core.phase

let init : state = No_token

let bools : bool list = [ false; true ]

let toks : tok list =
  List.concat_map
    (fun alg ->
      List.concat_map
        (fun tampered ->
          List.concat_map
            (fun iss_ok ->
              List.concat_map
                (fun aud_ok ->
                  List.map
                    (fun fresh -> { alg; tampered; iss_ok; aud_ok; fresh })
                    bools)
                bools)
            bools)
        bools)
    [ A_match; A_none; A_wrong ]

(* What each pipeline check would report for this token. Shape, payload
   and claims decode, nbf and iat are held good: the properties under
   test concern the identity checks, not the codecs (the library test
   suites own those). *)
let results (m : mode) (t : tok) (c : Verify_core.check) : bool =
  match c with
  | Verify_core.Shape -> true
  | Verify_core.Header ->
    (match (m, t.alg) with
     | Strict, (A_match | A_wrong) -> true
     | Strict, A_none -> false (* Algx.of_string rejects "none" *)
     | Lax, (A_match | A_wrong | A_none) -> true)
  | Verify_core.Alg ->
    (match (m, t.alg) with
     | Strict, A_match -> true
     | Strict, (A_none | A_wrong) -> false
     | Lax, (A_match | A_none) -> true (* the alg-confusion hole *)
     | Lax, A_wrong -> false)
  | Verify_core.Sig ->
    (match (m, t.alg) with
     | Lax, A_none -> true (* "none": nothing checked, forgery passes *)
     | Lax, (A_match | A_wrong) -> not t.tampered
     | Strict, (A_match | A_none | A_wrong) -> not t.tampered)
  | Verify_core.Payload -> true
  | Verify_core.Claims -> true
  | Verify_core.Iss -> t.iss_ok
  | Verify_core.Aud -> t.aud_ok
  | Verify_core.Exp -> t.fresh
  | Verify_core.Nbf -> true
  | Verify_core.Iat -> true

(* Decided states self-loop so the successor map stays serial. *)
let post (m : mode) (s : state) : state list =
  match s with
  | No_token -> List.map (fun t -> Running (t, Verify_core.start)) toks
  | Running (t, ph) ->
    (match ph with
     | Verify_core.Admitted -> [ s ]
     | Verify_core.Rejected (_ : Verify_core.check) -> [ s ]
     | Verify_core.Checking c ->
       [ Running (t, Verify_core.step ph (results m t c)) ])

(* Atoms. *)

let on_phase (f : Verify_core.phase -> bool) (s : state) : bool =
  match s with
  | No_token -> false
  | Running ((_ : tok), ph) -> f ph

let on_tok (f : tok -> bool) (s : state) : bool =
  match s with
  | No_token -> false
  | Running (t, (_ : Verify_core.phase)) -> f t

let admitted : state -> bool =
  on_phase (fun ph ->
      match ph with
      | Verify_core.Admitted -> true
      | Verify_core.Checking (_ : Verify_core.check) -> false
      | Verify_core.Rejected (_ : Verify_core.check) -> false)

let rejected : state -> bool =
  on_phase (fun ph ->
      match ph with
      | Verify_core.Rejected (_ : Verify_core.check) -> true
      | Verify_core.Checking (_ : Verify_core.check) -> false
      | Verify_core.Admitted -> false)

let at_check (c : Verify_core.check) : state -> bool =
  on_phase (fun ph ->
      match ph with
      | Verify_core.Checking c' -> Int.equal (Stdlib.compare c c') 0
      | Verify_core.Admitted -> false
      | Verify_core.Rejected (_ : Verify_core.check) -> false)

let alg_is (a : alg_choice) : state -> bool =
  on_tok (fun t ->
      match (t.alg, a) with
      | A_match, A_match -> true
      | A_none, A_none -> true
      | A_wrong, A_wrong -> true
      | A_match, (A_none | A_wrong) -> false
      | A_none, (A_match | A_wrong) -> false
      | A_wrong, (A_match | A_none) -> false)

let tampered : state -> bool = on_tok (fun t -> t.tampered)
let iss_ok : state -> bool = on_tok (fun t -> t.iss_ok)
let aud_ok : state -> bool = on_tok (fun t -> t.aud_ok)
let fresh : state -> bool = on_tok (fun t -> t.fresh)

(* The honest signature actually verifies: right algorithm, untouched
   content. *)
let sig_genuine : state -> bool =
  on_tok (fun t ->
      match t.alg with
      | A_match -> not t.tampered
      | A_none -> false
      | A_wrong -> false)

(* The verifier observes only where its own pipeline stands, never the
   adversary's private choices. The render is injective on phases. *)
let view_verifier (s : state) : string =
  match s with
  | No_token -> "start"
  | Running ((_ : tok), ph) ->
    (match ph with
     | Verify_core.Checking c -> "checking:" ^ Verify_core.name c
     | Verify_core.Admitted -> "admitted"
     | Verify_core.Rejected c -> "rejected:" ^ Verify_core.name c)
