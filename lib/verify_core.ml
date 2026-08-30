(* The verification pipeline as a total state machine: the one
   transition semantics shared by the library (jwsx/jwtx thread a phase
   through their checks and admit only from [Admitted]) and the model
   checker (model/ copies this file and explores [step] over adversary
   token menus). Admitted and Rejected are absorbing: a decided token
   never changes verdict, and admission requires every check to pass in
   the fixed order below. *)

type check =
  | Shape
  | Header
  | Alg
  | Sig
  | Payload
  | Claims
  | Iss
  | Aud
  | Exp
  | Nbf
  | Iat

type phase = Checking of check | Admitted | Rejected of check

let start : phase = Checking Shape

(* The pipeline order: split -> header policy -> alg gate -> signature
   -> payload decode -> claims parse -> iss -> aud -> exp -> nbf -> iat.
   The alg gate precedes the signature check, so no attacker-chosen
   algorithm ever reaches crypto. *)
let next (c : check) : check option =
  match c with
  | Shape -> Some Header
  | Header -> Some Alg
  | Alg -> Some Sig
  | Sig -> Some Payload
  | Payload -> Some Claims
  | Claims -> Some Iss
  | Iss -> Some Aud
  | Aud -> Some Exp
  | Exp -> Some Nbf
  | Nbf -> Some Iat
  | Iat -> None

let name (c : check) : string =
  match c with
  | Shape -> "shape"
  | Header -> "header"
  | Alg -> "alg"
  | Sig -> "sig"
  | Payload -> "payload"
  | Claims -> "claims"
  | Iss -> "iss"
  | Aud -> "aud"
  | Exp -> "exp"
  | Nbf -> "nbf"
  | Iat -> "iat"

let step (ph : phase) (ok : bool) : phase =
  match ph with
  | Admitted -> Admitted
  | Rejected c -> Rejected c
  | Checking c ->
    if ok then
      Option.fold (next c) ~none:Admitted ~some:(fun n -> Checking n)
    else Rejected c

(* Run the machine to a verdict against an oracle of per-check results.
   The library never calls this (its checks are data-dependent); the
   correspondence gate and the model do. *)
let rec drive (results : check -> bool) (ph : phase) : phase =
  match ph with
  | Admitted -> Admitted
  | Rejected c -> Rejected c
  | Checking c -> drive results (step ph (results c))

let run (results : check -> bool) : phase = drive results start

(* Library-facing step: advance the walk for check [c] only when the
   walk is exactly at [c]; any mis-ordered, duplicated, or extra call
   poisons the walk to [Rejected c], so the admission gate fails
   closed. jwsx/jwtx use this exclusively. *)
let advance (c : check) (ph : phase) : phase =
  match ph with
  | Admitted -> Rejected c
  | Rejected c' -> Rejected c'
  | Checking c' ->
    if Int.equal (Stdlib.compare c c') 0 then step ph true else Rejected c
