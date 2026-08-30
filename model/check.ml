(* CTLK property suite over the ctlk_topos kernel: DESIGN.md P1-P6 on
   the Strict frame, plus non-vacuity controls. Positive controls N1-N5
   phrase the attack or the honest run as an Ef formula that must hold,
   so a model in which nothing is ever admitted (or the Lax hole is
   gone) fails loudly instead of passing vacuously. Exit 0 only when
   every verdict matches. *)

open Jose_model

type agent = Verifier

type prop =
  | Admitted
  | Rejected
  | At_alg
  | At_sig
  | Alg_none
  | Alg_wrong
  | Alg_matched
  | Tampered
  | Sig_genuine
  | Iss_ok
  | Aud_ok
  | Fresh

type kind = Must_be_valid | Must_be_satisfiable

type checkrow = {
  name : string;
  desc : string;
  kind : kind;
  mode : Frame.mode;
  form : (prop, agent) Ctlk.form;
}

let den (p : prop) : Frame.state -> bool =
  match p with
  | Admitted -> Frame.admitted
  | Rejected -> Frame.rejected
  | At_alg -> Frame.at_check Verify_core.Alg
  | At_sig -> Frame.at_check Verify_core.Sig
  | Alg_none -> Frame.alg_is Frame.A_none
  | Alg_wrong -> Frame.alg_is Frame.A_wrong
  | Alg_matched -> Frame.alg_is Frame.A_match
  | Tampered -> Frame.tampered
  | Sig_genuine -> Frame.sig_genuine
  | Iss_ok -> Frame.iss_ok
  | Aud_ok -> Frame.aud_ok
  | Fresh -> Frame.fresh

let view (v : agent) (s : Frame.state) : string =
  match v with Verifier -> Frame.view_verifier s

let sys (m : Frame.mode) : (Frame.state, agent) Ctlk.system =
  Ctlk.system_of Stdlib.compare (Frame.post m) Frame.init [ Verifier ] view

let a (p : prop) : (prop, agent) Ctlk.form = Ctlk.Atom p

let conj (fs : (prop, agent) Ctlk.form list) : (prop, agent) Ctlk.form =
  List.fold_left (fun acc f -> Ctlk.And (acc, f)) Ctlk.Tt fs

let checks : checkrow list =
  [ { name = "P1-admit-implies-all";
      desc = "admitted -> genuine sig, matched alg, aud, iss, fresh";
      kind = Must_be_valid;
      mode = Frame.Strict;
      form =
        Ctlk.Ag
          (Ctlk.Imp
             ( a Admitted,
               conj
                 [ a Sig_genuine; a Alg_matched; a Aud_ok; a Iss_ok; a Fresh ]
             )) };
    { name = "P2-alg-none-never-admitted";
      desc = "alg=none token is admitted on no path";
      kind = Must_be_valid;
      mode = Frame.Strict;
      form = Ctlk.Ag (Ctlk.Imp (a Alg_none, Ctlk.Ag (Ctlk.Not (a Admitted)))) };
    { name = "P3-mismatch-rejects-next";
      desc = "at the alg gate, a mismatched alg rejects in one step";
      kind = Must_be_valid;
      mode = Frame.Strict;
      form =
        Ctlk.Ag
          (Ctlk.Imp (Ctlk.And (a At_alg, a Alg_wrong), Ctlk.Ax (a Rejected)))
    };
    { name = "P3-mismatch-precedes-crypto";
      desc = "a wrong or none alg never reaches the signature check";
      kind = Must_be_valid;
      mode = Frame.Strict;
      form =
        Ctlk.Ag
          (Ctlk.Imp
             ( Ctlk.Or (a Alg_wrong, a Alg_none),
               Ctlk.Ag (Ctlk.Not (a At_sig)) )) };
    { name = "P4-no-resurrection";
      desc = "a rejected token is never later admitted";
      kind = Must_be_valid;
      mode = Frame.Strict;
      form = Ctlk.Ag (Ctlk.Imp (a Rejected, Ctlk.Ag (Ctlk.Not (a Admitted))))
    };
    { name = "P5-admit-knows-aud-iss";
      desc = "at admission the verifier knows aud and iss matched";
      kind = Must_be_valid;
      mode = Frame.Strict;
      form =
        Ctlk.Ag
          (Ctlk.Imp
             ( a Admitted,
               Ctlk.Know (Verifier, Ctlk.And (a Aud_ok, a Iss_ok)) )) };
    { name = "P6-no-forgery-admission";
      desc = "a tampered (unforgeable-sig) token is admitted on no path";
      kind = Must_be_valid;
      mode = Frame.Strict;
      form = Ctlk.Ag (Ctlk.Imp (a Tampered, Ctlk.Ag (Ctlk.Not (a Admitted))))
    };
    { name = "N1-honest-token-admits";
      desc = "positive control: some strict path admits a token";
      kind = Must_be_satisfiable;
      mode = Frame.Strict;
      form = Ctlk.Ef (a Admitted) };
    { name = "N2-some-rejection";
      desc = "positive control: some strict path rejects a token";
      kind = Must_be_satisfiable;
      mode = Frame.Strict;
      form = Ctlk.Ef (a Rejected) };
    { name = "N3-lax-none-forgery-admits";
      desc = "lax control: alg=none forgery is admitted (CVE-2015-9235)";
      kind = Must_be_satisfiable;
      mode = Frame.Lax;
      form = Ctlk.Ef (conj [ a Admitted; a Tampered; a Alg_none ]) };
    { name = "N4-lax-breaks-P1";
      desc = "lax control: admission without a genuine signature";
      kind = Must_be_satisfiable;
      mode = Frame.Lax;
      form = Ctlk.Ef (Ctlk.And (a Admitted, Ctlk.Not (a Sig_genuine))) };
    { name = "N5-lax-epistemic-blindspot";
      desc = "lax control: at some admission the verifier cannot rule out tampering";
      kind = Must_be_satisfiable;
      mode = Frame.Lax;
      form =
        Ctlk.Ef
          (Ctlk.And
             ( a Admitted,
               Ctlk.Not (Ctlk.Know (Verifier, Ctlk.Not (a Tampered))) )) };
    { name = "N6-strict-at-alg-wrong";
      desc = "control: the P3 antecedent (at alg gate, wrong alg) is reachable";
      kind = Must_be_satisfiable;
      mode = Frame.Strict;
      form = Ctlk.Ef (Ctlk.And (a At_alg, a Alg_wrong)) };
    { name = "N7-strict-tampered-rejected";
      desc = "control: a tampered token reaches rejection in strict";
      kind = Must_be_satisfiable;
      mode = Frame.Strict;
      form = Ctlk.Ef (Ctlk.And (a Tampered, a Rejected)) }
  ]

let () =
  let failures =
    List.fold_left
      (fun acc c ->
        let got = Ctlk.holds_at (sys c.mode) den c.form Frame.init in
        let label =
          match c.kind with
          | Must_be_valid -> "valid"
          | Must_be_satisfiable -> "satisfiable"
        in
        let verdict = if got then "PASS" else "FAIL" in
        Printf.printf "%s %-28s must be %-11s  %s\n" verdict c.name label
          c.desc;
        acc + Bool.to_int (not got))
      0 checks
  in
  Printf.printf "%d checks, %d failures\n" (List.length checks) failures;
  exit (Int.min failures 1)
