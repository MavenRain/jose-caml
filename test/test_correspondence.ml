(* Correspondence gate: on a shared vector set, the library verdict of
   Jose.Jwt.verify must agree with the Verify_core machine driven by
   each vector's per-check oracle. The machine rows pin the
   Verify_core order and verdict on the model library copy (model/dune
   copy_files); the library rows pin the exact error per vector. The
   phase walk inside the library is not observable here -- it is
   enforced by the check-named Verify_core.advance calls and the
   admission gate, which fail closed on any mis-ordered walk. *)

module V = Jose_model.Verify_core

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

let secret : string = "test-secret-test-secret-test-sec"

let mk_token ?(secret = secret) (header : string) (payload : string) : string
    =
  let si = Jose.B64url.encode header ^ "." ^ Jose.B64url.encode payload in
  si ^ "." ^ Jose.B64url.encode (Jose.Hmac.sha256 ~key:secret si)

let now_s : int = 1000000
let hs : string = "{\"alg\":\"HS256\"}"

let claims ?(iss = "\"iss\":\"iss1\",") ?(aud = "\"aud\":\"aud1\",")
    ?(exp = "\"exp\":1000100") ?(extra = "") () : string =
  "{" ^ iss ^ aud ^ extra ^ exp ^ "}"

type verdict = Admit | Reject of V.check * (Jose.Error.t -> bool)

type vec = { vname : string; token : string; want : verdict }

let exact (e : Jose.Error.t) : Jose.Error.t -> bool =
  fun got -> got = e

let b64_invalid (got : Jose.Error.t) : bool =
  match got with
  | Jose.Error.B64_invalid (_ : string) -> true
  | Jose.Error.Json_invalid (_ : string) -> false
  | Jose.Error.Token_shape (_ : string) -> false
  | Jose.Error.Alg_unsupported (_ : string) -> false
  | Jose.Error.Alg_mismatch { token = (_ : string); key = (_ : string) } -> false
  | Jose.Error.Header_rejected_member (_ : string) -> false
  | Jose.Error.Crit_unsupported -> false
  | Jose.Error.Typ_rejected (_ : string) -> false
  | Jose.Error.Header_malformed (_ : string) -> false
  | Jose.Error.Sig_invalid -> false
  | Jose.Error.Key_rejected (_ : string) -> false
  | Jose.Error.Jwk_invalid (_ : string) -> false
  | Jose.Error.Missing_claim (_ : string) -> false
  | Jose.Error.Claim_malformed (_ : string) -> false
  | Jose.Error.Iss_mismatch -> false
  | Jose.Error.Aud_mismatch -> false
  | Jose.Error.Expired { exp = (_ : int); now = (_ : int) } -> false
  | Jose.Error.Not_yet_valid { nbf = (_ : int); now = (_ : int) } -> false
  | Jose.Error.Iat_in_future { iat = (_ : int); now = (_ : int) } -> false
  | Jose.Error.Time_invalid (_ : string) -> false
  | Jose.Error.Expect_invalid (_ : string) -> false

let vectors : vec list =
  let bad_payload_b64 =
    let si = Jose.B64url.encode hs ^ ".!!!" in
    si ^ "." ^ Jose.B64url.encode (Jose.Hmac.sha256 ~key:secret si)
  in
  [ { vname = "valid"; token = mk_token hs (claims ()); want = Admit };
    { vname = "shape-two-parts";
      token = "a.b";
      want =
        Reject
          (V.Shape, exact (Jose.Error.Token_shape "fewer than three parts"))
    };
    { vname = "shape-oversize";
      token = String.make 17000 'a';
      want =
        Reject
          (V.Shape, exact (Jose.Error.Token_shape "token longer than 16 KiB"))
    };
    { vname = "header-bad-b64";
      token = "!!!.AAAA.AAAA";
      want = Reject (V.Header, b64_invalid) };
    { vname = "alg-none";
      token = mk_token "{\"alg\":\"none\"}" (claims ());
      want = Reject (V.Header, exact (Jose.Error.Alg_unsupported "none")) };
    { vname = "alg-wrong";
      token = mk_token "{\"alg\":\"RS256\"}" (claims ());
      want =
        Reject
          ( V.Alg,
            exact
              (Jose.Error.Alg_mismatch { token = "RS256"; key = "HS256" }) )
    };
    { vname = "sig-wrong-key";
      token = mk_token ~secret:(String.make 32 'z') hs (claims ());
      want = Reject (V.Sig, exact Jose.Error.Sig_invalid) };
    { vname = "payload-bad-b64";
      token = bad_payload_b64;
      want = Reject (V.Payload, b64_invalid) };
    { vname = "claims-not-object";
      token = mk_token hs "[1]";
      want =
        Reject
          ( V.Claims,
            exact (Jose.Error.Claim_malformed "payload is not a JSON object")
          ) };
    { vname = "iss-missing";
      token = mk_token hs (claims ~iss:"" ());
      want = Reject (V.Iss, exact (Jose.Error.Missing_claim "iss")) };
    { vname = "iss-wrong";
      token = mk_token hs (claims ~iss:"\"iss\":\"evil\"," ());
      want = Reject (V.Iss, exact Jose.Error.Iss_mismatch) };
    { vname = "aud-missing";
      token = mk_token hs (claims ~aud:"" ());
      want = Reject (V.Aud, exact (Jose.Error.Missing_claim "aud")) };
    { vname = "aud-wrong";
      token = mk_token hs (claims ~aud:"\"aud\":\"other\"," ());
      want = Reject (V.Aud, exact Jose.Error.Aud_mismatch) };
    { vname = "exp-missing";
      token = mk_token hs (claims ~exp:"\"sub\":\"s\"" ());
      want = Reject (V.Exp, exact (Jose.Error.Missing_claim "exp")) };
    { vname = "expired";
      token = mk_token hs (claims ~exp:"\"exp\":999900" ());
      want =
        Reject
          (V.Exp, exact (Jose.Error.Expired { exp = 999900; now = now_s }))
    };
    { vname = "nbf-future";
      token = mk_token hs (claims ~extra:"\"nbf\":1000100," ());
      want =
        Reject
          ( V.Nbf,
            exact (Jose.Error.Not_yet_valid { nbf = 1000100; now = now_s })
          ) };
    { vname = "iat-future";
      token = mk_token hs (claims ~extra:"\"iat\":1000100," ());
      want =
        Reject
          ( V.Iat,
            exact (Jose.Error.Iat_in_future { iat = 1000100; now = now_s })
          ) }
  ]

let phase_admitted (ph : V.phase) : bool =
  match ph with
  | V.Admitted -> true
  | V.Checking (_ : V.check) -> false
  | V.Rejected (_ : V.check) -> false

let vec_checks (key : Jose.Key.hs256 Jose.Key.t) (expect : Jose.Expect.t)
    (now : Jose.Time.t) (v : vec) : (string * bool) list =
  let lib =
    Result.map
      (fun (_ : Jose.Claims.verified Jose.Claims.t) -> ())
      (Jose.Jwt.verify ~key ~expect ~now v.token)
  in
  let oracle (c : V.check) : bool =
    match v.want with
    | Admit -> true
    | Reject (f, (_ : Jose.Error.t -> bool)) ->
      not (Int.equal (Stdlib.compare c f) 0)
  in
  let mach = V.run oracle in
  let lib_ok =
    match v.want with
    | Admit -> lib = Ok ()
    | Reject ((_ : V.check), p) ->
      Result.fold ~ok:(fun () -> false) ~error:p lib
  in
  let mach_ok =
    match v.want with
    | Admit -> phase_admitted mach
    | Reject (f, (_ : Jose.Error.t -> bool)) -> mach = V.Rejected f
  in
  [ (v.vname ^ ": library verdict", lib_ok);
    (v.vname ^ ": machine verdict", mach_ok);
    (v.vname ^ ": agreement", Bool.equal (Result.is_ok lib) (phase_admitted mach))
  ]

let () =
  run
    (Result.fold
       ~error:(fun (e : Jose.Error.t) ->
         [ ("fixture builds: " ^ Jose.Error.to_string e, false) ])
       ~ok:(fun checks -> checks)
       (Result.bind (Jose.Key.hs256 ~secret) (fun key ->
            Result.bind (Jose.Expect.issuer "iss1") (fun iss ->
                Result.bind (Jose.Expect.audience "aud1") (fun aud ->
                    Result.bind (Jose.Time.of_epoch_seconds now_s)
                      (fun now ->
                        let expect = Jose.Expect.make ~iss ~aud () in
                        Ok
                          (List.concat_map
                             (vec_checks key expect now)
                             vectors)))))))
