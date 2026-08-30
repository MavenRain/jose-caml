(* The full pipeline: JWS verification, then the mandatory claim
   witnesses (iss, aud, exp) plus nbf/iat sanity, then admission. This
   is the only caller of Clx.admit, so [Claims.verified] values exist
   only past every check. The Verify_core phase started in jwsx is
   walked one [step ph true] per passed check, and admission happens
   only from [Admitted]: a check skipped anywhere fails closed. *)

let ( let* ) = Result.bind

let verify (type a) ~(key : a Keyx.t) ~(expect : Expx.t) ~(now : Timex.t)
    (token : string) : (Clx.verified Clx.t, Errx.t) result =
  let* jws = Jwsx.verify ~key token in
  let* pjson =
    Result.map_error
      (fun e -> Errx.Json_invalid e)
      (Jsonx.parse jws.Jwsx.payload)
  in
  let* uc = Clx.of_json pjson in
  let ph = Verify_core.advance Verify_core.Claims jws.Jwsx.ph in
  let p = Clx.payload_of uc in
  let nowi = Timex.seconds now in
  let skew = Expx.skew expect in
  let* iss = Option.to_result p.Clx.iss ~none:(Errx.Missing_claim "iss") in
  let* () =
    if String.equal iss (Expx.iss expect) then Ok ()
    else Error Errx.Iss_mismatch
  in
  let ph = Verify_core.advance Verify_core.Iss ph in
  let* () =
    match p.Clx.aud with
    | [] -> Error (Errx.Missing_claim "aud")
    | _ :: _ -> Ok ()
  in
  let* () =
    if List.exists (String.equal (Expx.aud expect)) p.Clx.aud then Ok ()
    else Error Errx.Aud_mismatch
  in
  let ph = Verify_core.advance Verify_core.Aud ph in
  let* exp = Option.to_result p.Clx.exp ~none:(Errx.Missing_claim "exp") in
  let* () =
    if nowi < exp + skew then Ok ()
    else Error (Errx.Expired { exp; now = nowi })
  in
  let ph = Verify_core.advance Verify_core.Exp ph in
  let* () =
    Option.fold p.Clx.nbf
      ~none:(Ok ())
      ~some:(fun nbf ->
        if nbf <= nowi + skew then Ok ()
        else Error (Errx.Not_yet_valid { nbf; now = nowi }))
  in
  let ph = Verify_core.advance Verify_core.Nbf ph in
  let* () =
    Option.fold p.Clx.iat
      ~none:(Ok ())
      ~some:(fun iat ->
        if iat <= nowi + skew then Ok ()
        else Error (Errx.Iat_in_future { iat; now = nowi }))
  in
  let ph = Verify_core.advance Verify_core.Iat ph in
  match ph with
  | Verify_core.Admitted -> Ok (Clx.admit uc ~iss ~exp)
  | Verify_core.Checking c ->
    Error (Errx.Token_shape ("pipeline incomplete at " ^ Verify_core.name c))
  | Verify_core.Rejected c ->
    Error (Errx.Token_shape ("pipeline rejected at " ^ Verify_core.name c))
