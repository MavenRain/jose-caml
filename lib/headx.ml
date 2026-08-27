(* Typed JOSE protected header. The policy is baked in, not configurable:

   - Members that carry or point at key material (jwk, jku, x5u, x5c,
     x5t, x5t#S256) are rejected. Keys come only from the caller's
     keyset, so an attacker cannot ship the verification key inside the
     token (the embedded-jwk CVE class).
   - crit is rejected: this library implements no extensions, and RFC
     7515 forbids ignoring a critical extension.
   - zip is rejected: no decompression, no compression bombs.
   - cty is rejected: nested JWTs are out of scope.
   - kid is an opaque string. Nothing ever interprets it; it is only
     compared for equality against caller keyset entries. *)

type t = { alg : Algx.t; kid : string option; typ : string option }

let ( let* ) = Result.bind

let rejected_members : string list =
  [ "jwk"; "jku"; "x5u"; "x5c"; "x5t"; "x5t#S256"; "zip"; "cty" ]

let opt_string_member (name : string) (j : Jsonx.t) :
    (string option, Errx.t) result =
  Option.fold (Jsonx.member name j)
    ~none:(Ok None)
    ~some:(fun v ->
      Option.fold (Jsonx.as_string v)
        ~none:(Error (Errx.Header_malformed (name ^ " is not a string")))
        ~some:(fun s -> Ok (Some s)))

let parse (j : Jsonx.t) : (t, Errx.t) result =
  match j with
  | Jsonx.Jnull | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jstring _
  | Jsonx.Jlist _ ->
    Error (Errx.Header_malformed "header is not a JSON object")
  | Jsonx.Jobj _ ->
    let* () =
      List.fold_left
        (fun acc m ->
          let* () = acc in
          Option.fold (Jsonx.member m j)
            ~none:(Ok ())
            ~some:(fun (_ : Jsonx.t) ->
              Error (Errx.Header_rejected_member m)))
        (Ok ()) rejected_members
    in
    let* () =
      Option.fold (Jsonx.member "crit" j)
        ~none:(Ok ())
        ~some:(fun (_ : Jsonx.t) -> Error Errx.Crit_unsupported)
    in
    let* alg_j =
      Option.to_result (Jsonx.member "alg" j)
        ~none:(Errx.Header_malformed "alg is missing")
    in
    let* alg_s =
      Option.to_result (Jsonx.as_string alg_j)
        ~none:(Errx.Header_malformed "alg is not a string")
    in
    let* alg = Algx.of_string alg_s in
    let* typ = opt_string_member "typ" j in
    let* () =
      Option.fold typ
        ~none:(Ok ())
        ~some:(fun s ->
          if String.equal (String.uppercase_ascii s) "JWT" then Ok ()
          else Error (Errx.Typ_rejected s))
    in
    let* kid = opt_string_member "kid" j in
    Ok { alg; kid; typ }
