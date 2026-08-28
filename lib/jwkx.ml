(* RFC 7517 JWK and JWK Set parsing, into the same phantom-typed keys
   Keyx constructs. The algorithm comes from kty (and crv), never from
   the caller or the token; when the JWK carries an "alg" member it
   must agree with the kty-derived algorithm. Material validation is
   Keyx's: the length floors, parity, and on-curve checks run on every
   key that comes out of here.

   Check order inside [of_json] is fixed and the tests pin it:
   private-key members, then "use", then "key_ops", then kty (and crv),
   then "alg" agreement, then base64url material, then the Keyx
   constructor. *)

let ( let* ) = Result.bind

type any =
  | Hs256 of Keyx.hs256 Keyx.t
  | Rs256 of Keyx.rs256 Keyx.t
  | Es256 of Keyx.es256 Keyx.t

let alg (j : any) : Algx.t =
  match j with
  | Hs256 k -> Keyx.alg k
  | Rs256 k -> Keyx.alg k
  | Es256 k -> Keyx.alg k

(* This library verifies; it must never be handed signing material. A
   JWK that carries any asymmetric private member is rejected outright,
   and in a set that rejection is fatal for the whole set: a published
   private key is a broken key source, not an entry to skip past. *)
let private_members : string list = [ "d"; "p"; "q"; "dp"; "dq"; "qi"; "oth" ]

let private_member (obj : Jsonx.t) : string option =
  List.find_opt
    (fun (m : string) -> Option.is_some (Jsonx.member m obj))
    private_members

let no_private_members (obj : Jsonx.t) : (unit, Errx.t) result =
  Option.fold ~none:(Ok ())
    ~some:(fun (m : string) ->
      Error (Errx.Jwk_invalid ("private key member " ^ m)))
    (private_member obj)

let string_member (name : string) (obj : Jsonx.t) : string option =
  Option.bind (Jsonx.member name obj) Jsonx.as_string

(* "use", when present, must be exactly "sig" (RFC 7517 4.2): an
   encryption key must never verify a signature. *)
let use_ok (obj : Jsonx.t) : (unit, Errx.t) result =
  Option.fold ~none:(Ok ())
    ~some:(fun (u : Jsonx.t) ->
      Option.fold
        ~none:(Error (Errx.Jwk_invalid "use is not a string"))
        ~some:(fun (s : string) ->
          if String.equal s "sig" then Ok ()
          else Error (Errx.Jwk_invalid ("use is not sig: " ^ s)))
        (Jsonx.as_string u))
    (Jsonx.member "use" obj)

(* "key_ops", when present, must be a list of strings that includes
   "verify" (RFC 7517 4.3). *)
let key_ops_ok (obj : Jsonx.t) : (unit, Errx.t) result =
  Option.fold ~none:(Ok ())
    ~some:(fun (ops : Jsonx.t) ->
      match ops with
      | Jsonx.Jlist items ->
        let strs = List.filter_map Jsonx.as_string items in
        (match () with
         | () when not (Int.equal (List.length strs) (List.length items)) ->
           Error (Errx.Jwk_invalid "key_ops has a non-string member")
         | () when List.exists (String.equal "verify") strs -> Ok ()
         | () -> Error (Errx.Jwk_invalid "key_ops lacks verify"))
      | Jsonx.Jnull | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jstring _
      | Jsonx.Jobj _ ->
        Error (Errx.Jwk_invalid "key_ops is not a list"))
    (Jsonx.member "key_ops" obj)

(* "alg", when present, must equal the algorithm the kty (and crv)
   already determined; a JWK does not get to rename its own key type. *)
let alg_agrees (expected : Algx.t) (obj : Jsonx.t) : (unit, Errx.t) result =
  Option.fold ~none:(Ok ())
    ~some:(fun (a : Jsonx.t) ->
      Option.fold
        ~none:(Error (Errx.Jwk_invalid "alg is not a string"))
        ~some:(fun (s : string) ->
          if String.equal s (Algx.to_string expected) then Ok ()
          else
            Error
              (Errx.Jwk_invalid
                 ("alg " ^ s ^ " does not match kty for "
                 ^ Algx.to_string expected)))
        (Jsonx.as_string a))
    (Jsonx.member "alg" obj)

(* A required base64url string member, strictly decoded. *)
let b64_member (name : string) (obj : Jsonx.t) : (string, Errx.t) result =
  Option.fold
    ~none:(Error (Errx.Jwk_invalid (name ^ " is missing or not a string")))
    ~some:B64x.decode
    (string_member name obj)

let of_json (j : Jsonx.t) : (any, Errx.t) result =
  match j with
  | Jsonx.Jobj _ ->
    let* () = no_private_members j in
    let* () = use_ok j in
    let* () = key_ops_ok j in
    let* kty =
      Option.fold
        ~none:(Error (Errx.Jwk_invalid "kty is missing or not a string"))
        ~some:Result.ok (string_member "kty" j)
    in
    (match kty with
     | "oct" ->
       let* () = alg_agrees Algx.HS256 j in
       let* k = b64_member "k" j in
       Result.map (fun key -> Hs256 key) (Keyx.hs256 ~secret:k)
     | "RSA" ->
       let* () = alg_agrees Algx.RS256 j in
       let* n = b64_member "n" j in
       let* e = b64_member "e" j in
       Result.map (fun key -> Rs256 key) (Keyx.rs256 ~n ~e)
     | "EC" ->
       let* crv =
         Option.fold
           ~none:(Error (Errx.Jwk_invalid "crv is missing or not a string"))
           ~some:Result.ok (string_member "crv" j)
       in
       let* () =
         if String.equal crv "P-256" then Ok ()
         else Error (Errx.Jwk_invalid ("crv unsupported: " ^ crv))
       in
       let* () = alg_agrees Algx.ES256 j in
       let* x = b64_member "x" j in
       let* y = b64_member "y" j in
       Result.map (fun key -> Es256 key) (Keyx.es256 ~x ~y)
     | other -> Error (Errx.Jwk_invalid ("kty unsupported: " ^ other)))
  | Jsonx.Jnull | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jstring _
  | Jsonx.Jlist _ ->
    Error (Errx.Jwk_invalid "JWK is not a JSON object")

let parse (s : string) : (any, Errx.t) result =
  let* j = Result.map_error (fun (m : string) -> Errx.Json_invalid m)
      (Jsonx.parse s)
  in
  of_json j

(* A JWK Set, for opaque-kid lookup. Structural problems are fatal:
   bad JSON, a missing or non-list "keys", a non-object entry, a
   non-string kid, private key material anywhere, or two retained
   entries sharing a kid (an ambiguous equality lookup is a key
   confusion primitive). An entry that is a well-formed object but not
   a verification key this library supports (use=enc, a foreign kty or
   crv or alg, material Keyx rejects) is dropped, not fatal -- RFC
   7517 5 -- so one foreign key in a rotation set cannot brick
   verification; [dropped] counts them for monitoring. *)
type set = { entries : (string option * any) list; dropped_count : int }

let kid_of (entry : Jsonx.t) : (string option, Errx.t) result =
  Option.fold ~none:(Ok None)
    ~some:(fun (k : Jsonx.t) ->
      Option.fold
        ~none:(Error (Errx.Jwk_invalid "kid is not a string"))
        ~some:(fun (s : string) -> Ok (Some s))
        (Jsonx.as_string k))
    (Jsonx.member "kid" entry)

let no_duplicate_kids (entries : (string option * any) list) :
    (unit, Errx.t) result =
  let kids = List.filter_map (fun (kid, (_ : any)) -> kid) entries in
  if
    Int.equal (List.length kids)
      (List.length (List.sort_uniq String.compare kids))
  then Ok ()
  else Error (Errx.Jwk_invalid "duplicate kid in JWK Set")

let set_parse (s : string) : (set, Errx.t) result =
  let* j = Result.map_error (fun (m : string) -> Errx.Json_invalid m)
      (Jsonx.parse s)
  in
  let* () =
    match j with
    | Jsonx.Jobj _ -> Ok ()
    | Jsonx.Jnull | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jstring _
    | Jsonx.Jlist _ ->
      Error (Errx.Jwk_invalid "JWK Set is not a JSON object")
  in
  let* items =
    Option.fold ~none:(Error (Errx.Jwk_invalid "keys is missing"))
      ~some:(fun (k : Jsonx.t) ->
        match k with
        | Jsonx.Jlist l -> Ok l
        | Jsonx.Jnull | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jstring _
        | Jsonx.Jobj _ ->
          Error (Errx.Jwk_invalid "keys is not a list"))
      (Jsonx.member "keys" j)
  in
  let* kept_rev, dropped_count =
    List.fold_left
      (fun (acc : ((string option * any) list * int, Errx.t) result)
           (entry : Jsonx.t) ->
        let* kept, dropped = acc in
        let* () =
          match entry with
          | Jsonx.Jobj _ -> Ok ()
          | Jsonx.Jnull | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jstring _
          | Jsonx.Jlist _ ->
            Error (Errx.Jwk_invalid "JWK Set entry is not an object")
        in
        let* () = no_private_members entry in
        let* kid = kid_of entry in
        Ok
          (Result.fold
             ~ok:(fun (key : any) -> ((kid, key) :: kept, dropped))
             ~error:(fun (_ : Errx.t) -> (kept, dropped + 1))
             (of_json entry)))
      (Ok ([], 0)) items
  in
  let entries = List.rev kept_rev in
  let* () = no_duplicate_kids entries in
  Ok { entries; dropped_count }

let find ~(kid : string) (s : set) : any option =
  Option.map snd
    (List.find_opt
       (fun ((k : string option), (_ : any)) ->
         Option.fold ~none:false ~some:(String.equal kid) k)
       s.entries)

let keys (s : set) : any list = List.map snd s.entries
let dropped (s : set) : int = s.dropped_count
