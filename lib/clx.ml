(* Claims, phantom-typed by verification status. The GADT makes the
   verified accessors total: at type [verified t] the [U] constructor is
   refuted by the type checker, so no accessor can ever see an
   unverified payload. [admit] is reachable inside the library only; the
   public signature (jose.mli) does not export it. *)

type unverified
type verified

type payload = {
  iss : string option;
  sub : string option;
  aud : string list;
  exp : int option;
  nbf : int option;
  iat : int option;
  jti : string option;
  all : Jsonx.t;
}

(* The witnessed facts recorded at admission: the matched issuer and the
   expiry that was checked against the caller's clock. *)
type admitted = { p : payload; a_iss : string; a_exp : int }

type _ t = U : payload -> unverified t | V : admitted -> verified t

let ( let* ) = Result.bind

let str_opt (name : string) (j : Jsonx.t) : (string option, Errx.t) result =
  Option.fold (Jsonx.member name j)
    ~none:(Ok None)
    ~some:(fun v ->
      Option.fold (Jsonx.as_string v)
        ~none:(Error (Errx.Claim_malformed name))
        ~some:(fun s -> Ok (Some s)))

(* NumericDate: a non-negative integer number of seconds. *)
let date_opt (name : string) (j : Jsonx.t) : (int option, Errx.t) result =
  Option.fold (Jsonx.member name j)
    ~none:(Ok None)
    ~some:(fun v ->
      Option.fold (Jsonx.as_int v)
        ~none:(Error (Errx.Claim_malformed name))
        ~some:(fun n ->
          if n < 0 then Error (Errx.Claim_malformed name) else Ok (Some n)))

(* aud is a string or a non-empty list of strings (RFC 7519 4.1.3). *)
let aud_list (j : Jsonx.t) : (string list, Errx.t) result =
  Option.fold (Jsonx.member "aud" j)
    ~none:(Ok [])
    ~some:(fun v ->
      match v with
      | Jsonx.Jstring s -> Ok [ s ]
      | Jsonx.Jlist items ->
        let strings = List.filter_map Jsonx.as_string items in
        (match () with
         | () when List.is_empty items -> Error (Errx.Claim_malformed "aud")
         | () when not (Int.equal (List.length strings) (List.length items))
           ->
           Error (Errx.Claim_malformed "aud")
         | () -> Ok strings)
      | Jsonx.Jnull | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jobj _ ->
        Error (Errx.Claim_malformed "aud"))

let of_json (j : Jsonx.t) : (unverified t, Errx.t) result =
  match j with
  | Jsonx.Jnull | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jstring _
  | Jsonx.Jlist _ ->
    Error (Errx.Claim_malformed "payload is not a JSON object")
  | Jsonx.Jobj _ ->
    let* iss = str_opt "iss" j in
    let* sub = str_opt "sub" j in
    let* aud = aud_list j in
    let* exp = date_opt "exp" j in
    let* nbf = date_opt "nbf" j in
    let* iat = date_opt "iat" j in
    let* jti = str_opt "jti" j in
    Ok (U { iss; sub; aud; exp; nbf; iat; jti; all = j })

let payload_of (c : unverified t) : payload = match c with U p -> p

(* Library-internal: the single point that mints [verified]. jose.mli
   does not export it. *)
let admit (c : unverified t) ~(iss : string) ~(exp : int) : verified t =
  match c with U p -> V { p; a_iss = iss; a_exp = exp }

let subject (c : verified t) : string option = match c with V a -> a.p.sub
let issuer (c : verified t) : string = match c with V a -> a.a_iss
let audiences (c : verified t) : string list = match c with V a -> a.p.aud
let expires (c : verified t) : Timex.t = match c with V a -> a.a_exp
let jti (c : verified t) : string option = match c with V a -> a.p.jti

let claim (c : verified t) (name : string) : Jsonx.t option =
  match c with V a -> Jsonx.member name a.p.all
