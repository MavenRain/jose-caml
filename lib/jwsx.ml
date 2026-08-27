(* JWS compact serialization: header.payload.signature. Order of checks:
   shape and caps first, then header policy, then the alg-vs-key gate,
   then signature shape, then crypto, then payload decode. Nothing
   attacker-controlled reaches crypto before the header passes policy
   and the algorithm equals the key's algorithm. *)

let ( let* ) = Result.bind

let max_token_bytes : int = 16384
let max_header_bytes : int = 4096

(* Split on '.', requiring exactly three parts. *)
let split3 (s : string) : (string * string * string, Errx.t) result =
  let finish (parts_rev : char list list) :
      (string * string * string, Errx.t) result =
    let str (cs_rev : char list) : string =
      String.of_seq (List.to_seq (List.rev cs_rev))
    in
    match parts_rev with
    | [ p3; p2; p1 ] -> Ok (str p1, str p2, str p3)
    | [ _ ] | [ _; _ ] -> Error (Errx.Token_shape "fewer than three parts")
    | [] | _ :: _ :: _ :: _ :: _ ->
      Error (Errx.Token_shape "more than three parts")
  in
  let step ((parts_rev, cur_rev) : char list list * char list) (c : char) :
      char list list * char list =
    match c with
    | '.' -> (cur_rev :: parts_rev, [])
    | other -> (parts_rev, other :: cur_rev)
  in
  let parts_rev, cur_rev =
    Seq.fold_left step ([], []) (String.to_seq s)
  in
  finish (cur_rev :: parts_rev)

type checked = { header : Headx.t; payload : string }

let verify (type a) ~(key : a Keyx.t) (token : string) :
    (checked, Errx.t) result =
  let* () =
    if String.length token > max_token_bytes then
      Error (Errx.Token_shape "token longer than 16 KiB")
    else Ok ()
  in
  let* h64, p64, s64 = split3 token in
  let* () =
    match () with
    | () when String.equal h64 "" -> Error (Errx.Token_shape "empty header")
    | () when String.equal s64 "" ->
      Error (Errx.Token_shape "empty signature")
    | () -> Ok ()
  in
  let* hbytes = B64x.decode h64 in
  let* () =
    if String.length hbytes > max_header_bytes then
      Error (Errx.Token_shape "header longer than 4 KiB")
    else Ok ()
  in
  let* hjson =
    Result.map_error (fun e -> Errx.Json_invalid e) (Jsonx.parse hbytes)
  in
  let* header = Headx.parse hjson in
  let* () =
    if Algx.equal header.Headx.alg (Keyx.alg key) then Ok ()
    else
      Error
        (Errx.Alg_mismatch
           { token = Algx.to_string header.Headx.alg;
             key = Algx.to_string (Keyx.alg key) })
  in
  let* sigbytes = B64x.decode s64 in
  let* () =
    if Int.equal (String.length sigbytes) (Keyx.signature_length key) then
      Ok ()
    else Error Errx.Sig_invalid
  in
  let signing_input = h64 ^ "." ^ p64 in
  let* () =
    if Keyx.verify_bytes key ~input:signing_input ~signature:sigbytes then
      Ok ()
    else Error Errx.Sig_invalid
  in
  let* payload = B64x.decode p64 in
  Ok { header; payload }

let check_signature (type a) ~(key : a Keyx.t) (token : string) :
    (unit, Errx.t) result =
  Result.map (fun (_ : checked) -> ()) (verify ~key token)

(* A lookup hint only: the kid from the (unverified) header, for picking
   a key out of the caller's keyset. It is opaque; nothing interprets
   it. Any malformation just means "no hint". *)
let kid_hint (token : string) : string option =
  Option.bind (Result.to_option (split3 token)) (fun (h64, _, _) ->
      Option.bind (Result.to_option (B64x.decode h64)) (fun hbytes ->
          Option.bind (Result.to_option (Jsonx.parse hbytes)) (fun hjson ->
              Option.bind (Jsonx.member "kid" hjson) Jsonx.as_string)))
