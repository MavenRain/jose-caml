(* Keys fix the algorithm at construction time, in a phantom type index.
   There is no key for "none". A key carries its own verifier, so key
   material never leaves this module. *)

type hs256
type rs256
type es256

type material = Hs of string

type 'alg t = { alg : Algx.t; material : material }

let is_prefix (prefix : char list) (s : char list) : bool =
  let rec go (p : char list) (rest : char list) : bool =
    match p with
    | [] -> true
    | pc :: ps ->
      (match rest with
       | rc :: rs -> Char.equal pc rc && go ps rs
       | [] -> false)
  in
  go prefix s

let contains_sub (needle : string) (hay : string) : bool =
  let n = List.of_seq (String.to_seq needle) in
  let rec scan (rest : char list) : bool =
    match rest with
    | [] -> is_prefix n []
    | _ :: tail as here -> is_prefix n here || scan tail
  in
  scan (List.of_seq (String.to_seq hay))

(* An HMAC secret that is really asymmetric key material is the RS256 ->
   HS256 confusion attack in the making: the attacker signs with the
   public key bytes as the MAC secret. Reject anything PEM-shaped, DER-
   shaped (leading SEQUENCE tag 0x30), or base64-DER-shaped ("MII"). *)
let looks_like_asymmetric_material (s : string) : bool =
  (* DER SPKI / RSAPublicKey blobs always exceed 127 bytes, so the outer
     SEQUENCE always uses a long-form length: 0x30 0x81 or 0x30 0x82. A
     bare 0x30 is also ASCII '0', which a real passphrase may start
     with, so the tag alone is not evidence. *)
  let cs = List.of_seq (String.to_seq s) in
  contains_sub "-----BEGIN" s
  || is_prefix [ '\x30'; '\x81' ] cs
  || is_prefix [ '\x30'; '\x82' ] cs
  || is_prefix [ 'M'; 'I'; 'I' ] cs

let hs256 ~(secret : string) : (hs256 t, Errx.t) result =
  match () with
  | () when String.length secret < 32 ->
    Error (Errx.Key_rejected "HS256 secret shorter than 32 bytes")
  | () when looks_like_asymmetric_material secret ->
    Error (Errx.Key_rejected "HS256 secret looks like asymmetric key material")
  | () -> Ok { alg = Algx.HS256; material = Hs secret }

let alg (k : 'alg t) : Algx.t = k.alg

(* The exact signature length this key accepts, so a wrong-shape
   signature is rejected before any crypto. *)
let signature_length (k : 'alg t) : int =
  match k.material with Hs _ -> 32

let verify_bytes (k : 'alg t) ~(input : string) ~(signature : string) : bool =
  match k.material with
  | Hs secret -> Hmacx.equal_ct (Hmacx.sha256 ~key:secret input) signature
