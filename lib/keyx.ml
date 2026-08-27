(* Keys fix the algorithm at construction time, in a phantom type index.
   There is no key for "none". A key carries its own verifier, so key
   material never leaves this module. *)

type hs256
type rs256
type es256

type material =
  | Hs of string
  | Rs of { n : string; e : string }
  | Es of { x : string; y : string }

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

(* The last byte of s, or None when empty; the parity guards below
   read it. A fold, not an index: direct string indexing is partial,
   and the inputs here are at most 1024 bytes read once per key
   construction, so the linear walk costs nothing that matters. *)
let last_byte (s : string) : int option =
  String.fold_left (fun (_ : int option) c -> Some (Char.code c)) None s

let is_even (s : string) : bool =
  Option.fold ~none:false
    ~some:(fun b -> Int.equal (b land 1) 0)
    (last_byte s)

(* An RS256 public key: modulus and exponent as minimal big-endian
   bytes (a JWK's "n" and "e" after base64url decoding). RFC 7518 3.3
   sets the 2048-bit floor; the 8192-bit modulus cap and the 8-byte
   exponent cap bound the modexp work a hostile key set can demand.
   Minimal encodings keep the modulus byte length equal to the RSA
   length k, which the signature-length gate and the EM comparison in
   Rsax both depend on. Parity: a real modulus is a product of odd
   primes and a real verification exponent is odd, so even values are
   garbage input, never a key. *)
let rs256 ~(n : string) ~(e : string) : (rs256 t, Errx.t) result =
  match () with
  | () when String.length n < 256 ->
    Error (Errx.Key_rejected "RS256 modulus shorter than 2048 bits")
  | () when String.length n > 1024 ->
    Error (Errx.Key_rejected "RS256 modulus longer than 8192 bits")
  | () when String.starts_with ~prefix:"\x00" n ->
    Error (Errx.Key_rejected "RS256 modulus has a leading zero byte")
  | () when is_even n -> Error (Errx.Key_rejected "RS256 modulus is even")
  | () when String.equal e "" ->
    Error (Errx.Key_rejected "RS256 exponent is empty")
  | () when String.starts_with ~prefix:"\x00" e ->
    Error (Errx.Key_rejected "RS256 exponent has a leading zero byte")
  | () when String.length e > 8 ->
    Error (Errx.Key_rejected "RS256 exponent longer than 8 bytes")
  | () when is_even e -> Error (Errx.Key_rejected "RS256 exponent is even")
  | () when String.equal e "\x01" ->
    Error (Errx.Key_rejected "RS256 exponent is one")
  | () -> Ok { alg = Algx.RS256; material = Rs { n; e } }

(* An ES256 public key: the affine point as two 32-byte big-endian
   coordinates (a JWK's "x" and "y" after base64url decoding, RFC 7518
   6.2.1). The point must lie on P-256 itself: accepting an off-curve
   point is the invalid-curve attack, so membership is checked here,
   once, at construction. Coordinates at or above the field prime are
   non-canonical encodings of some other residue and are rejected
   rather than reduced. *)
let es256 ~(x : string) ~(y : string) : (es256 t, Errx.t) result =
  match () with
  | () when not (Int.equal (String.length x) 32) ->
    Error (Errx.Key_rejected "ES256 x is not 32 bytes")
  | () when not (Int.equal (String.length y) 32) ->
    Error (Errx.Key_rejected "ES256 y is not 32 bytes")
  | () when not (P256x.coord_in_field x) ->
    Error (Errx.Key_rejected "ES256 x is not below the field prime")
  | () when not (P256x.coord_in_field y) ->
    Error (Errx.Key_rejected "ES256 y is not below the field prime")
  | () when not (P256x.on_curve_bytes ~x ~y) ->
    Error (Errx.Key_rejected "ES256 point is not on the curve")
  | () -> Ok { alg = Algx.ES256; material = Es { x; y } }

let alg (k : 'alg t) : Algx.t = k.alg

(* The exact signature length this key accepts, so a wrong-shape
   signature is rejected before any crypto. *)
let signature_length (k : 'alg t) : int =
  match k.material with
  | Hs _ -> 32
  | Rs { n; _ } -> String.length n
  | Es _ -> 64

let verify_bytes (k : 'alg t) ~(input : string) ~(signature : string) : bool =
  match k.material with
  | Hs secret -> Hmacx.equal_ct (Hmacx.sha256 ~key:secret input) signature
  | Rs { n; e } -> Rsax.verify ~n ~e ~input ~signature
  | Es { x; y } -> P256x.verify ~x ~y ~input ~signature
