(* M11 ES256: RFC 7515 appendix A.3 through the public API, plus P256x
   unit negatives, psychic-signature rejects (CVE-2022-21449 shape),
   and the Key.es256 rejection sweep. harness/diff_rfc.py redoes the
   whole ECDSA verify with python integers and requires the constants
   below (including the off-curve and boundary constants) to sit here
   verbatim, so a mistyped vector cannot pass the gates. *)

module P = Jose__P256x

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

let a3_h64 : string = "eyJhbGciOiJFUzI1NiJ9"

let a3_p64 : string =
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
  ^ "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

let a3_x64 : string = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
let a3_y64 : string = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"

let a3_s64 : string =
  "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
  ^ "pmWQxfKTUJqPP3-Kg6NU1Q"

(* a3_y with its last bit flipped: 32 in-field bytes that are NOT a
   point on the curve (diff_rfc.py checks that). *)
let off_y64 : string = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5aw"

(* The P-256 field prime and group order, 32 big-endian bytes each. *)
let p_mod64 : string = "_____wAAAAEAAAAAAAAAAAAAAAD_______________8"
let n_ord64 : string = "_____wAAAAD__________7zm-q2nF56E87nKwvxjJVE"

let a3_input : string = a3_h64 ^ "." ^ a3_p64
let a3_token : string = a3_input ^ "." ^ a3_s64

let err_name (r : ('a, Jose.Error.t) result) : string =
  Result.fold ~ok:(fun (_ : 'a) -> "ok") ~error:Jose.Error.to_string r

let dec (s : string) : string =
  Result.fold ~ok:Fun.id
    ~error:(fun (_ : Jose.Error.t) -> "")
    (Jose.B64url.decode s)

let x_bytes : string = dec a3_x64
let y_bytes : string = dec a3_y64
let sig_bytes : string = dec a3_s64
let off_y_bytes : string = dec off_y64
let p_bytes : string = dec p_mod64
let n_bytes : string = dec n_ord64
let zero32 : string = String.make 32 '\x00'

let r_bytes : string = fst (P.take_drop 32 sig_bytes)
let s_bytes : string = snd (P.take_drop 32 sig_bytes)

(* A token that reuses the A.3 header and payload but carries the given
   raw signature bytes. *)
let token_with_sig (raw : string) : string =
  a3_input ^ "." ^ Jose.B64url.encode raw

let with_key (checks : Jose.Key.es256 Jose.Key.t -> (string * bool) list) :
    (string * bool) list =
  Result.fold
    ~error:(fun (_ : Jose.Error.t) ->
      [ ("fixture: es256 key builds", false) ])
    ~ok:checks
    (Jose.Key.es256 ~x:x_bytes ~y:y_bytes)

(* Expect for the A.3 payload's issuer; the payload carries no aud, so
   a full verify must stop at the missing claim. *)
let expect_and_now : (Jose.Expect.t * Jose.Time.t) option =
  Option.bind (Result.to_option (Jose.Expect.issuer "joe")) (fun iss ->
      Option.bind
        (Option.map
           (fun aud -> Jose.Expect.make ~iss ~aud ())
           (Result.to_option (Jose.Expect.audience "https://rp.example")))
        (fun expect ->
          Option.map
            (fun now -> (expect, now))
            (Result.to_option (Jose.Time.of_epoch_seconds 1300819000))))

let api_checks : (string * bool) list =
  with_key (fun key ->
      [ ("a3 signature verifies",
         String.equal (err_name (Jose.Jwt.check_signature ~key a3_token)) "ok");
        ("a3 key alg is ES256",
         (match Jose.Key.alg key with
          | Jose.Alg.ES256 -> true
          | Jose.Alg.HS256 | Jose.Alg.RS256 -> false));
        ("a3 payload swap rejected",
         String.equal
           (err_name
              (Jose.Jwt.check_signature ~key
                 (a3_h64 ^ "." ^ Jose.B64url.encode "{}" ^ "." ^ a3_s64)))
           "signature invalid");
        ("a3 wrong-length signature rejected",
         String.equal
           (err_name
              (Jose.Jwt.check_signature ~key
                 (token_with_sig (String.make 63 '\x00'))))
           "signature invalid");
        ("a3 psychic r = 0 rejected",
         String.equal
           (err_name
              (Jose.Jwt.check_signature ~key
                 (token_with_sig (zero32 ^ s_bytes))))
           "signature invalid");
        ("a3 psychic s = 0 rejected",
         String.equal
           (err_name
              (Jose.Jwt.check_signature ~key
                 (token_with_sig (r_bytes ^ zero32))))
           "signature invalid");
        ("a3 r equal to the group order rejected",
         String.equal
           (err_name
              (Jose.Jwt.check_signature ~key
                 (token_with_sig (n_bytes ^ s_bytes))))
           "signature invalid");
        ("a3 s equal to the group order rejected",
         String.equal
           (err_name
              (Jose.Jwt.check_signature ~key
                 (token_with_sig (r_bytes ^ n_bytes))))
           "signature invalid");
        ("a3 full verify demands aud",
         Option.fold ~none:false
           ~some:(fun ((expect : Jose.Expect.t), (now : Jose.Time.t)) ->
             String.equal
               (err_name (Jose.Jwt.verify ~key ~expect ~now a3_token))
               "missing claim: aud")
           expect_and_now)
      ])

let mismatch_checks : (string * bool) list =
  Result.fold
    ~error:(fun (_ : Jose.Error.t) ->
      [ ("fixture: hs256 key builds", false) ])
    ~ok:(fun (key : Jose.Key.hs256 Jose.Key.t) ->
      [ ("hs256 key rejects the ES256 token before crypto",
         String.equal
           (err_name (Jose.Jwt.check_signature ~key a3_token))
           "alg mismatch: token says ES256, key is HS256")
      ])
    (Jose.Key.hs256 ~secret:"test-secret-test-secret-test-sec")

let p256x_checks : (string * bool) list =
  [ ("p256x verifies the a3 vector",
     P.verify ~x:x_bytes ~y:y_bytes ~input:a3_input ~signature:sig_bytes);
    ("p256x rejects a flipped input",
     not
       (P.verify ~x:x_bytes ~y:y_bytes ~input:(a3_input ^ "x")
          ~signature:sig_bytes));
    ("p256x rejects an empty signature",
     not (P.verify ~x:x_bytes ~y:y_bytes ~input:a3_input ~signature:""));
    ("p256x rejects a 65-byte signature",
     not
       (P.verify ~x:x_bytes ~y:y_bytes ~input:a3_input
          ~signature:(sig_bytes ^ "\x00")));
    ("p256x holds the a3 point on the curve",
     P.on_curve_bytes ~x:x_bytes ~y:y_bytes);
    ("p256x holds the flipped-y point off the curve",
     not (P.on_curve_bytes ~x:x_bytes ~y:off_y_bytes));
    ("p256x holds the field prime out of the field",
     not (P.coord_in_field p_bytes));
    ("p256x holds the a3 x coordinate in the field",
     P.coord_in_field x_bytes)
  ]

let reject (label : string) ~(x : string) ~(y : string) (want : string) :
    string * bool =
  ( label,
    String.equal
      (err_name (Jose.Key.es256 ~x ~y))
      ("key rejected: " ^ want) )

let key_checks : (string * bool) list =
  [ reject "x 31 bytes"
      ~x:(String.make 31 '\x01')
      ~y:y_bytes "ES256 x is not 32 bytes";
    reject "x 33 bytes"
      ~x:(String.make 33 '\x01')
      ~y:y_bytes "ES256 x is not 32 bytes";
    reject "y 31 bytes" ~x:x_bytes
      ~y:(String.make 31 '\x01')
      "ES256 y is not 32 bytes";
    reject "x at the field prime" ~x:p_bytes ~y:y_bytes
      "ES256 x is not below the field prime";
    reject "y at the field prime" ~x:x_bytes ~y:p_bytes
      "ES256 y is not below the field prime";
    reject "off-curve point" ~x:x_bytes ~y:off_y_bytes
      "ES256 point is not on the curve";
    reject "zero point" ~x:zero32 ~y:zero32
      "ES256 point is not on the curve"
  ]

(* Pinned suite size: a collapsed fixture (any short-circuit above)
   shrinks the list and fails this check as lost coverage. *)
let expected_total : int = 25

let () =
  let all = api_checks @ mismatch_checks @ p256x_checks @ key_checks in
  run
    (("suite total pinned", Int.equal (List.length all) expected_total)
    :: all)
