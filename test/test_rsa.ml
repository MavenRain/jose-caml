(* M10 RS256: RFC 7515 appendix A.2 through the public API, plus Rsax
   unit negatives and the Key.rs256 rejection sweep. The constants
   below are recomputed by harness/diff_rfc.py, which redoes the whole
   RSA verify with python pow() and requires every 64-char fragment to
   sit here verbatim, so a mistyped vector cannot pass the gates. *)

module R = Jose__Rsax

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

let a2_h64 : string = "eyJhbGciOiJSUzI1NiJ9"

let a2_p64 : string =
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
  ^ "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

let a2_n64 : string =
  "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp"
  ^ "-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOW"
  ^ "vG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUs"
  ^ "LA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9k"
  ^ "G4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2"
  ^ "PAcDTW9gb54h4FRWyuXpoQ"

let a2_e64 : string = "AQAB"

let a2_s64 : string =
  "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
  ^ "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
  ^ "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
  ^ "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
  ^ "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
  ^ "p0igcN_IoypGlUPQGe77Rw"

let a2_input : string = a2_h64 ^ "." ^ a2_p64
let a2_token : string = a2_input ^ "." ^ a2_s64

let err_name (r : ('a, Jose.Error.t) result) : string =
  Result.fold ~ok:(fun (_ : 'a) -> "ok") ~error:Jose.Error.to_string r

let dec (s : string) : string =
  Result.fold ~ok:Fun.id
    ~error:(fun (_ : Jose.Error.t) -> "")
    (Jose.B64url.decode s)

let n_bytes : string = dec a2_n64
let e_bytes : string = dec a2_e64

let with_key (checks : Jose.Key.rs256 Jose.Key.t -> (string * bool) list) :
    (string * bool) list =
  Result.fold
    ~error:(fun (_ : Jose.Error.t) ->
      [ ("fixture: rs256 key builds", false) ])
    ~ok:checks
    (Jose.Key.rs256 ~n:n_bytes ~e:e_bytes)

(* Expect for the A.2 payload's issuer; the payload carries no aud, so
   the full pipeline must refuse it as a missing mandatory claim. *)
let expect_and_now : (Jose.Expect.t * Jose.Time.t) option =
  Option.bind
    (Result.to_option
       (Result.bind (Jose.Expect.issuer "joe") (fun iss ->
            Result.map
              (fun aud -> Jose.Expect.make ~iss ~aud ())
              (Jose.Expect.audience "https://rp.example"))))
    (fun expect ->
      Option.map
        (fun now -> (expect, now))
        (Result.to_option (Jose.Time.of_epoch_seconds 1300819000)))

let api_checks : (string * bool) list =
  with_key (fun key ->
      [ ("a2 signature verifies",
         String.equal (err_name (Jose.Jwt.check_signature ~key a2_token)) "ok");
        ("a2 key alg is RS256",
         (match Jose.Key.alg key with
          | Jose.Alg.RS256 -> true
          | Jose.Alg.HS256 | Jose.Alg.ES256 -> false));
        ("a2 payload swap rejected",
         String.equal
           (err_name
              (Jose.Jwt.check_signature ~key
                 (a2_h64 ^ "." ^ Jose.B64url.encode "{}" ^ "." ^ a2_s64)))
           "signature invalid");
        ("a2 wrong-length signature rejected",
         String.equal
           (err_name
              (Jose.Jwt.check_signature ~key
                 (a2_input ^ "."
                 ^ Jose.B64url.encode (String.make 255 '\x00'))))
           "signature invalid");
        ("a2 signature equal to modulus rejected",
         String.equal
           (err_name
              (Jose.Jwt.check_signature ~key
                 (a2_input ^ "." ^ Jose.B64url.encode n_bytes)))
           "signature invalid");
        ("a2 full verify demands aud",
         Option.fold ~none:false
           ~some:(fun ((expect : Jose.Expect.t), (now : Jose.Time.t)) ->
             String.equal
               (err_name (Jose.Jwt.verify ~key ~expect ~now a2_token))
               "missing claim: aud")
           expect_and_now)
      ])

let mismatch_checks : (string * bool) list =
  Result.fold
    ~error:(fun (_ : Jose.Error.t) ->
      [ ("fixture: hs256 key builds", false) ])
    ~ok:(fun (key : Jose.Key.hs256 Jose.Key.t) ->
      [ ("hs256 key rejects the RS256 token before crypto",
         String.equal
           (err_name (Jose.Jwt.check_signature ~key a2_token))
           "alg mismatch: token says RS256, key is HS256")
      ])
    (Jose.Key.hs256 ~secret:"test-secret-test-secret-test-sec")

let rsax_checks : (string * bool) list =
  [ ("rsax verifies the a2 vector",
     R.verify ~n:n_bytes ~e:e_bytes ~input:a2_input ~signature:(dec a2_s64));
    ("rsax rejects a flipped input",
     not
       (R.verify ~n:n_bytes ~e:e_bytes ~input:(a2_input ^ "x")
          ~signature:(dec a2_s64)));
    ("rsax rejects a wrong exponent",
     not
       (R.verify ~n:n_bytes ~e:"\x03" ~input:a2_input
          ~signature:(dec a2_s64)));
    ("rsax rejects an empty signature",
     not (R.verify ~n:n_bytes ~e:e_bytes ~input:a2_input ~signature:""));
    ("rsax rejects s = n",
     not (R.verify ~n:n_bytes ~e:e_bytes ~input:a2_input ~signature:n_bytes));
    ("encode_em floors the padding at eight bytes",
     Option.is_none (R.encode_em ~k:61 (String.make 32 'h')));
    ("encode_em emits k bytes",
     Option.fold ~none:false
       ~some:(fun em -> Int.equal (String.length em) 62)
       (R.encode_em ~k:62 (String.make 32 'h')))
  ]

let reject (label : string) ~(n : string) ~(e : string) (want : string) :
    string * bool =
  ( label,
    String.equal
      (err_name (Jose.Key.rs256 ~n ~e))
      ("key rejected: " ^ want) )

let key_checks : (string * bool) list =
  [ reject "n shorter than 2048 bits"
      ~n:(String.make 255 '\xff')
      ~e:"\x03" "RS256 modulus shorter than 2048 bits";
    reject "n longer than 8192 bits"
      ~n:(String.make 1025 '\xff')
      ~e:"\x03" "RS256 modulus longer than 8192 bits";
    reject "n leading zero"
      ~n:("\x00" ^ String.make 255 '\xff')
      ~e:"\x03" "RS256 modulus has a leading zero byte";
    reject "n even"
      ~n:(String.make 255 '\xff' ^ "\x02")
      ~e:"\x03" "RS256 modulus is even";
    reject "e empty" ~n:n_bytes ~e:"" "RS256 exponent is empty";
    reject "e leading zero" ~n:n_bytes ~e:"\x00\x03"
      "RS256 exponent has a leading zero byte";
    reject "e wider than 8 bytes" ~n:n_bytes
      ~e:(String.make 9 '\x03')
      "RS256 exponent longer than 8 bytes";
    reject "e even" ~n:n_bytes ~e:"\x04" "RS256 exponent is even";
    reject "e one" ~n:n_bytes ~e:"\x01" "RS256 exponent is one"
  ]

(* Pinned suite size: a collapsed fixture (any short-circuit above)
   shrinks the list and fails this check as lost coverage. *)
let expected_total : int = 23

let () =
  let all = api_checks @ mismatch_checks @ rsax_checks @ key_checks in
  run
    (("suite total pinned", Int.equal (List.length all) expected_total)
    :: all)
