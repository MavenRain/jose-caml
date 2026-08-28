(* M12 JWK / JWK Set: RFC 7517 appendix A.1 as printed (joined base64url
   lines), plus an end-to-end set built from the RFC 7515 A.1/A.2/A.3
   keys, so a key parsed out of a JWKS verifies the matching RFC token.
   diff_rfc.py re-derives the key material facts (on-curve, modulus
   bounds, parity) in python and pins every fragment used here. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

let err_name (r : ('a, Jose.Error.t) result) : string =
  Result.fold ~ok:(fun (_ : 'a) -> "ok") ~error:Jose.Error.to_string r

(* RFC 7517 A.1: the EC key is use=enc (never a verification key); the
   RSA key is kid 2011-04-29 with alg RS256. *)
let a1_ec_x64 : string = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"
let a1_ec_y64 : string = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"

let a1_rsa_n64 : string =
  "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86z"
  ^ "wu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5Js"
  ^ "GY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMic"
  ^ "AtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-"
  ^ "bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csF"
  ^ "Cur-kEgU8awapJzKnqDKgw"

let rfc7517_a1 : string =
  "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" ^ a1_ec_x64
  ^ "\",\"y\":\"" ^ a1_ec_y64 ^ "\",\"use\":\"enc\",\"kid\":\"1\"},"
  ^ "{\"kty\":\"RSA\",\"n\":\"" ^ a1_rsa_n64
  ^ "\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}]}"

(* RFC 7515 A.1 (oct), A.2 (RSA), A.3 (EC): keys as JWK members and the
   matching compact tokens, as pinned in test_jwt / test_rsa /
   test_p256. *)
let a1_k64 : string =
  "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T"
  ^ "-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

let a1_token : string =
  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
  ^ ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
  ^ "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
  ^ ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

let a2_n64 : string =
  "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp"
  ^ "-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOW"
  ^ "vG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUs"
  ^ "LA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9k"
  ^ "G4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2"
  ^ "PAcDTW9gb54h4FRWyuXpoQ"

let a2_token : string =
  "eyJhbGciOiJSUzI1NiJ9"
  ^ ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
  ^ "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
  ^ ".cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
  ^ "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
  ^ "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
  ^ "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
  ^ "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
  ^ "p0igcN_IoypGlUPQGe77Rw"

let a3_x64 : string = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
let a3_y64 : string = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"

(* a3_y with its last bit flipped: in-field but not on the curve. *)
let off_y64 : string = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5aw"

let a3_token : string =
  "eyJhbGciOiJFUzI1NiJ9"
  ^ ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
  ^ "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
  ^ ".DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
  ^ "pmWQxfKTUJqPP3-Kg6NU1Q"

let oct_jwk (kid : string) : string =
  "{\"kty\":\"oct\",\"kid\":\"" ^ kid ^ "\",\"k\":\"" ^ a1_k64 ^ "\"}"

let rsa_jwk (kid : string) : string =
  "{\"kty\":\"RSA\",\"kid\":\"" ^ kid ^ "\",\"use\":\"sig\",\"n\":\""
  ^ a2_n64 ^ "\",\"e\":\"AQAB\"}"

let ec_jwk (kid : string) : string =
  "{\"kty\":\"EC\",\"kid\":\"" ^ kid
  ^ "\",\"crv\":\"P-256\",\"key_ops\":[\"verify\"],\"x\":\"" ^ a3_x64
  ^ "\",\"y\":\"" ^ a3_y64 ^ "\"}"

let e2e_set : string =
  "{\"keys\":[" ^ oct_jwk "hs-a1" ^ "," ^ rsa_jwk "rsa-a2" ^ ","
  ^ ec_jwk "ec-a3" ^ "]}"

let check_tok (j : Jose.Jwk.t) (token : string) : (unit, Jose.Error.t) result
    =
  match j with
  | Jose.Jwk.Hs256 k -> Jose.Jwt.check_signature ~key:k token
  | Jose.Jwk.Rs256 k -> Jose.Jwt.check_signature ~key:k token
  | Jose.Jwk.Es256 k -> Jose.Jwt.check_signature ~key:k token

let found_verifies (s : Jose.Jwks.t) (kid : string) (token : string) : bool =
  Option.fold ~none:false
    ~some:(fun (j : Jose.Jwk.t) -> Result.is_ok (check_tok j token))
    (Jose.Jwks.find ~kid s)

let found_alg (s : Jose.Jwks.t) (kid : string) : Jose.Alg.t option =
  Option.map Jose.Jwk.alg (Jose.Jwks.find ~kid s)

let with_set (label : string) (json : string)
    (checks : Jose.Jwks.t -> (string * bool) list) : (string * bool) list =
  Result.fold
    ~error:(fun (e : Jose.Error.t) ->
      [ ("fixture: " ^ label ^ " parses (" ^ Jose.Error.to_string e ^ ")",
         false) ])
    ~ok:checks
    (Jose.Jwks.parse json)

let jwk_err (json : string) : string = err_name (Jose.Jwk.parse json)

let rfc7517_checks : (string * bool) list =
  with_set "rfc7517 a1" rfc7517_a1 (fun s ->
      [ ("7517 a1: enc key dropped", Int.equal (Jose.Jwks.dropped s) 1);
        ("7517 a1: one key retained",
         Int.equal (List.length (Jose.Jwks.keys s)) 1);
        ("7517 a1: rsa kid found, RS256",
         Option.fold ~none:false ~some:(Jose.Alg.equal Jose.Alg.RS256)
           (found_alg s "2011-04-29"));
        ("7517 a1: enc kid not findable",
         Option.is_none (Jose.Jwks.find ~kid:"1" s));
        ("7517 a1: enc key rejected alone",
         String.equal (jwk_err
           ("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" ^ a1_ec_x64
            ^ "\",\"y\":\"" ^ a1_ec_y64 ^ "\",\"use\":\"enc\",\"kid\":\"1\"}"))
           "jwk: use is not sig: enc")
      ])

let e2e_checks : (string * bool) list =
  with_set "e2e" e2e_set (fun s ->
      [ ("e2e: nothing dropped", Int.equal (Jose.Jwks.dropped s) 0);
        ("e2e: three keys", Int.equal (List.length (Jose.Jwks.keys s)) 3);
        ("e2e: oct key verifies rfc7515 a1", found_verifies s "hs-a1" a1_token);
        ("e2e: rsa key verifies rfc7515 a2",
         found_verifies s "rsa-a2" a2_token);
        ("e2e: ec key verifies rfc7515 a3", found_verifies s "ec-a3" a3_token);
        ("e2e: rsa key vs es256 token is alg mismatch",
         Option.fold ~none:false
           ~some:(fun (j : Jose.Jwk.t) ->
             check_tok j a3_token
             = Error
                 (Jose.Error.Alg_mismatch { token = "ES256"; key = "RS256" }))
           (Jose.Jwks.find ~kid:"rsa-a2" s));
        ("e2e: unknown kid misses", Option.is_none (Jose.Jwks.find ~kid:"?" s))
      ])

(* One usable key plus one foreign (OKP) key: the foreign key drops, the
   usable one still works, so rotation survives an unsupported kty. *)
let mixed_checks : (string * bool) list =
  with_set "mixed"
    ("{\"keys\":[" ^ oct_jwk "good"
     ^ ",{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"ed\",\"x\":\"AA\"}]}")
    (fun s ->
      [ ("mixed: foreign kty dropped", Int.equal (Jose.Jwks.dropped s) 1);
        ("mixed: good key survives", found_verifies s "good" a1_token);
        ("mixed: dropped kid not findable",
         Option.is_none (Jose.Jwks.find ~kid:"ed" s))
      ])

(* A key with no kid is retained (listable) but never found by kid. *)
let kidless_checks : (string * bool) list =
  with_set "kidless"
    ("{\"keys\":[{\"kty\":\"oct\",\"k\":\"" ^ a1_k64 ^ "\"}]}")
    (fun s ->
      [ ("kidless: retained", Int.equal (List.length (Jose.Jwks.keys s)) 1);
        ("kidless: not findable", Option.is_none (Jose.Jwks.find ~kid:"" s))
      ])

let single_parse_checks : (string * bool) list =
  [ ("single: oct parses HS256",
     Result.fold ~error:(fun (_ : Jose.Error.t) -> false)
       ~ok:(fun (j : Jose.Jwk.t) ->
         Jose.Alg.equal (Jose.Jwk.alg j) Jose.Alg.HS256)
       (Jose.Jwk.parse (oct_jwk "x")));
    ("single: short oct secret rejected",
     String.equal
       (jwk_err "{\"kty\":\"oct\",\"k\":\"AAAA\"}")
       "key rejected: HS256 secret shorter than 32 bytes");
    ("single: private member d fatal",
     String.equal (jwk_err "{\"kty\":\"RSA\",\"d\":\"AA\"}")
       "jwk: private key member d");
    ("single: private beats use",
     String.equal (jwk_err "{\"kty\":\"RSA\",\"d\":\"AA\",\"use\":\"enc\"}")
       "jwk: private key member d");
    ("single: use beats kty",
     String.equal (jwk_err "{\"kty\":\"NOPE\",\"use\":\"enc\"}")
       "jwk: use is not sig: enc");
    ("single: non-string use",
     String.equal (jwk_err "{\"kty\":\"oct\",\"use\":3}")
       "jwk: use is not a string");
    ("single: key_ops without verify",
     String.equal
       (jwk_err "{\"kty\":\"oct\",\"key_ops\":[\"sign\"]}")
       "jwk: key_ops lacks verify");
    ("single: key_ops not a list",
     String.equal
       (jwk_err "{\"kty\":\"oct\",\"key_ops\":\"verify\"}")
       "jwk: key_ops is not a list");
    ("single: key_ops non-string member",
     String.equal
       (jwk_err "{\"kty\":\"oct\",\"key_ops\":[\"verify\",3]}")
       "jwk: key_ops has a non-string member");
    ("single: kty missing", String.equal (jwk_err "{}")
       "jwk: kty is missing or not a string");
    ("single: kty unsupported",
     String.equal (jwk_err "{\"kty\":\"OKP\"}") "jwk: kty unsupported: OKP");
    ("single: crv missing",
     String.equal (jwk_err "{\"kty\":\"EC\"}")
       "jwk: crv is missing or not a string");
    ("single: crv unsupported",
     String.equal
       (jwk_err
          ("{\"kty\":\"EC\",\"crv\":\"P-384\",\"x\":\"" ^ a3_x64
           ^ "\",\"y\":\"" ^ a3_y64 ^ "\"}"))
       "jwk: crv unsupported: P-384");
    ("single: alg contradicts kty",
     String.equal
       (jwk_err ("{\"kty\":\"oct\",\"alg\":\"RS256\",\"k\":\"" ^ a1_k64
                 ^ "\"}"))
       "jwk: alg RS256 does not match kty for HS256");
    ("single: alg not a string",
     String.equal
       (jwk_err ("{\"kty\":\"oct\",\"alg\":7,\"k\":\"" ^ a1_k64 ^ "\"}"))
       "jwk: alg is not a string");
    ("single: k missing",
     String.equal (jwk_err "{\"kty\":\"oct\"}")
       "jwk: k is missing or not a string");
    ("single: padded k is non-canonical",
     String.starts_with ~prefix:"base64url:"
       (jwk_err "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObw==\"}"));
    ("single: off-curve point rejected",
     String.equal
       (jwk_err
          ("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" ^ a3_x64
           ^ "\",\"y\":\"" ^ off_y64 ^ "\"}"))
       "key rejected: ES256 point is not on the curve");
    ("single: not an object", String.equal (jwk_err "[]")
       "jwk: JWK is not a JSON object");
    ("single: duplicate json keys",
     String.starts_with ~prefix:"json:"
       (jwk_err "{\"kty\":\"oct\",\"kty\":\"oct\"}"))
  ]

let set_err (json : string) : string = err_name (Jose.Jwks.parse json)

let set_structural_checks : (string * bool) list =
  [ ("set: keys missing", String.equal (set_err "{}") "jwk: keys is missing");
    ("set: keys not a list",
     String.equal (set_err "{\"keys\":3}") "jwk: keys is not a list");
    ("set: not an object",
     String.equal (set_err "[]") "jwk: JWK Set is not a JSON object");
    ("set: entry not an object",
     String.equal (set_err "{\"keys\":[3]}")
       "jwk: JWK Set entry is not an object");
    ("set: non-string kid fatal",
     String.equal (set_err "{\"keys\":[{\"kty\":\"oct\",\"kid\":3}]}")
       "jwk: kid is not a string");
    ("set: private material fatal even in a droppable entry",
     String.equal
       (set_err "{\"keys\":[{\"kty\":\"OKP\",\"d\":\"AA\"}]}")
       "jwk: private key member d");
    ("set: duplicate kid fatal",
     String.equal
       (set_err ("{\"keys\":[" ^ oct_jwk "same" ^ "," ^ rsa_jwk "same" ^ "]}"))
       "jwk: duplicate kid in JWK Set");
    ("set: duplicate kid ok when one entry dropped",
     Result.is_ok
       (Jose.Jwks.parse
          ("{\"keys\":[" ^ oct_jwk "same"
           ^ ",{\"kty\":\"OKP\",\"kid\":\"same\"}]}")));
    ("set: empty keys parses",
     Result.fold ~error:(fun (_ : Jose.Error.t) -> false)
       ~ok:(fun (s : Jose.Jwks.t) ->
         Int.equal (List.length (Jose.Jwks.keys s)) 0
         && Int.equal (Jose.Jwks.dropped s) 0)
       (Jose.Jwks.parse "{\"keys\":[]}"))
  ]

let () =
  run
    (rfc7517_checks @ e2e_checks @ mixed_checks @ kidless_checks
    @ single_parse_checks @ set_structural_checks)
