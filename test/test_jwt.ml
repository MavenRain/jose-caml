(* M4 header policy + M6 JWS + M7 claims pipeline, all through the
   public API. Tokens are built with the library's own encoder and HMAC;
   external correctness of the crypto is pinned by the RFC 7515 A.1
   vector, which the gates additionally recompute with python3. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

let secret : string = "test-secret-test-secret-test-sec"

let mk_token ?(secret = secret) (header : string) (payload : string) : string
    =
  let si = Jose.B64url.encode header ^ "." ^ Jose.B64url.encode payload in
  si ^ "." ^ Jose.B64url.encode (Jose.Hmac.sha256 ~key:secret si)

(* RFC 7515 appendix A.1. The header and payload contain CRLF whitespace;
   the key is the A.1 JWK "k" value. See gates.sh: diff_rfc7515.py
   recomputes this signature from the key and the signing input. *)
let a1_token : string =
  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
  ^ ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
  ^ "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
  ^ ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

let a1_key_b64 : string =
  "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T"
  ^ "-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

let err_name (r : ('a, Jose.Error.t) result) : string =
  Result.fold ~ok:(fun (_ : 'a) -> "ok") ~error:Jose.Error.to_string r

let with_key (checks : Jose.Key.hs256 Jose.Key.t -> (string * bool) list) :
    (string * bool) list =
  Result.fold
    ~error:(fun (_ : Jose.Error.t) -> [ ("fixture: hs256 key builds", false) ])
    ~ok:checks
    (Jose.Key.hs256 ~secret)

let check_sig (key : 'a Jose.Key.t) (token : string) :
    (unit, Jose.Error.t) result =
  Jose.Jwt.check_signature ~key token

let jws_checks : (string * bool) list =
  with_key (fun key ->
      let h = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}" in
      let good = mk_token h "{\"a\":1}" in
      let wrong_sig = mk_token ~secret:(String.make 32 'z') h "{\"a\":1}" in
      [ ("self-built verifies", check_sig key good = Ok ());
        ("wrong secret rejected", check_sig key wrong_sig = Error Jose.Error.Sig_invalid);
        ("alg none rejected",
         check_sig key (mk_token "{\"alg\":\"none\"}" "{}")
         = Error (Jose.Error.Alg_unsupported "none"));
        ("alg RS256 vs HS256 key",
         check_sig key (mk_token "{\"alg\":\"RS256\"}" "{}")
         = Error
             (Jose.Error.Alg_mismatch { token = "RS256"; key = "HS256" }));
        ("embedded jwk rejected",
         check_sig key
           (mk_token "{\"alg\":\"HS256\",\"jwk\":{\"kty\":\"oct\"}}" "{}")
         = Error (Jose.Error.Header_rejected_member "jwk"));
        ("jku rejected",
         check_sig key
           (mk_token "{\"alg\":\"HS256\",\"jku\":\"https://evil\"}" "{}")
         = Error (Jose.Error.Header_rejected_member "jku"));
        ("x5u rejected",
         check_sig key (mk_token "{\"alg\":\"HS256\",\"x5u\":\"u\"}" "{}")
         = Error (Jose.Error.Header_rejected_member "x5u"));
        ("zip rejected",
         check_sig key (mk_token "{\"alg\":\"HS256\",\"zip\":\"DEF\"}" "{}")
         = Error (Jose.Error.Header_rejected_member "zip"));
        ("cty rejected",
         check_sig key (mk_token "{\"alg\":\"HS256\",\"cty\":\"JWT\"}" "{}")
         = Error (Jose.Error.Header_rejected_member "cty"));
        ("crit rejected",
         check_sig key
           (mk_token "{\"alg\":\"HS256\",\"crit\":[\"exp\"],\"exp\":1}" "{}")
         = Error Jose.Error.Crit_unsupported);
        ("typ JWT ok",
         check_sig key (mk_token "{\"alg\":\"HS256\",\"typ\":\"jwt\"}" "{}")
         = Ok ());
        ("typ other rejected",
         check_sig key (mk_token "{\"alg\":\"HS256\",\"typ\":\"at+jwt\"}" "{}")
         = Error (Jose.Error.Typ_rejected "at+jwt"));
        ("dup header key rejected",
         Result.fold
           ~ok:(fun () -> false)
           ~error:(fun (e : Jose.Error.t) ->
             match e with
             | Jose.Error.Json_invalid (_ : string) -> true
             | Jose.Error.B64_invalid (_ : string) | Jose.Error.Token_shape _
             | Jose.Error.Alg_unsupported _ | Jose.Error.Alg_mismatch _
             | Jose.Error.Header_rejected_member _
             | Jose.Error.Crit_unsupported | Jose.Error.Typ_rejected _
             | Jose.Error.Header_malformed _ | Jose.Error.Sig_invalid
             | Jose.Error.Key_rejected _ | Jose.Error.Missing_claim _
             | Jose.Error.Claim_malformed _ | Jose.Error.Iss_mismatch
             | Jose.Error.Aud_mismatch | Jose.Error.Expired _
             | Jose.Error.Not_yet_valid _ | Jose.Error.Iat_in_future _
             | Jose.Error.Time_invalid _ | Jose.Error.Expect_invalid _ ->
               false)
           (check_sig key
              (mk_token "{\"alg\":\"HS256\",\"alg\":\"HS256\"}" "{}")));
        ("two parts",
         check_sig key "eyJhbGciOiJIUzI1NiJ9.e30"
         = Error (Jose.Error.Token_shape "fewer than three parts"));
        ("four parts",
         check_sig key "a.b.c.d"
         = Error (Jose.Error.Token_shape "more than three parts"));
        ("empty signature part",
         check_sig key "eyJhbGciOiJIUzI1NiJ9.e30."
         = Error (Jose.Error.Token_shape "empty signature"));
        ("empty header part",
         check_sig key ".e30.AAAA"
         = Error (Jose.Error.Token_shape "empty header"));
        ("oversize token",
         check_sig key (String.make 17000 'a')
         = Error (Jose.Error.Token_shape "token longer than 16 KiB"));
        ("padded signature",
         Result.is_error
           (check_sig key ("eyJhbGciOiJIUzI1NiJ9.e30.Zg==")));
        ("short signature",
         (let si =
            Jose.B64url.encode "{\"alg\":\"HS256\"}" ^ "." ^ Jose.B64url.encode "{}"
          in
          check_sig key (si ^ "." ^ Jose.B64url.encode "0123456789abcdef"))
         = Error Jose.Error.Sig_invalid);
        ("tampered payload",
         (let h64 = Jose.B64url.encode h in
          let si = h64 ^ "." ^ Jose.B64url.encode "{\"a\":1}" in
          let s64 = Jose.B64url.encode (Jose.Hmac.sha256 ~key:secret si) in
          check_sig key (h64 ^ "." ^ Jose.B64url.encode "{\"a\":2}" ^ "." ^ s64))
         = Error Jose.Error.Sig_invalid);
        ("kid hint",
         Jose.Jwt.kid_hint
           (mk_token "{\"alg\":\"HS256\",\"kid\":\"key-9\"}" "{}")
         = Some "key-9");
        ("kid hint absent", Jose.Jwt.kid_hint (mk_token h "{}") = None);
        ("kid hint garbage", Jose.Jwt.kid_hint "not-a-token" = None)
      ])

let a1_checks : (string * bool) list =
  Result.fold
    ~error:(fun (_ : Jose.Error.t) -> [ ("fixture: a1 key decodes", false) ])
    ~ok:(fun (k : string) ->
      Result.fold
        ~error:(fun (_ : Jose.Error.t) ->
          [ ("fixture: a1 key accepted", false) ])
        ~ok:(fun key ->
          [ ("rfc7515 a1 verifies", check_sig key a1_token = Ok ());
            ("rfc7515 a1 tamper",
             Result.is_error
               (check_sig key (a1_token ^ "x")))
          ])
        (Jose.Key.hs256 ~secret:k))
    (Jose.B64url.decode a1_key_b64)

let key_checks : (string * bool) list =
  [ ("short secret rejected",
     err_name (Jose.Key.hs256 ~secret:"too-short")
     = "key rejected: HS256 secret shorter than 32 bytes");
    ("pem secret rejected",
     Result.is_error
       (Jose.Key.hs256
          ~secret:
            "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n-----END PUBLIC KEY-----"));
    ("base64 der secret rejected",
     Result.is_error
       (Jose.Key.hs256
          ~secret:"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7v8ddk"));
    ("der secret rejected",
     Result.is_error
       (Jose.Key.hs256 ~secret:("\x30\x82\x01\x22" ^ String.make 40 'q')));
    ("ascii zero secret accepted",
     Result.is_ok (Jose.Key.hs256 ~secret:"0123456789abcdef0123456789abcdef"));
    ("skew cap",
     Result.is_error (Jose.Time.Skew.of_seconds 601)
     && Result.is_ok (Jose.Time.Skew.of_seconds 600));
    ("negative time rejected",
     Result.is_error (Jose.Time.of_epoch_seconds (-1)));
    ("empty issuer rejected", Result.is_error (Jose.Expect.issuer ""));
    ("empty audience rejected", Result.is_error (Jose.Expect.audience ""))
  ]

(* ---------- full pipeline ---------- *)

let ( let* ) = Result.bind

let now_1500 : (Jose.Time.t, Jose.Error.t) result =
  Jose.Time.of_epoch_seconds 1500000000

let jwt_checks : (string * bool) list =
  Result.fold
    ~error:(fun (_ : Jose.Error.t) -> [ ("fixture: jwt pipeline", false) ])
    ~ok:(fun checks -> checks)
    (let* key = Jose.Key.hs256 ~secret in
     let* iss = Jose.Expect.issuer "https://op.example" in
     let* aud = Jose.Expect.audience "svc" in
     let* now = now_1500 in
     let* skew100 = Jose.Time.Skew.of_seconds 100 in
     let expect = Jose.Expect.make ~iss ~aud () in
     let expect_skew = Jose.Expect.make ~iss ~aud ~skew:skew100 () in
     let h = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}" in
     let verify ?(e = expect) (payload : string) =
       Jose.Jwt.verify ~key ~expect:e ~now (mk_token h payload)
     in
     let good =
       "{\"iss\":\"https://op.example\",\"aud\":\"svc\",\"exp\":2000000000,"
       ^ "\"sub\":\"user-7\",\"iat\":1400000000,\"nbf\":1400000000}"
     in
     let* c = verify good in
     Ok
       [ ("happy path subject", Jose.Claims.subject c = Some "user-7");
         ("happy path issuer",
          String.equal (Jose.Claims.issuer c) "https://op.example");
         ("happy path audiences", Jose.Claims.audiences c = [ "svc" ]);
         ("happy path expires",
          Int.equal (Jose.Time.seconds (Jose.Claims.expires c)) 2000000000);
         ("happy path jti", Jose.Claims.jti c = None);
         ("claim lookup",
          Jose.Claims.claim c "aud" = Some (Jose.Json.Jstring "svc"));
         ("aud list member",
          Result.is_ok
            (verify
               "{\"iss\":\"https://op.example\",\"aud\":[\"a\",\"svc\"],\"exp\":2000000000}"));
         ("aud list non-member",
          verify
            "{\"iss\":\"https://op.example\",\"aud\":[\"a\",\"b\"],\"exp\":2000000000}"
          = Error Jose.Error.Aud_mismatch);
         ("aud empty list",
          verify "{\"iss\":\"https://op.example\",\"aud\":[],\"exp\":2000000000}"
          = Error (Jose.Error.Claim_malformed "aud"));
         ("aud mixed list",
          verify
            "{\"iss\":\"https://op.example\",\"aud\":[\"svc\",1],\"exp\":2000000000}"
          = Error (Jose.Error.Claim_malformed "aud"));
         ("aud missing",
          verify "{\"iss\":\"https://op.example\",\"exp\":2000000000}"
          = Error (Jose.Error.Missing_claim "aud"));
         ("iss missing",
          verify "{\"aud\":\"svc\",\"exp\":2000000000}"
          = Error (Jose.Error.Missing_claim "iss"));
         ("iss mismatch",
          verify "{\"iss\":\"https://evil\",\"aud\":\"svc\",\"exp\":2000000000}"
          = Error Jose.Error.Iss_mismatch);
         ("exp missing",
          verify "{\"iss\":\"https://op.example\",\"aud\":\"svc\"}"
          = Error (Jose.Error.Missing_claim "exp"));
         ("exp boundary now",
          verify
            "{\"iss\":\"https://op.example\",\"aud\":\"svc\",\"exp\":1500000000}"
          = Error (Jose.Error.Expired { exp = 1500000000; now = 1500000000 }));
         ("exp boundary now+1",
          Result.is_ok
            (verify
               "{\"iss\":\"https://op.example\",\"aud\":\"svc\",\"exp\":1500000001}"));
         ("exp within skew",
          Result.is_ok
            (verify ~e:expect_skew
               "{\"iss\":\"https://op.example\",\"aud\":\"svc\",\"exp\":1499999950}"));
         ("exp beyond skew",
          verify ~e:expect_skew
            "{\"iss\":\"https://op.example\",\"aud\":\"svc\",\"exp\":1499999900}"
          = Error (Jose.Error.Expired { exp = 1499999900; now = 1500000000 }));
         ("nbf future",
          verify
            "{\"iss\":\"https://op.example\",\"aud\":\"svc\",\"exp\":2000000000,\"nbf\":1500000001}"
          = Error
              (Jose.Error.Not_yet_valid { nbf = 1500000001; now = 1500000000 }));
         ("nbf boundary ok",
          Result.is_ok
            (verify
               "{\"iss\":\"https://op.example\",\"aud\":\"svc\",\"exp\":2000000000,\"nbf\":1500000000}"));
         ("iat future",
          verify
            "{\"iss\":\"https://op.example\",\"aud\":\"svc\",\"exp\":2000000000,\"iat\":1500000700}"
          = Error
              (Jose.Error.Iat_in_future { iat = 1500000700; now = 1500000000 }));
         ("exp as string",
          verify
            "{\"iss\":\"https://op.example\",\"aud\":\"svc\",\"exp\":\"soon\"}"
          = Error (Jose.Error.Claim_malformed "exp"));
         ("exp negative",
          verify "{\"iss\":\"https://op.example\",\"aud\":\"svc\",\"exp\":-1}"
          = Error (Jose.Error.Claim_malformed "exp"));
         ("payload not object",
          verify "[]" = Error (Jose.Error.Claim_malformed "payload is not a JSON object"));
         ("payload dup claims",
          Result.fold
            ~ok:(fun (_ : Jose.Claims.verified Jose.Claims.t) -> false)
            ~error:(fun (e : Jose.Error.t) ->
              String.equal (Jose.Error.to_string e) "json: duplicate key")
            (verify "{\"iss\":\"a\",\"iss\":\"a\"}"))
       ])

let () = run (jws_checks @ a1_checks @ key_checks @ jwt_checks)
