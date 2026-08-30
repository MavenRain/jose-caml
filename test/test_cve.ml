(* M14: runtime CVE corpus. One attack vector per row of DESIGN section 2
   (the threat model this design deletes), each driven through the public
   API and pinned to the exact typed error that kills it. The suite is the
   table, executable: if a defense regresses, the row for its CVE class
   goes red with the wrong error, not merely "some test failed".

   Row -> CVE / class -> where it dies here:
     1  alg=none accepted            CVE-2015-9235            Alg_unsupported "none"
     2  RS256->HS256 confusion       CVE-2016-5431/10555      Alg_mismatch + Key_rejected
     3  embedded jwk header          CVE-2018-0114            Header_rejected_member "jwk"
     4  kid injection (path/SQL)     Auth0 advisories         opaque kid: no lookup, verbatim hint
     5  psychic signature r=0/s=0    CVE-2022-21449           Sig_invalid (ECDSA reject)
     6  signature stripping          many                     Token_shape "empty signature"
     7  non-canonical base64url      jwt bypass class         B64_invalid
     8  duplicate JSON keys          claim smuggling          Json_invalid "duplicate key"
     9  missing exp / eternal        operational              Missing_claim "exp"
    10  aud not checked / replay     cross-service replay     Missing_claim "aud" / Aud_mismatch
    11  crit bypass                  RFC 7515 4.1.11          Crit_unsupported
    12  compression bomb (zip)       zip header               Header_rejected_member "zip"

   Everything here goes through Jose.Jwt / Jose.Key / Jose.Jwks only: the
   corpus attacks the same public surface a caller has, so a vector that
   reached a defense in the real library reaches it here. *)

let ( let* ) = Result.bind

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

let b64 : string -> string = Jose.B64url.encode

let dec (s : string) : string =
  Result.fold ~ok:Fun.id
    ~error:(fun (_ : Jose.Error.t) -> "")
    (Jose.B64url.decode s)

let secret : string = "test-secret-test-secret-test-sec"

(* A well-formed HS256 token from the library's own encoder and MAC, so
   any rejection below is the named defense firing, never a malformed
   fixture. *)
let mk_token ?(secret = secret) (header : string) (payload : string) : string =
  let si = b64 header ^ "." ^ b64 payload in
  si ^ "." ^ b64 (Jose.Hmac.sha256 ~key:secret si)

let check_sig (key : 'a Jose.Key.t) (token : string) :
    (unit, Jose.Error.t) result =
  Jose.Jwt.check_signature ~key token

(* RFC 7515 A.2 RSA public key (pinned by test_rsa + diff_rfc.py). *)
let a2_n64 : string =
  "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp"
  ^ "-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOW"
  ^ "vG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUs"
  ^ "LA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9k"
  ^ "G4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2"
  ^ "PAcDTW9gb54h4FRWyuXpoQ"

(* RFC 7515 A.3 EC public key, signing input and token (all pinned by
   test_p256 + diff_rfc.py). The token verifies, so the psychic row can
   show the ES256 verifier rejects r=0/s=0 without wholesale-rejecting a
   valid signature. *)
let a3_x64 : string = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
let a3_y64 : string = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"

let a3_p64 : string =
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
  ^ "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

let a3_s64 : string =
  "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
  ^ "pmWQxfKTUJqPP3-Kg6NU1Q"

let a3_token : string = "eyJhbGciOiJFUzI1NiJ9" ^ "." ^ a3_p64 ^ "." ^ a3_s64

(* A JWK Set holding one real RS256 verification key at a known kid, for
   the kid-injection row: [find] only ever compares kid for equality. *)
let jwks_json : string =
  "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"prod-key\",\"use\":\"sig\","
  ^ "\"alg\":\"RS256\",\"n\":\"" ^ a2_n64 ^ "\",\"e\":\"AQAB\"}]}"

(* ---------- rows that need only an HS256 verifier key ---------- *)

let hs_rows (key : Jose.Key.hs256 Jose.Key.t) : (string * bool) list =
  let good = mk_token "{\"alg\":\"HS256\",\"typ\":\"JWT\"}" "{}" in
  [ (* row 1: alg=none accepted (CVE-2015-9235). "none" never parses. *)
    ("CVE-2015-9235 alg=none rejected",
     check_sig key (mk_token "{\"alg\":\"none\"}" "{}")
     = Error (Jose.Error.Alg_unsupported "none"));
    (* row 2b: the smuggled public key as a MAC secret (CVE-2016-10555).
       Key.hs256 refuses PEM/DER-shaped material, so an RS256 public key
       cannot be re-labeled an HMAC secret. *)
    ("CVE-2016-10555 pubkey-as-MAC-secret rejected",
     Result.fold
       ~ok:(fun (_ : Jose.Key.hs256 Jose.Key.t) -> false)
       ~error:(fun (e : Jose.Error.t) ->
         String.equal (Jose.Error.to_string e)
           "key rejected: HS256 secret looks like asymmetric key material")
       (Jose.Key.hs256
          ~secret:
            "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n-----END PUBLIC KEY-----"));
    (* row 3: embedded jwk header trusted (CVE-2018-0114). *)
    ("CVE-2018-0114 embedded jwk rejected",
     check_sig key (mk_token "{\"alg\":\"HS256\",\"jwk\":{\"kty\":\"oct\"}}" "{}")
     = Error (Jose.Error.Header_rejected_member "jwk"));
    (* row 6: signature stripping / empty signature. *)
    ("empty-signature stripping rejected",
     check_sig key "eyJhbGciOiJIUzI1NiJ9.e30."
     = Error (Jose.Error.Token_shape "empty signature"));
    (* row 7: non-canonical base64url. The signature IS the correct MAC,
       re-encoded with '=' padding; only the strict decoder rejects it. *)
    ("non-canonical base64url rejected",
     check_sig key (good ^ "=")
     = Error (Jose.Error.B64_invalid "byte outside alphabet"));
    (* row 8: duplicate JSON keys (claim smuggling). *)
    ("duplicate-key smuggling rejected",
     Result.fold
       ~ok:(fun () -> false)
       ~error:(fun (e : Jose.Error.t) ->
         String.equal (Jose.Error.to_string e) "json: duplicate key")
       (check_sig key (mk_token "{\"alg\":\"HS256\",\"alg\":\"HS256\"}" "{}")));
    (* row 11: crit bypass (RFC 7515 4.1.11). *)
    ("crit-bypass rejected",
     check_sig key
       (mk_token "{\"alg\":\"HS256\",\"crit\":[\"exp\"],\"exp\":1}" "{}")
     = Error Jose.Error.Crit_unsupported);
    (* row 12: compression bomb via zip header. *)
    ("zip-bomb header rejected",
     check_sig key (mk_token "{\"alg\":\"HS256\",\"zip\":\"DEF\"}" "{}")
     = Error (Jose.Error.Header_rejected_member "zip"));
    (* row 4c: the kid is an opaque hint, returned verbatim and never
       interpreted, so a SQL/path payload cannot escape into a lookup. *)
    ("Auth0 kid-injection hint stays opaque",
     Jose.Jwt.kid_hint
       (mk_token "{\"alg\":\"HS256\",\"kid\":\"' OR '1'='1\"}" "{}")
     = Some "' OR '1'='1")
  ]

(* ---------- row 2a: RS256->HS256 key confusion, gate before crypto ----- *)

let confusion_rows : (string * bool) list =
  Result.fold
    ~error:(fun (_ : Jose.Error.t) ->
      [ ("fixture: rs256 key builds", false) ])
    ~ok:(fun (rskey : Jose.Key.rs256 Jose.Key.t) ->
      (* An RS256 relying party is handed an HS256 token (the forgery is
         MAC'd with anything; it never gets that far). The header alg must
         equal the key's alg before any crypto runs, so it dies here. *)
      [ ("CVE-2016-5431 RS256/HS256 confusion rejected",
         check_sig rskey (mk_token "{\"alg\":\"HS256\"}" "{}")
         = Error
             (Jose.Error.Alg_mismatch { token = "HS256"; key = "RS256" }))
      ])
    (Jose.Key.rs256 ~n:(dec a2_n64) ~e:(dec "AQAB"))

(* ---------- row 5: psychic signature r=0 or s=0 (CVE-2022-21449) ------- *)

let psychic_rows : (string * bool) list =
  Result.fold
    ~error:(fun (_ : Jose.Error.t) ->
      [ ("fixture: es256 key builds", false) ])
    ~ok:(fun (eskey : Jose.Key.es256 Jose.Key.t) ->
      (* A 64-byte all-zero signature is r=0 || s=0: the classic psychic
         signature. It clears the length gate and dies in the ECDSA
         check, not before. *)
      let zero_sig = b64 (String.make 64 '\000') in
      let token =
        b64 "{\"alg\":\"ES256\"}" ^ "." ^ b64 "{}" ^ "." ^ zero_sig
      in
      [ (* Positive control: without it, a verifier that rejected every
           signature would pass the psychic row for the wrong reason. *)
        ("ES256 A.3 valid signature accepted (positive control)",
         check_sig eskey a3_token = Ok ());
        ("CVE-2022-21449 psychic r=0,s=0 rejected",
         check_sig eskey token = Error Jose.Error.Sig_invalid)
      ])
    (Jose.Key.es256 ~x:(dec a3_x64) ~y:(dec a3_y64))

(* ---------- row 4: kid injection through a JWK Set lookup ------------- *)

let jwks_rows : (string * bool) list =
  Result.fold
    ~error:(fun (_ : Jose.Error.t) -> [ ("fixture: jwks parses", false) ])
    ~ok:(fun (set : Jose.Jwks.t) ->
      [ (* A path-traversal kid matches nothing: kid is compared for
           equality, never resolved against a filesystem or store. *)
        ("Auth0 kid path-traversal finds no key",
         Jose.Jwks.find ~kid:"../../../etc/passwd" set = None);
        (* The genuine kid still resolves, so the equality lookup works. *)
        ("Auth0 kid exact match resolves",
         Option.is_some (Jose.Jwks.find ~kid:"prod-key" set))
      ])
    (Jose.Jwks.parse jwks_json)

(* ---------- rows 9, 10: mandatory exp and aud in the full pipeline ---- *)

let claim_rows : (string * bool) list =
  Result.fold
    ~error:(fun (_ : Jose.Error.t) -> [ ("fixture: jwt pipeline", false) ])
    ~ok:(fun (checks : (string * bool) list) -> checks)
    (let* key = Jose.Key.hs256 ~secret in
     let* iss = Jose.Expect.issuer "https://op.example" in
     let* aud = Jose.Expect.audience "svc" in
     let* now = Jose.Time.of_epoch_seconds 1500000000 in
     let expect = Jose.Expect.make ~iss ~aud () in
     let h = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}" in
     let verify (payload : string) =
       Jose.Jwt.verify ~key ~expect ~now (mk_token h payload)
     in
     Ok
       [ (* row 9: an eternal token (no exp) is refused; exp is mandatory. *)
         ("missing-exp eternal token rejected",
          verify "{\"iss\":\"https://op.example\",\"aud\":\"svc\"}"
          = Error (Jose.Error.Missing_claim "exp"));
         (* row 10a: a token that never names an audience cannot be
            replayed cross-service; aud is a mandatory witness. *)
         ("missing-aud replay rejected",
          verify "{\"iss\":\"https://op.example\",\"exp\":2000000000}"
          = Error (Jose.Error.Missing_claim "aud"));
         (* row 10b: a token minted for another service is rejected here. *)
         ("wrong-aud cross-service replay rejected",
          verify
            "{\"iss\":\"https://op.example\",\"aud\":\"other-svc\",\"exp\":2000000000}"
          = Error Jose.Error.Aud_mismatch)
       ])

let with_hs_key (f : Jose.Key.hs256 Jose.Key.t -> (string * bool) list) :
    (string * bool) list =
  Result.fold
    ~error:(fun (_ : Jose.Error.t) -> [ ("fixture: hs256 key builds", false) ])
    ~ok:f
    (Jose.Key.hs256 ~secret)

(* One canonical vector per DESIGN section 2 row (some rows carry a second
   facet the table names) plus one positive ES256 control. A shrunk list --
   any fixture short-circuit above -- fails this pin as lost coverage. *)
let expected_total : int = 17

let () =
  let all =
    with_hs_key hs_rows @ confusion_rows @ psychic_rows @ jwks_rows
    @ claim_rows
  in
  run
    (("cve corpus total pinned", Int.equal (List.length all) expected_total)
    :: all)
