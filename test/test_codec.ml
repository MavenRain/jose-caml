(* M2 base64url + M3 strict JSON. *)

module J = Jose.Json

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

let enc = Jose.B64url.encode
let dec = Jose.B64url.decode
let dec_fails (s : string) : bool = Result.is_error (dec s)

(* All 256 byte values, as a literal (no Char.chr anywhere). *)
let all_bytes : string =
  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  ^ "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
  ^ "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
  ^ "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
  ^ "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
  ^ "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
  ^ "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
  ^ "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
  ^ "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
  ^ "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
  ^ "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
  ^ "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
  ^ "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
  ^ "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
  ^ "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
  ^ "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

let b64_checks : (string * bool) list =
  [ ("enc empty", String.equal (enc "") "");
    ("dec empty", dec "" = Ok "");
    ("enc f", String.equal (enc "f") "Zg");
    ("enc fo", String.equal (enc "fo") "Zm8");
    ("enc foo", String.equal (enc "foo") "Zm9v");
    ("enc foob", String.equal (enc "foob") "Zm9vYg");
    ("enc fooba", String.equal (enc "fooba") "Zm9vYmE");
    ("enc foobar", String.equal (enc "foobar") "Zm9vYmFy");
    ("dec foobar", dec "Zm9vYmFy" = Ok "foobar");
    ("dec foob", dec "Zm9vYg" = Ok "foob");
    ("url alphabet", String.equal (enc "\xff\xef") "_-8");
    ("url alphabet dec", dec "_-8" = Ok "\xff\xef");
    ("roundtrip 256", dec (enc all_bytes) = Ok all_bytes);
    ("reject padding", dec_fails "Zg==");
    ("reject std plus", dec_fails "+A");
    ("reject std slash", dec_fails "/A");
    ("reject newline", dec_fails "Zm9v\nZg");
    ("reject len mod 4 = 1", dec_fails "AAAAA");
    ("reject trailing bits 2char", dec_fails "Zh");
    ("reject trailing bits 3char", dec_fails "Zm9");
    ("accept canonical 3char", dec "Zm8" = Ok "fo");
    ("padding is typed",
     dec "=" = Error (Jose.Error.B64_invalid "byte outside alphabet"))
  ]

let deep (n : int) : string =
  String.concat "" (List.init n (fun (_ : int) -> "["))
  ^ "0"
  ^ String.concat "" (List.init n (fun (_ : int) -> "]"))

let parse_fails (s : string) : bool = Result.is_error (J.parse s)

let json_checks : (string * bool) list =
  [ ("empty obj", J.parse "{}" = Ok (J.Jobj []));
    ("simple", J.parse "{\"a\":1}" = Ok (J.Jobj [ ("a", J.Jint 1) ]));
    ("crlf ws", J.parse " {\r\n \"a\" :\t1 } " = Ok (J.Jobj [ ("a", J.Jint 1) ]));
    ("dup key", parse_fails "{\"a\":1,\"a\":2}");
    ("nested dup key", parse_fails "{\"o\":{\"b\":1,\"b\":2}}");
    ("depth 30 ok", Result.is_ok (J.parse (deep 30)));
    ("depth 33 rejected", parse_fails (deep 33));
    ("neg int", J.parse "-5" = Ok (J.Jint (-5)));
    ("leading zero", parse_fails "007");
    ("19 digits", parse_fails "1234567890123456789");
    ("18 digits ok", Result.is_ok (J.parse "123456789012345678"));
    ("no fraction", parse_fails "1.5");
    ("no exponent", parse_fails "1e3");
    ("escapes", J.parse "\"a\\n\\t\\\"\\\\b\"" = Ok (J.Jstring "a\n\t\"\\b"));
    ("u escape", J.parse "\"\\u0041\"" = Ok (J.Jstring "A"));
    ("u escape above ff", parse_fails "\"\\u1234\"");
    ("raw control char", parse_fails "\"a\x01b\"");
    ("unterminated", parse_fails "\"abc");
    ("trailing input", parse_fails "{} x");
    ("bool null list",
     J.parse "[true,false,null]"
     = Ok (J.Jlist [ J.Jbool true; J.Jbool false; J.Jnull ]));
    ("member", J.member "a" (J.Jobj [ ("a", J.Jint 1) ]) = Some (J.Jint 1));
    ("as_string", J.as_string (J.Jstring "x") = Some "x");
    ("as_int on string", J.as_int (J.Jstring "x") = None);
    ("emit roundtrip",
     J.parse (J.emit (J.Jobj [ ("k", J.Jstring "v\n") ]))
     = Ok (J.Jobj [ ("k", J.Jstring "v\n") ]))
  ]

let () = run (b64_checks @ json_checks)
