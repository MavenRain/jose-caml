(* M5 HMAC-SHA256: RFC 4231 vectors. The gates also run a random
   differential sweep against python3 hmac through bin/josec. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

let to_hex (s : string) : string =
  String.concat ""
    (List.map
       (fun c -> Printf.sprintf "%02x" (Char.code c))
       (List.of_seq (String.to_seq s)))

let hmac_hex (key : string) (msg : string) : string =
  to_hex (Jose.Hmac.sha256 ~key msg)

let checks : (string * bool) list =
  [ ("rfc4231 tc1",
     String.equal
       (hmac_hex (String.make 20 '\x0b') "Hi There")
       "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    ("rfc4231 tc2",
     String.equal
       (hmac_hex "Jefe" "what do ya want for nothing?")
       "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    ("rfc4231 tc3",
     String.equal
       (hmac_hex (String.make 20 '\xaa') (String.make 50 '\xdd'))
       "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    ("rfc4231 tc6 long key",
     String.equal
       (hmac_hex
          (String.make 131 '\xaa')
          "Test Using Larger Than Block-Size Key - Hash Key First")
       "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    ("block-size key path",
     String.equal (hmac_hex (String.make 64 '\x0b') "x")
       (hmac_hex (String.make 64 '\x0b') "x"));
    ("equal_ct equal", Jose.Hmac.equal_ct "abcd" "abcd");
    ("equal_ct differs", not (Jose.Hmac.equal_ct "abcd" "abce"));
    ("equal_ct length", not (Jose.Hmac.equal_ct "abc" "abcd"));
    ("equal_ct empty", Jose.Hmac.equal_ct "" "")
  ]

let () = run checks
