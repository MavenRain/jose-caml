(* M9 limbs: 16-bit limb bignum + arbitrary-modulus modexp. The 255-bit
   modexp constants below are recomputed by harness/diff_rfc.py with
   python pow() and must appear here verbatim. *)

module L = Jose__Limbsx

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

let rec of_int (n : int) : int list =
  if n <= 0 then [] else (n land 0xffff) :: of_int (n lsr 16)

let of_hex (s : string) : int list = L.limbs_of_be_bytes (L.ints_of_hex s)

(* 2^255 - 19; base is arbitrary; result pinned by diff_rfc.py. *)
let m255 = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
let b255 = "4a7c559911fa2016c34479067b47d02be2b17b0b1b0d8a2d6d312bc939b204d1"
let r255 = "5eb83da95dcbbc85d618d524bffd39e9edd7b8a0de199ebd5e43829a52b80264"

let checks : (string * bool) list =
  [ ("carry_norm oversize", L.carry_norm [ 0x1ffff ] = [ 0xffff; 1 ]);
    ("trim high zeros", L.trim [ 5; 0; 0 ] = [ 5 ]);
    ("trim zero", L.trim [ 0; 0 ] = []);
    ("cmp lt same length", L.cmp [ 0; 1 ] [ 1; 1 ] < 0);
    ("cmp by length", L.cmp [ 0xffff ] [ 0; 1 ] < 0);
    ("cmp eq trims", L.cmp [ 7; 0 ] [ 7 ] = 0);
    ("add carry", L.carry_norm (L.add_lists [ 0xffff ] [ 1 ]) = [ 0; 1 ]);
    ("sub borrow", L.sub_limbs [ 0; 1 ] [ 1 ] = [ 0xffff; 0 ]);
    ("map2t stops short", L.map2t ( + ) [ 1; 2 ] [ 10 ] = [ 11 ]);
    ("pad_to", L.pad_to 3 [ 1 ] = [ 1; 0; 0 ]);
    ("split_at", L.split_at 2 [ 1; 2; 3 ] = ([ 1; 2 ], [ 3 ]));
    ("mul 0xffff^2",
     L.trim (L.carry_norm (L.mul_limbs (of_int 0xffff) (of_int 0xffff)))
     = of_int 0xfffe0001);
    ("mul by zero", L.trim (L.carry_norm (L.mul_limbs [] (of_int 5))) = []);
    ("bits_of_limbs two",
     (match L.bits_of_limbs [ 2 ] with
      | 0 :: 1 :: rest -> List.for_all (Int.equal 0) rest
      | _ :: _ | [] -> false));
    ("le bytes to limb", L.limbs_of_le_bytes [ 0x34; 0x12 ] = [ 0x1234 ]);
    ("be hex to limb", of_hex "0102" = [ 0x0102 ]);
    ("ints_of_hex mixed case", L.ints_of_hex "aAbB" = [ 0xaa; 0xbb ]);
    ("bytes roundtrip",
     L.bytes_to_ints (L.ints_to_bytes [ 0; 127; 255 ]) = [ 0; 127; 255 ]);
    ("string_to_ints", L.string_to_ints "AB" = [ 65; 66 ]);
    ("mod_red basic", L.mod_red (of_int 7) (of_int 100) = of_int 2);
    ("mod_red below modulus", L.mod_red (of_int 1000) (of_int 999) = of_int 999);
    ("mod_red oversized limb input", L.mod_red (of_int 1000) [ 1000001 ] = [ 1 ]);
    ("mod_red to zero", L.mod_red (of_int 1000) [ 1000000 ] = []);
    ("mod_pow 3^5 mod 7", L.mod_pow (of_int 7) (of_int 3) (of_int 5) = Some (of_int 5));
    ("mod_pow 2^10 mod 1000",
     L.mod_pow (of_int 1000) (of_int 2) (of_int 10) = Some (of_int 24));
    ("mod_pow rsa toy sign 65^17 mod 3233",
     L.mod_pow (of_int 3233) (of_int 65) (of_int 17) = Some (of_int 2790));
    ("mod_pow rsa toy verify 2790^2753 mod 3233",
     L.mod_pow (of_int 3233) (of_int 2790) (of_int 2753) = Some (of_int 65));
    ("mod_pow exp zero", L.mod_pow (of_int 7) (of_int 3) [] = Some (of_int 1));
    ("mod_pow base zero", L.mod_pow (of_int 7) [] (of_int 5) = Some []);
    ("mod_pow modulus one", L.mod_pow (of_int 1) (of_int 3) (of_int 5) = Some []);
    ("mod_pow modulus zero", L.mod_pow [] (of_int 3) (of_int 5) = None);
    ("mod_pow 255-bit e=65537",
     L.mod_pow (of_hex m255) (of_hex b255) (of_int 65537) = Some (of_hex r255))
  ]

let () = run checks
