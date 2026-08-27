(* Strict minimal JSON, adapted from x402-caml's wire codec. Token input
   is attacker-controlled, so: nesting depth cap, integer overflow
   rejection, duplicate-key rejection at every depth, raw control
   characters rejected in strings, canonical integers only (no leading
   zeros, no fraction, no exponent). Unicode escapes cover U+0000..U+00FF;
   higher code points travel as raw UTF-8 bytes. *)

type t =
  | Jnull
  | Jbool of bool
  | Jint of int
  | Jstring of string
  | Jlist of t list
  | Jobj of (string * t) list

let ( let* ) = Result.bind

let hex_chars : char list = List.of_seq (String.to_seq "0123456789abcdef")

let hex_char (n : int) : char =
  Option.value (List.nth_opt hex_chars (n land 15)) ~default:'0'

let hex_value (c : char) : int option =
  let code = Char.code c in
  match () with
  | () when 48 <= code && code <= 57 -> Some (code - 48)
  | () when 97 <= code && code <= 102 -> Some (code - 87)
  | () when 65 <= code && code <= 70 -> Some (code - 55)
  | () -> None

(* ---------- emitter ---------- *)

let escape_char (c : char) : string =
  match c with
  | '"' -> "\\\""
  | '\\' -> "\\\\"
  | '\n' -> "\\n"
  | '\r' -> "\\r"
  | '\t' -> "\\t"
  | _ ->
    let code = Char.code c in
    if code < 32 then
      String.of_seq
        (List.to_seq
           [ '\\'; 'u'; '0'; '0'; hex_char (code lsr 4); hex_char code ])
    else String.make 1 c

let escape_string (s : string) : string =
  String.concat "" (List.map escape_char (List.of_seq (String.to_seq s)))

let rec emit (v : t) : string =
  match v with
  | Jnull -> "null"
  | Jbool b -> if b then "true" else "false"
  | Jint n -> string_of_int n
  | Jstring s -> "\"" ^ escape_string s ^ "\""
  | Jlist items -> "[" ^ String.concat "," (List.map emit items) ^ "]"
  | Jobj fields ->
    "{"
    ^ String.concat ","
        (List.map
           (fun (k, v) -> "\"" ^ escape_string k ^ "\":" ^ emit v)
           fields)
    ^ "}"

(* ---------- parser ---------- *)

(* Token input is untrusted: cap container nesting so a hostile payload
   cannot exhaust the stack. *)
let max_depth : int = 32

(* At most 18 digits: every accepted magnitude fits a 63-bit int, so the
   accumulator can never wrap. *)
let max_digits : int = 18

let digit_value (c : char) : int option =
  let n = Char.code c - 48 in
  if 0 <= n && n <= 9 then Some n else None

let rec skip_ws (cs : char list) : char list =
  match cs with
  | ' ' :: rest | '\n' :: rest | '\r' :: rest | '\t' :: rest -> skip_ws rest
  | _ -> cs

let expect (c : char) (cs : char list) : (char list, string) result =
  match cs with
  | x :: rest when x = c -> Ok rest
  | _ -> Error ("expected '" ^ String.make 1 c ^ "'")

let literal (word : string) (value : t) (cs : char list) :
    (t * char list, string) result =
  let chars = List.of_seq (String.to_seq word) in
  let rec eat (want : char list) (have : char list) :
      (t * char list, string) result =
    match want with
    | [] -> Ok (value, have)
    | w :: ws ->
      (match have with
       | h :: hs when h = w -> eat ws hs
       | _ -> Error ("expected literal " ^ word))
  in
  eat chars cs

let unicode_escape (h1 : char) (h2 : char) (h3 : char) (h4 : char) :
    char option =
  Option.bind (hex_value h1) (fun v1 ->
      Option.bind (hex_value h2) (fun v2 ->
          Option.bind (hex_value h3) (fun v3 ->
              Option.bind (hex_value h4) (fun v4 ->
                  let code = (v1 lsl 12) lor (v2 lsl 8) lor (v3 lsl 4) lor v4 in
                  if code < 256 then Some (Bytesx.chr code) else None))))

let parse_string_body (cs : char list) : (string * char list, string) result =
  let rec go (acc : char list) (rest : char list) :
      (string * char list, string) result =
    match rest with
    | [] -> Error "unterminated string"
    | '"' :: tail -> Ok (String.of_seq (List.to_seq (List.rev acc)), tail)
    | '\\' :: '"' :: tail -> go ('"' :: acc) tail
    | '\\' :: '\\' :: tail -> go ('\\' :: acc) tail
    | '\\' :: 'n' :: tail -> go ('\n' :: acc) tail
    | '\\' :: 'r' :: tail -> go ('\r' :: acc) tail
    | '\\' :: 't' :: tail -> go ('\t' :: acc) tail
    | '\\' :: '/' :: tail -> go ('/' :: acc) tail
    | '\\' :: 'u' :: h1 :: h2 :: h3 :: h4 :: tail ->
      Option.fold (unicode_escape h1 h2 h3 h4)
        ~none:(Error "unsupported unicode escape")
        ~some:(fun c -> go (c :: acc) tail)
    | '\\' :: _ -> Error "unsupported escape"
    | c :: tail ->
      if Char.code c < 32 then Error "raw control character in string"
      else go (c :: acc) tail
  in
  go [] cs

let parse_int_body (cs : char list) : (t * char list, string) result =
  let negative, cs =
    match cs with
    | '-' :: rest -> (true, rest)
    | _ -> (false, cs)
  in
  let finish (acc : int list) (count : int) (leading_zero : bool)
      (rest : char list) : (t * char list, string) result =
    match () with
    | () when count = 0 -> Error "expected digit"
    | () when leading_zero && count > 1 -> Error "leading zero"
    | () ->
      let value = List.fold_left (fun a d -> (a * 10) + d) 0 (List.rev acc) in
      Ok (Jint (if negative then -value else value), rest)
  in
  let rec span (acc : int list) (count : int) (leading_zero : bool)
      (rest : char list) : (t * char list, string) result =
    match rest with
    | c :: tail ->
      Option.fold (digit_value c)
        ~some:(fun d ->
          if count >= max_digits then Error "integer out of range"
          else
            span (d :: acc) (count + 1)
              (if count = 0 then d = 0 else leading_zero)
              tail)
        ~none:(finish acc count leading_zero rest)
    | [] -> finish acc count leading_zero []
  in
  span [] 0 false cs

let rec parse_value (depth : int) (cs : char list) :
    (t * char list, string) result =
  match skip_ws cs with
  | [] -> Error "unexpected end of input"
  | '"' :: rest ->
    let* s, rest = parse_string_body rest in
    Ok (Jstring s, rest)
  | 't' :: _ as rest -> literal "true" (Jbool true) rest
  | 'f' :: _ as rest -> literal "false" (Jbool false) rest
  | 'n' :: _ as rest -> literal "null" Jnull rest
  | '[' :: rest ->
    if depth >= max_depth then Error "too deeply nested"
    else parse_list (depth + 1) [] (skip_ws rest)
  | '{' :: rest ->
    if depth >= max_depth then Error "too deeply nested"
    else parse_obj (depth + 1) [] (skip_ws rest)
  | rest -> parse_int_body rest

and parse_list (depth : int) (acc : t list) (cs : char list) :
    (t * char list, string) result =
  match cs with
  | ']' :: rest -> Ok (Jlist (List.rev acc), rest)
  | _ ->
    let* v, rest = parse_value depth cs in
    (match skip_ws rest with
     | ',' :: tail ->
       (match skip_ws tail with
        | ']' :: _ -> Error "expected value after ','"
        | t2 -> parse_list depth (v :: acc) t2)
     | ']' :: tail -> Ok (Jlist (List.rev (v :: acc)), tail)
     | _ -> Error "expected ',' or ']'")

and parse_obj (depth : int) (acc : (string * t) list) (cs : char list) :
    (t * char list, string) result =
  match cs with
  | '}' :: rest -> Ok (Jobj (List.rev acc), rest)
  | '"' :: rest ->
    let* k, rest = parse_string_body rest in
    if List.mem_assoc k acc then Error "duplicate key"
    else
      let* rest = expect ':' (skip_ws rest) in
      let* v, rest = parse_value depth rest in
      (match skip_ws rest with
       | ',' :: tail ->
         (match skip_ws tail with
          | '"' :: _ as t2 -> parse_obj depth ((k, v) :: acc) t2
          | _ -> Error "expected key after ','")
       | '}' :: tail -> Ok (Jobj (List.rev ((k, v) :: acc)), tail)
       | _ -> Error "expected ',' or '}'")
  | _ -> Error "expected key or '}'"

let parse (s : string) : (t, string) result =
  let* v, rest = parse_value 0 (List.of_seq (String.to_seq s)) in
  match skip_ws rest with
  | [] -> Ok v
  | _ :: _ -> Error "trailing input"

(* ---------- helpers ---------- *)

let member (name : string) (v : t) : t option =
  match v with
  | Jobj fields -> List.assoc_opt name fields
  | Jnull | Jbool _ | Jint _ | Jstring _ | Jlist _ -> None

let as_string (v : t) : string option =
  match v with
  | Jstring s -> Some s
  | Jnull | Jbool _ | Jint _ | Jlist _ | Jobj _ -> None

let as_int (v : t) : int option =
  match v with
  | Jint n -> Some n
  | Jnull | Jbool _ | Jstring _ | Jlist _ | Jobj _ -> None
