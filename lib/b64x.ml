(* Strict base64url (RFC 7515 flavor of RFC 4648 section 5): no padding,
   no line breaks, no bytes outside the alphabet, canonical trailing bits,
   and length mod 4 <> 1. A '=' is simply outside the alphabet, so padded
   input is rejected by the same rule as any other foreign byte. *)

let ( let* ) = Result.bind

let enc_chars : char list =
  List.of_seq
    (String.to_seq
       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

(* Total: the index is masked to [0, 63]. *)
let enc_char (i : int) : char =
  Option.value (List.nth_opt enc_chars (i land 63)) ~default:'A'

let dec_assoc : (char * int) list = List.mapi (fun i c -> (c, i)) enc_chars

let dec_val (c : char) : int option = List.assoc_opt c dec_assoc

let encode (s : string) : string =
  let emit3 (a : int) (b : int) (c : int) : char list =
    [ enc_char (a lsr 2);
      enc_char (((a land 3) lsl 4) lor (b lsr 4));
      enc_char (((b land 15) lsl 2) lor (c lsr 6));
      enc_char (c land 63) ]
  in
  let rec go (acc : char list list) (codes : int list) : string =
    match codes with
    | [] -> String.of_seq (List.to_seq (List.concat (List.rev acc)))
    | [ a ] ->
      go ([ enc_char (a lsr 2); enc_char ((a land 3) lsl 4) ] :: acc) []
    | [ a; b ] ->
      go
        ([ enc_char (a lsr 2);
           enc_char (((a land 3) lsl 4) lor (b lsr 4));
           enc_char ((b land 15) lsl 2) ]
        :: acc)
        []
    | a :: b :: c :: rest -> go (emit3 a b c :: acc) rest
  in
  go [] (List.map Char.code (List.of_seq (String.to_seq s)))

let decode (s : string) : (string, Errx.t) result =
  let bad (why : string) : ('a, Errx.t) result = Error (Errx.B64_invalid why) in
  (* Fold every char to its 6-bit value; group values four at a time. *)
  let step (st : (int list * int list, Errx.t) result) (c : char) :
      (int list * int list, Errx.t) result =
    let* out_rev, group = st in
    let* v =
      Option.to_result (dec_val c) ~none:(Errx.B64_invalid "byte outside alphabet")
    in
    match group with
    | [ y; x; w ] ->
      (* Four 6-bit values w x y v make three bytes. Bytes are pushed most
         significant last, so out_rev stays in reverse output order. *)
      Ok
        ( (((y land 3) lsl 6) lor v)
          :: (((x land 15) lsl 4) lor (y lsr 2))
          :: ((w lsl 2) lor (x lsr 4))
          :: out_rev,
          [] )
    | short -> Ok (out_rev, v :: short)
  in
  let regroup (g_rev : int list) (out_rev : int list) :
      (string, Errx.t) result =
    (* g_rev holds the trailing partial group, most recent value first. *)
    match List.rev g_rev with
    | [] -> Ok (Bytesx.of_codes (List.rev out_rev))
    | [ _ ] -> bad "length mod 4 = 1"
    | [ a; b ] ->
      if Int.equal (b land 15) 0 then
        Ok (Bytesx.of_codes (List.rev (((a lsl 2) lor (b lsr 4)) :: out_rev)))
      else bad "non-zero trailing bits"
    | [ a; b; c ] ->
      if Int.equal (c land 3) 0 then
        Ok
          (Bytesx.of_codes
             (List.rev
                (((b lsl 4) lor (c lsr 2))
                :: ((a lsl 2) lor (b lsr 4))
                :: out_rev)))
      else bad "non-zero trailing bits"
    | _ :: _ :: _ :: _ :: _ -> bad "internal group overflow"
  in
  let* out_rev, group =
    List.fold_left step (Ok ([], [])) (List.of_seq (String.to_seq s))
  in
  regroup group out_rev
