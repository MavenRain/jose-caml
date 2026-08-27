(* HMAC-SHA256 (RFC 2104 / FIPS 198-1) over sha2-caml, and the
   constant-time comparison used for every MAC check. *)

let block_size : int = 64

let pad_key (key : string) : string =
  let k =
    if String.length key > block_size then Sha2.Sha256.digest key else key
  in
  k ^ String.make (block_size - String.length k) '\x00'

let xor_with (mask : int) (s : string) : string =
  String.map (fun c -> Bytesx.chr (Char.code c lxor mask)) s

let sha256 ~(key : string) (msg : string) : string =
  let k = pad_key key in
  Sha2.Sha256.digest
    (xor_with 0x5c k ^ Sha2.Sha256.digest (xor_with 0x36 k ^ msg))

(* Accumulate the OR of every byte difference; no early exit, so the
   running time does not depend on where the first difference sits. *)
let equal_ct (a : string) (b : string) : bool =
  Int.equal (String.length a) (String.length b)
  && Int.equal
       (Seq.fold_left
          (fun acc (x, y) -> acc lor (Char.code x lxor Char.code y))
          0
          (Seq.zip (String.to_seq a) (String.to_seq b)))
       0
