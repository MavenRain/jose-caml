(* RSASSA-PKCS1-v1_5 verification with SHA-256 (RFC 8017 8.2.2) over
   Limbsx. Verification only: every input is public (modulus, exponent,
   signing input, candidate signature), so the modexp need not be
   constant-time. The check compares the full re-encoded EM as one
   integer, so the 0x00 0x01 prefix, the 0xff padding, the DigestInfo,
   and the hash are all pinned at once; nothing is parsed out of the
   decrypted block, which is what makes the BB'06 lenient-parse
   forgery unrepresentable here. *)

(* DigestInfo prefix for SHA-256 (RFC 8017 9.2 notes). *)
let digest_info_prefix : string =
  "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"

let t_len : int = String.length digest_info_prefix + 32

let limbs_of_be_string (s : string) : int list =
  Limbsx.limbs_of_be_bytes (Limbsx.string_to_ints s)

(* EMSA-PKCS1-v1_5 encoding of a 32-byte hash at modulus length k:
   0x00 0x01 PS 0x00 DigestInfo hash, PS all 0xff. None when k cannot
   hold the mandatory eight padding bytes (RFC 8017 9.2 step 3). *)
let encode_em ~(k : int) (hash : string) : string option =
  let ps = k - t_len - 3 in
  if ps < 8 then None
  else
    Some
      ("\x00\x01" ^ String.make ps '\xff' ^ "\x00" ^ digest_info_prefix
     ^ hash)

(* Order of checks: signature byte length must equal the modulus length
   k, the signature representative must be below the modulus (RFC 8017
   8.2.2 step 1), then s^e mod n must equal the expected EM. *)
let verify ~(n : string) ~(e : string) ~(input : string)
    ~(signature : string) : bool =
  let k = String.length n in
  let nl = limbs_of_be_string n in
  let sl = limbs_of_be_string signature in
  match () with
  | () when not (Int.equal (String.length signature) k) -> false
  | () when Limbsx.cmp sl nl >= 0 -> false
  | () ->
    Option.fold ~none:false
      ~some:(fun em ->
        Option.fold ~none:false
          ~some:(fun m ->
            Int.equal (Limbsx.cmp m (limbs_of_be_string em)) 0)
          (Limbsx.mod_pow nl sl (limbs_of_be_string e)))
      (encode_em ~k (Sha2.Sha256.digest input))
