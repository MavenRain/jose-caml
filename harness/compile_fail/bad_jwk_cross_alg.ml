(* A key of one algorithm cannot inhabit another algorithm's Jwk arm:
   the constructor carries the phantom index, so a keyset entry cannot
   relabel its key. *)
let broken (k : Jose.Key.es256 Jose.Key.t) : Jose.Jwk.t = Jose.Jwk.Hs256 k
