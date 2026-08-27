(* Time is seconds since the Unix epoch, supplied by the caller. The
   library never reads a clock, so verification is deterministic. *)

type t = int

let of_epoch_seconds (n : int) : (t, Errx.t) result =
  if n < 0 then Error (Errx.Time_invalid "seconds are negative") else Ok n

let seconds (t : t) : int = t

module Skew = struct
  (* Allowed clock skew, bounded so a config typo cannot quietly turn
     expiry checks off. *)
  type t = int

  let max_seconds : int = 600

  let of_seconds (n : int) : (t, Errx.t) result =
    if n < 0 || n > max_seconds then
      Error (Errx.Time_invalid "skew outside [0, 600] seconds")
    else Ok n

  let zero : t = 0
  let seconds (s : t) : int = s
end
