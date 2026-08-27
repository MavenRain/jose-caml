#!/usr/bin/env bash
# Mutation confirmation: each mutant flips one guard; the suites must go
# red (behaviorally: the mutant must COMPILE and then fail tests --
# KILLED(compile) is vacuous). Files are restored from backups after
# each mutant, and the ladder must end green.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"

tests_green() {
  dune build --root "$root" @all >/dev/null 2>&1 || return 2
  for t in test_codec test_hmac test_jwt test_limbs; do
    case "$("$root/_build/default/test/$t.exe" 2>/dev/null)" in
      *FAIL*) return 1 ;;
    esac
  done
  return 0
}

fail=0
mutant() {
  name="$1"; file="$2"; pat="$3"; rep="$4"
  cp "$root/$file" "$root/$file.bak"
  sd -s "$pat" "$rep" "$root/$file"
  if cmp -s "$root/$file" "$root/$file.bak"; then
    echo "mutate: $name PATTERN DID NOT APPLY"; fail=1
  else
    tests_green; rc=$?
    case "$rc" in
      2) echo "mutate: $name VACUOUS (does not compile)"; fail=1 ;;
      0) echo "mutate: $name SURVIVED"; fail=1 ;;
      *) echo "mutate: $name killed" ;;
    esac
  fi
  mv "$root/$file.bak" "$root/$file"
}

mutant b64-trailing-bits lib/b64x.ml \
  "Int.equal (b land 15) 0" "Int.equal (b land 0) 0"
mutant hmac-opad lib/hmacx.ml \
  "xor_with 0x5c k" "xor_with 0x5b k"
mutant exp-boundary lib/jwtx.ml \
  "if nowi < exp + skew then Ok ()" "if nowi <= exp + skew then Ok ()"
mutant aud-check lib/jwtx.ml \
  "if List.exists (String.equal (Expx.aud expect)) p.Clx.aud then Ok ()" \
  "if true then Ok ()"
mutant jwk-header lib/headx.ml \
  "\"jwk\"; " ""
mutant alg-none lib/algx.ml \
  "when String.equal s \"HS256\" -> Ok HS256" \
  "when String.equal s \"HS256\" || String.equal s \"none\" -> Ok HS256"

mutant limbs-sub-borrow lib/limbsx.ml \
  "((s + 0x10000) :: acc, 1)" "((s + 0x10000) :: acc, 0)"
mutant limbs-bit-mask lib/limbsx.ml \
  "(limb lsr i) land 1" "(limb lsr i) land 0"
mutant limbs-square-step lib/limbsx.ml \
  "red (mul_limbs sq sq)" "red (mul_limbs sq acc)"
mutant limbs-le-shift lib/limbsx.ml \
  "(b0 lor (b1 lsl 8))" "(b0 lor (b1 lsl 7))"

if tests_green; then
  echo "mutate: ladder restored green"
else
  echo "mutate: LADDER NOT GREEN AFTER RESTORE"; fail=1
fi
exit "$fail"
