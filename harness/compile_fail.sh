#!/usr/bin/env bash
# M8 compile-fail harness. Each bad_*.ml encodes one misuse; the type
# checker must reject it WITH the expected error text (so a snippet
# failing for an unrelated reason, e.g. a typo, is caught). The control
# snippet must compile, so the failures are not vacuous.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
objs="$root/_build/default/lib/.jose.objs/byte"

if [ ! -d "$objs" ]; then
  echo "compile_fail: build the library first (dune build)"; exit 1
fi

out="$here/compile_fail/_out"
rm -rf "$out"; mkdir -p "$out"

expected() {
  case "$1" in
    bad_unverified_read) echo "unverified" ;;
    bad_expect_no_aud) echo "aud" ;;
    bad_key_from_string) echo "Key.t" ;;
    bad_forge_verified) echo "verified" ;;
    bad_admit_external) echo "Unbound value" ;;
    bad_jwk_cross_alg) echo "hs256" ;;
    *) echo "UNKNOWN-SNIPPET" ;;
  esac
}

fail=0
for f in "$here"/compile_fail/bad_*.ml; do
  name="$(basename "$f" .ml)"
  cp "$f" "$out/$name.ml"
  if (cd "$out" && ocamlc -I "$objs" -c "$name.ml" >"$name.err" 2>&1); then
    echo "compile_fail: $name COMPILED (misuse is representable)"; fail=1
  elif ! rg -q "$(expected "$name")" "$out/$name.err"; then
    echo "compile_fail: $name failed for the wrong reason:"
    cat "$out/$name.err"; fail=1
  else
    echo "compile_fail: $name rejected as expected"
  fi
done

cp "$here/compile_fail/control_ok.ml" "$out/control_ok.ml"
if (cd "$out" && ocamlc -I "$objs" -c control_ok.ml >control_ok.err 2>&1); then
  echo "compile_fail: control compiles (harness is not vacuous)"
else
  echo "compile_fail: CONTROL FAILED TO COMPILE (harness vacuous):"
  cat "$out/control_ok.err"; fail=1
fi

exit "$fail"
