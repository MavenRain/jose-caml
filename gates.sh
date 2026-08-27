#!/usr/bin/env bash
# Gate ladder: build (0 warnings) + every test suite + compile-fail
# harness + python3 differential over the embedded vectors.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

dune build --root "$here" @all

for t in test_codec test_hmac test_jwt; do
  out="$("$here/_build/default/test/$t.exe")"
  echo "$t: $out"
  case "$out" in
    *FAIL*) echo "gate: $t failed"; exit 1 ;;
  esac
done

"$here/harness/compile_fail.sh"
python3 "$here/harness/diff_rfc.py"
echo "gates: all green"
