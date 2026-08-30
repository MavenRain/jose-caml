#!/usr/bin/env bash
# Gate ladder: build (0 warnings) + every test suite + compile-fail
# harness + python3 differential over the embedded vectors.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

dune build --root "$here" @all

for t in test_codec test_hmac test_jwt test_jwk test_limbs test_rsa test_p256 test_correspondence; do
  if out="$("$here/_build/default/test/$t.exe")"; then
    echo "$t: $out"
  else
    echo "$t: $out"; echo "gate: $t failed"; exit 1
  fi
  case "$out" in
    *FAIL*) echo "gate: $t failed"; exit 1 ;;
  esac
done

if out="$("$here/_build/default/model/check.exe")"; then
  echo "$out"
else
  echo "$out"; echo "gate: model check failed"; exit 1
fi
case "$out" in
  *FAIL*) echo "gate: model check failed"; exit 1 ;;
esac

"$here/harness/compile_fail.sh"
python3 "$here/harness/diff_rfc.py"
echo "gates: all green"
