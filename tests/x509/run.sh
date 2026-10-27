#!/bin/sh
# Compares test_x509 against `openssl x509`, then fuzzes it.
# Usage: run.sh test_x509 [fuzz-iterations-per-file]
# ctest runs it; a build with TLS_SANITIZE=address,undefined fuzzes under
# the sanitizers.
bin=$(realpath "$1")
cd "$(dirname "$0")"
iters=${2:-6000}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
[ -d gen ] || ./gen.sh >/dev/null 2>&1

# $OPENSSL: the OpenSSL 3 CLI (OpenBSD's openssl is LibreSSL's).
openssl() { command "${OPENSSL:-openssl}" "$@"; }

expect() {
    openssl x509 -in "$1" -inform "$2" -noout -nameopt RFC2253,-esc_msb \
	-subject -issuer -startdate -enddate -serial
    openssl x509 -in "$1" -inform "$2" -noout -fingerprint -sha1 | sed 's/.*=/sha1=/; s/://g'
    openssl x509 -in "$1" -inform "$2" -noout -fingerprint -sha256 | sed 's/.*=/sha256=/; s/://g'
    openssl x509 -in "$1" -inform "$2" -noout -text -certopt no_sigdump | awk '
	/Signature Algorithm:/ && !sig { sig = $NF }
	/Public Key Algorithm:/ { key = $NF }
	/Public-Key: \(/ { b = $0; sub(/.*\(/, "", b); sub(/ bit.*/, "", b) }
	/ED25519 Public-Key/ { b = 256 } /ED448 Public-Key/ { b = 456 }
	/X509v3 Subject Alternative Name:/ { getline; sub(/^ +/, ""); san = $0 }
	/X509v3 Subject Key Identifier:/ { getline; gsub(/[ :]/, ""); ski = $0 }
	/X509v3 Authority Key Identifier:/ { getline; sub(/^ +(keyid:)?/, "");
	    if ($0 ~ /^[0-9A-F:]+$/) { gsub(/:/, ""); aki = $0 } }
	/CA:TRUE/ { ca = "TRUE" }
	END {
	    print "sigalg=" sig; print "keyalg=" key
	    if (b) print "bits=" b
	    if (san != "") print "san=" san
	    if (ski != "") print "ski=" ski
	    if (aki != "") print "aki=" aki
	}'
    o=$(openssl x509 -in "$1" -inform "$2" -noout -ocsp_uri | tr '\n' ' ' | sed 's/ $//')
    [ -n "$o" ] && echo "ocsp=$o"
    openssl x509 -in "$1" -inform "$2" -noout -text | grep -q 'CA:TRUE' \
	&& echo ca=TRUE || echo ca=FALSE
    printf 'pem='; openssl x509 -in "$1" -inform "$2"
}

files="../certs/*-cert.pem ../certs/*.der real/*.pem gen/*.pem odd/*.der"
[ "$SYSCERTS" = 0 ] || files="$files /etc/ssl/certs/*.pem"
pass=0 fail=0
for f in $files; do
    [ -f "$f" ] || continue
    case $f in *.der) form=DER ;; *) form=PEM ;; esac
    expect "$f" $form > "$tmp/exp" 2>/dev/null || continue
    "$bin" compat "$f" > "$tmp/got"
    for x in exp got; do	# Windows programs write CRLF, MSYS tools LF
	tr -d '\r' < "$tmp/$x" > "$tmp/lf" && mv "$tmp/lf" "$tmp/$x"
    done
    if cmp -s "$tmp/exp" "$tmp/got"; then
	pass=$((pass + 1))
    else
	fail=$((fail + 1))
	echo "MISMATCH $f"; diff "$tmp/exp" "$tmp/got" | head -10
    fi
done
echo "compare: $pass passed, $fail failed"

# Non-certificates must be rejected.
for f in ../certs/*-key.pem ../certs/*.der; do
    case $f in *cert*) continue ;; esac
    "$bin" dump "$f" | grep -q 'cannot parse certificate' \
	|| { echo "ACCEPTED non-certificate $f"; fail=$((fail + 1)); }
done

"$bin" fuzz "$iters" ../certs/*-cert.pem real/*.pem gen/*.pem odd/*.der || fail=$((fail + 1))
[ $fail -eq 0 ]
