#!/bin/sh
# Copies sun.security.pkcs11 from an OpenJDK source checkout into this project,
# repackaged as com.github.kwart.jsign.pkcs11 with SunPKCS11 renamed to JSignPKCS11.
# The sun.security.pkcs11.wrapper package stays in the JDK (it is bound to the
# JDK's libj2pkcs11 native library) and Secmod is skipped (NSS mode is not supported).
#
# Usage: scripts/import-upstream.sh <openjdk-checkout>
# e.g. a sparse clone of https://github.com/openjdk/jdk21u at tag jdk-21.0.13-ga
set -eu
SRC="$1/src/jdk.crypto.cryptoki/share/classes/sun/security/pkcs11"
DST="$(dirname "$0")/../src/main/java/com/github/kwart/jsign/pkcs11"
[ -d "$SRC" ] || { echo "Not an OpenJDK checkout: $SRC" >&2; exit 1; }
mkdir -p "$DST"
for f in "$SRC"/*.java; do
  b=$(basename "$f")
  [ "$b" = Secmod.java ] && continue
  [ "$b" = SunPKCS11.java ] && b=JSignPKCS11.java
  perl -pe 's/sun\.security\.pkcs11(?!\.wrapper)/com.github.kwart.jsign.pkcs11/g; s/SunPKCS11/JSignPKCS11/g' "$f" > "$DST/$b"
done
