# Upstream base

| | |
|---|---|
| Base | OpenJDK [jdk21u](https://github.com/openjdk/jdk21u) tag `jdk-21.0.13-ga`, `src/jdk.crypto.cryptoki/share/classes/sun/security/pkcs11` |
| Previous base (1.x) | OpenJDK [jdk8u](https://github.com/openjdk/jdk8u) `jdk8u302-b04` (package identical in b01-b04, last change `8738609f98d1`, 8261355) |

The `sun.security.pkcs11.wrapper` package is not copied, the provider uses the
JDK's one (it's bound to the JDK's `libj2pkcs11` native library). `Secmod` is not
copied either (NSS mode, native code bound to `sun.security.pkcs11`).

## Rebasing

1. Check out the new upstream tag, e.g. a sparse clone:
   ```
   git clone --depth 1 --filter=blob:none --sparse --branch jdk-21.0.14-ga https://github.com/openjdk/jdk21u.git
   (cd jdk21u && git sparse-checkout set src/jdk.crypto.cryptoki)
   ```
2. On a branch, run `scripts/import-upstream.sh <path-to-jdk21u>` and commit the
   result as the plain upstream import.
3. Replay the jsign-pkcs11 commits made on top of the previous import
   (`git log <previous import>..`), e.g. with `git cherry-pick`.
4. If upstream registers new algorithms with aliases (`dA(...)`), regenerate
   `P11Aliases.java` with `scripts/GenerateAliases.java`.
5. `jdeps --jdk-internals target/jsign-pkcs11-*.jar` must list only
   `sun.security.pkcs11.wrapper`; `mvn verify -Dsofthsm.required=true` must pass
   on JDK 21 and on the newest JDK.

## Changes against upstream

jsign-pkcs11 features:

* Package `com.github.kwart.jsign.pkcs11`, class `JSignPKCS11`, provider name
  `JSignPKCS11-<name>`, KeyStore/SecureRandom type `JSIGNPKCS11`.
* `CKU_CONTEXT_SPECIFIC` login for keys with `CKA_ALWAYS_AUTHENTICATE`, with the key
  password from `KeyStore.getKey()`/`getEntry()` (`P11KeyStore`, `P11Key`,
  `JSignPKCS11.contextSpecificLogin`, `P11Signature`, `P11PSSSignature`), config
  option `contextSpecificLogin`.
* NSS mode rejected.
* Public `JSignPKCS11(String)` and `JSignPKCS11(InputStream)` constructors.

No JDK internals except `sun.security.pkcs11.wrapper`:

| Upstream uses | Replaced by |
|---|---|
| `sun.security.rsa.RSAUtil.encodeSignature` | `DigestAlgorithms.encodeDigestInfo` |
| `sun.security.rsa.RSAPadding` | PKCS#1 v1.5 padding in `P11Signature` |
| `sun.security.util.DerValue`, `DerInputStream`, `DerOutputStream` | `DerUtil` |
| `sun.security.util.ECUtil` | `P11ECUtil` (SunEC `AlgorithmParameters`/`KeyFactory`) |
| `sun.security.util.KnownOIDs`, `ObjectIdentifier`, `SignatureUtil` | `DigestAlgorithms` |
| `sun.security.util.SecurityProviderConstants` | `P11Aliases` (generated), constants in `P11KeyPairGenerator`/`P11KeyGenerator` |
| `sun.security.rsa.RSAKeyFactory`, `RSAPublicKeyImpl`, `RSAPrivateCrtKeyImpl` | `P11Util.checkRSAKeyLengths`, SunRsaSign `KeyFactory` |
| `sun.security.provider.DSAPublicKey`, `DSAPrivateKey`, `ParameterCache` | SUN `KeyFactory`/`KeyPairGenerator`, SunJCE `KeyPairGenerator` |
| `sun.security.util.KeyUtil` | `P11Util` |
| `sun.security.util.Debug`, `Cache`, `PropertyExpander`, `ResourcesMgr`, `SecurityConstants`, `sun.security.jca.JCAUtil`, `jdk.internal.misc.InnocuousThread` | `Debug`, `KeyCache`, `Config.expand`, `P11Util` |
| `sun.nio.ch.DirectBuffer`, `jdk.internal.access.JavaNioAccess`/`SharedSecrets` | default SPI implementations (copying) |
| `sun.security.util.Length`, `MessageDigestSpi2` | removed |
| `sun.security.internal.spec.*`, `sun.security.internal.interfaces.TlsMasterSecret`, `sun.security.util.PBEUtil`, `com.sun.crypto.provider.ChaCha20Poly1305Parameters`, `sun.security.util.ECParameters`/`GCMParameters` | services removed (TLS, PBE, AlgorithmParameters) |

Wrapper API differences between JDK versions (handled in `P11Util` and `P11SecretKeyFactory`):

* `CK_MECHANISM.freeHandle()` exists in JDK 21, removed in JDK 25.
* `PKCS11.C_GCMEncryptInitWithRetry`/`C_GCMDecryptInitWithRetry` exist since 21.0.5.
* `PKCS11Constants.PCKK_HMAC`, `PCKK_SSLMAC`, `PCKK_TLS*` removed in JDK 25.

Upstream bugs fixed here (also present in JDK 21.0.13 and 25.0.5):

* `P11AEADCipher`: after `update()`, `doFinal(input)` dropped the input unless it
  started at a non-zero offset and didn't reach the end of the array.
