# JSignPKCS11 Security Provider

This project is a fork of the `SunPKCS11` provider from OpenJDK 21
(jdk21u, `jdk-21.0.13-ga`), repackaged as `com.github.kwart.jsign.pkcs11`.
See [UPSTREAM.md](UPSTREAM.md) for the fork base and the differences.

The most significant change is the support of the `CKU_CONTEXT_SPECIFIC` login,
which keys with `CKA_ALWAYS_AUTHENTICATE=true` require before each signature
(e.g. qualified signature keys on eID cards).

The original `SunPKCS11` implementation only supports the keystore password - PIN
(second parameter in `java.security.KeyStore.load(InputStream, char[])`).

Such keys also require the key password - QPIN
(second parameter in `java.security.KeyStore.getKey(String, char[])`).

This provider calls the PKCS#11 login with the QPIN right after the signature
operation is initialized (`C_SignInit`):

```
PKCS11.C_Login(sessionId, CKU_CONTEXT_SPECIFIC, qpin);
```

## Requirements

Java 21 or newer.

The provider uses the JDK's native PKCS#11 wrapper (`sun.security.pkcs11.wrapper`
in the `jdk.crypto.cryptoki` module), so the JVM has to export it:

```
--add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED
```

No other JDK internals are used (`jdeps --jdk-internals` lists only this package).
In a custom runtime image (`jlink`, `jpackage`), include the `jdk.crypto.cryptoki` module.

## Usage

If you are Maven user, just add dependency on the latest JSignPKCS11 version

```xml
<dependency>
    <groupId>com.github.kwart.jsign</groupId>
    <artifactId>jsign-pkcs11</artifactId>
    <version>${jsign.pkcs11.version}</version>
</dependency>
```

Create the provider with the path to a `SunPKCS11` configuration file (or the
configuration itself prefixed with `--`), same as `Provider.configure(String)`:

```java
Provider provider = new JSignPKCS11("/path/to/pkcs11.cfg");
// or: new JSignPKCS11().configure("/path/to/pkcs11.cfg");

KeyStore ks = KeyStore.getInstance("JSIGNPKCS11", provider);
ks.load(null, pin);
PrivateKey key = (PrivateKey) ks.getKey(alias, qpin);

Signature signature = Signature.getInstance("SHA256withRSA", provider);
signature.initSign(key);
```

The provider name is `JSignPKCS11-<name>` and the KeyStore type `JSIGNPKCS11`
(`SunPKCS11` uses `SunPKCS11-<name>` and `PKCS11`), so both can be registered at the same time.

### Configuration

The configuration file format is the one of
[SunPKCS11](https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html),
with one additional option:

```
# When to do the CKU_CONTEXT_SPECIFIC login before signing:
#   auto   - for keys with CKA_ALWAYS_AUTHENTICATE=true (default)
#   always - also for keys which don't report the attribute; login errors are
#            ignored unless the key requires the login (the behavior of 1.1.0)
#   never  - never
contextSpecificLogin = auto
```

Debug output: `-Djava.security.debug=sunpkcs11,pkcs11keystore`.

## Differences from SunPKCS11

* **NSS modes are not supported.** The `Secmod` class depends on JDK native code
  which is bound to the `sun.security.pkcs11` package.
* Services which need JDK private classes are not provided: the TLS key
  generators (`SunTls*`), PBE ciphers, MACs and secret key factories, and the
  `AlgorithmParameters` (the JDK providers supply them).
* Direct `ByteBuffer`s are copied to byte arrays.

## Testing

The tests use [SoftHSM2](https://github.com/softhsm/SoftHSMv2) (`apt install softhsm2`).
Without it, the token tests are skipped; `-Dsofthsm.required=true` (used in CI) makes them fail instead.

```
mvn verify -Dsofthsm.required=true
```
