# JSignPKCS11 Security Provider

This project is a fork of `SunPKCS11` provider from OpenJDK 8.

The most significant change is the basic support of the `CKU_CONTEXT_SPECIFIC`-typed login before signing.

The original `SunPKCS11` implementation only supports the keystore password - PIN
(second parameter in `java.security.KeyStore.load(InputStream, char[])`).

Some newer hardware tokens also require the key password - QPIN
(second parameter in `java.security.KeyStore.getKey(String, char[])`).

This provider implementation calls PKCS11 login function with QPIN before signing (generating signature bytes in
`com.github.kwart.jsign.pkcs11.P11Signature.engineSign()`).

```
PKCS11.C_Login(sessionId, CKU_CONTEXT_SPECIFIC, qpin);
```

### Other changes

* Class `P11KeyStore` allows overriding the EC `keyLength` (from decoded `CKA_EC_PARAMS` attribute) by specifying
 the value as a system property named `jsign-pkcs11.keystore.override.keylength`;

## Usage

If you are Maven user, just add dependency on the latest JSignPKCS11 version

```xml
<dependency>
    <groupId>com.github.kwart.jsign</groupId>
    <artifactId>jsign-pkcs11</artifactId>
    <version>${jsign.pkcs11.version}</version>
</dependency>
```

And replace original SunPKCS11 usages by proper JSignPKCS11 class.

```diff
- sun.security.pkcs11.SunPKCS11
+ com.github.kwart.jsign.pkcs11.JSignPKCS11
```

## Warning - NSS not supported
**The NSS modes from SunPKCS11 provider are not supported!**
