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

**The NSS modes from SunPKCS11 provider are not supported!**
