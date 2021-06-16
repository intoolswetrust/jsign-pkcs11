# JSignPKCS11 Security Provider

This project is a fork of `SunPKCS11` provider from OpenJDK 8.

It includes a small change in digital signing - the `CKU_CONTEXT_SPECIFIC`-typed login is called before signing.

The NSS modes are not supported!
