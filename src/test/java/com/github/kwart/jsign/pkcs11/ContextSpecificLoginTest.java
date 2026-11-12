package com.github.kwart.jsign.pkcs11;

import static com.github.kwart.jsign.pkcs11.SignatureTest.DATA;
import static com.github.kwart.jsign.pkcs11.SignatureTest.verify;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import sun.security.pkcs11.wrapper.PKCS11Exception;

/**
 * Keys with CKA_ALWAYS_AUTHENTICATE=true need the CKU_CONTEXT_SPECIFIC login before each signature. SoftHSM2 checks
 * the user PIN in that login, so the key password (QPIN) is the token PIN here.
 */
class ContextSpecificLoginTest {

    static SoftHsm hsm;
    static JSignPKCS11 combined;
    static JSignPKCS11 raw;

    @BeforeAll
    static void setup() throws Exception {
        hsm = SoftHsm.get();
        combined = hsm.combinedProvider();
        raw = hsm.rawProvider();
    }

    @ParameterizedTest(name = "{0} {1} combined={2}")
    @CsvSource({ "rsa-always-auth, SHA256withRSA, true", "rsa-always-auth, SHA256withRSA, false",
            "ec256-always-auth, SHA256withECDSA, true", "ec256-always-auth, SHA256withECDSA, false" })
    void signWithKeyPassword(String alias, String algorithm, boolean useCombined) throws Exception {
        JSignPKCS11 p = useCombined ? combined : raw;
        PrivateKey key = (PrivateKey) SoftHsm.keyStore(p).getKey(alias, SoftHsm.PIN);
        assertTrue(isAlwaysAuthenticate(p, key));

        Signature s = Signature.getInstance(algorithm, p);
        s.initSign(key);
        // each signature needs its own login
        for (int i = 0; i < 2; i++) {
            s.update(DATA);
            assertTrue(verify(algorithm, hsm.certificate(alias).getPublicKey(), DATA, s.sign()));
        }
    }

    @Test
    void keyEntryPassword() throws Exception {
        KeyStore ks = SoftHsm.keyStore(combined);
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) ks.getEntry(SoftHsm.RSA_ALWAYS_AUTH,
                new KeyStore.PasswordProtection(SoftHsm.PIN));
        Signature s = Signature.getInstance("SHA256withRSA", combined);
        s.initSign(entry.getPrivateKey());
        s.update(DATA);
        assertTrue(verify("SHA256withRSA", entry.getCertificate().getPublicKey(), DATA, s.sign()));
    }

    @Test
    void pss() throws Exception {
        Provider.Service service = combined.getService("Signature", "RSASSA-PSS");
        Assumptions.assumeTrue(service != null, "RSASSA-PSS is not supported by the token");
        PSSParameterSpec spec = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        Signature s = Signature.getInstance("RSASSA-PSS", combined);
        s.initSign((PrivateKey) SoftHsm.keyStore(combined).getKey(SoftHsm.RSA_ALWAYS_AUTH, SoftHsm.PIN));
        s.setParameter(spec);
        s.update(DATA);
        byte[] signature = s.sign();
        Signature v = Signature.getInstance("RSASSA-PSS", "SunRsaSign");
        v.initVerify(hsm.certificate(SoftHsm.RSA_ALWAYS_AUTH).getPublicKey());
        v.setParameter(spec);
        v.update(DATA);
        assertTrue(v.verify(signature));
    }

    @Test
    void wrongKeyPassword() throws Exception {
        PrivateKey key = (PrivateKey) SoftHsm.keyStore(raw).getKey(SoftHsm.RSA_ALWAYS_AUTH, "0000".toCharArray());
        Signature s = Signature.getInstance("SHA256withRSA", raw);
        ProviderException e = assertThrows(ProviderException.class, () -> s.initSign(key));
        assertTrue(e.getMessage().contains("incorrect key password"), e.getMessage());
        assertTrue(e.getCause() instanceof PKCS11Exception, String.valueOf(e.getCause()));

        // the killed session doesn't break later operations
        signWithKeyPassword(SoftHsm.RSA_ALWAYS_AUTH, "SHA256withRSA", false);
    }

    @Test
    void missingKeyPassword() throws Exception {
        PrivateKey key = (PrivateKey) SoftHsm.keyStore(raw).getKey(SoftHsm.RSA_ALWAYS_AUTH, null);
        Signature s = Signature.getInstance("SHA256withRSA", raw);
        ProviderException e = assertThrows(ProviderException.class, () -> s.initSign(key));
        assertTrue(e.getMessage().contains("no key password"), e.getMessage());
    }

    @Test
    void keysWithoutAlwaysAuthenticate() throws Exception {
        // no key password needed and none of the contextSpecificLogin modes breaks signing
        for (String mode : new String[] { "auto", "always", "never" }) {
            JSignPKCS11 p = hsm.provider("mode-" + mode, "contextSpecificLogin = " + mode + "\n");
            KeyStore ks = SoftHsm.keyStore(p);
            for (char[] password : new char[][] { null, SoftHsm.PIN, "0000".toCharArray() }) {
                PrivateKey key = (PrivateKey) ks.getKey(SoftHsm.RSA, password);
                assertFalse(isAlwaysAuthenticate(p, key));
                Signature s = Signature.getInstance("SHA256withRSA", p);
                s.initSign(key);
                s.update(DATA);
                assertTrue(verify("SHA256withRSA", hsm.certificate(SoftHsm.RSA).getPublicKey(), DATA, s.sign()),
                        mode);
            }
        }
    }

    @Test
    void neverModeSkipsLogin() throws Exception {
        JSignPKCS11 p = hsm.provider("never", "contextSpecificLogin = never\n");
        PrivateKey key = (PrivateKey) SoftHsm.keyStore(p).getKey(SoftHsm.RSA_ALWAYS_AUTH, SoftHsm.PIN);
        Signature s = Signature.getInstance("SHA256withRSA", p);
        s.initSign(key);
        // the token refuses C_SignUpdate/C_Sign without the login
        Exception e = assertThrows(Exception.class, () -> {
            s.update(DATA);
            s.sign();
        });
        assertTrue(String.valueOf(e.getCause()).contains("CKR_USER_NOT_LOGGED_IN"), String.valueOf(e.getCause()));
    }

    static boolean isAlwaysAuthenticate(JSignPKCS11 p, PrivateKey key) throws Exception {
        P11Key p11Key = (P11Key) key;
        Session session = p.getToken().getOpSession();
        try {
            return p11Key.isAlwaysAuthenticate(session, p11Key.getKeyID());
        } finally {
            p11Key.releaseKeyID();
            p.getToken().releaseSession(session);
        }
    }

    @Test
    void sunPkcs11CannotSign() throws Exception {
        // negative control: the JDK provider doesn't do the context specific login
        Provider sun = hsm.sunPkcs11();
        KeyStore ks = KeyStore.getInstance("PKCS11", sun);
        ks.load(null, SoftHsm.PIN);
        PrivateKey key = (PrivateKey) ks.getKey(SoftHsm.RSA_ALWAYS_AUTH, SoftHsm.PIN);
        Signature s = Signature.getInstance("SHA256withRSA", sun);
        assertThrows(Exception.class, () -> {
            s.initSign(key);
            s.update(DATA);
            s.sign();
        });
    }
}
