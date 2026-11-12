package com.github.kwart.jsign.pkcs11;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * RSA PKCS#1 v1.5 and ECDSA signatures on the hash-and-sign (combined) and on the raw path. The signatures are
 * verified with the JDK providers.
 */
class SignatureTest {

    static final byte[] DATA = "The quick brown fox jumps over the lazy dog".repeat(100)
            .getBytes(StandardCharsets.UTF_8);

    static SoftHsm hsm;
    static JSignPKCS11 combined;
    static JSignPKCS11 raw;
    static KeyStore combinedKs;
    static KeyStore rawKs;

    @BeforeAll
    static void setup() throws Exception {
        hsm = SoftHsm.get();
        combined = hsm.combinedProvider();
        raw = hsm.rawProvider();
        combinedKs = SoftHsm.keyStore(combined);
        rawKs = SoftHsm.keyStore(raw);
    }

    static Stream<Arguments> rsa() {
        return Stream.of("SHA1withRSA", "SHA224withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA")
                .flatMap(alg -> Stream.of(Arguments.of(alg, true), Arguments.of(alg, false)));
    }

    @ParameterizedTest(name = "{0} combined={1}")
    @MethodSource("rsa")
    void rsaPkcs1(String algorithm, boolean useCombined) throws Exception {
        Provider p = useCombined ? combined : raw;
        String mechanism = mechanism(p, algorithm);
        if (useCombined) {
            assertTrue(mechanism.contains("_RSA_PKCS"), mechanism);
        } else {
            assertTrue(mechanism.endsWith("(CKM_RSA_PKCS)"), mechanism);
        }
        PrivateKey key = tokenKey(useCombined ? combinedKs : rawKs, SoftHsm.RSA);
        byte[] signature = sign(p, algorithm, key, DATA);

        assertTrue(verify(algorithm, hsm.certificate(SoftHsm.RSA).getPublicKey(), DATA, signature));
        // PKCS#1 v1.5 is deterministic: the DigestInfo encoding has to match the JDK's
        Signature sw = Signature.getInstance(algorithm, "SunRsaSign");
        sw.initSign(hsm.softwareKey(SoftHsm.RSA));
        sw.update(DATA);
        assertArrayEquals(sw.sign(), signature);
    }

    @Test
    void rsaSha3OnRawPath() throws Exception {
        // the token has no SHA3 hash-and-sign mechanisms, the provider hashes in Java
        PrivateKey key = tokenKey(rawKs, SoftHsm.RSA);
        byte[] signature = sign(raw, "SHA3-256withRSA", key, DATA);
        Signature sw = Signature.getInstance("SHA3-256withRSA", "SunRsaSign");
        sw.initSign(hsm.softwareKey(SoftHsm.RSA));
        sw.update(DATA);
        assertArrayEquals(sw.sign(), signature);
    }

    static Stream<Arguments> ecdsa() {
        return Stream.of(SoftHsm.EC256, SoftHsm.EC384).flatMap(alias -> Stream
                .of("SHA1withECDSA", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA",
                        "SHA256withECDSAinP1363Format")
                .flatMap(alg -> Stream.of(Arguments.of(alias, alg, true), Arguments.of(alias, alg, false))));
    }

    // SoftHSM2 2.6 has no CKM_ECDSA_SHA* mechanisms, so on it both variants sign with CKM_ECDSA over a digest
    // computed in Java (the path which failed with NoSuchMethodError in jsign-pkcs11 1.1.0 on Java 21)
    @ParameterizedTest(name = "{0} {1} combined={2}")
    @MethodSource("ecdsa")
    void ecdsa(String alias, String algorithm, boolean useCombined) throws Exception {
        Provider p = useCombined ? combined : raw;
        if (!useCombined) {
            String mechanism = mechanism(p, algorithm);
            assertTrue(mechanism.endsWith("(CKM_ECDSA)"), mechanism);
        }
        PrivateKey key = tokenKey(useCombined ? combinedKs : rawKs, alias);
        PublicKey publicKey = hsm.certificate(alias).getPublicKey();
        byte[] signature = sign(p, algorithm, key, DATA);
        assertTrue(verify(algorithm, publicKey, DATA, signature));

        byte[] other = DATA.clone();
        other[0] ^= 1;
        assertFalse(verify(algorithm, publicKey, other, signature));
    }

    @Test
    void ecdsaVerifiedByProvider() throws Exception {
        // DER -> r||s conversion on the verify side
        Signature sw = Signature.getInstance("SHA256withECDSA", "SunEC");
        sw.initSign(hsm.softwareKey(SoftHsm.EC256));
        sw.update(DATA);
        byte[] signature = sw.sign();
        for (Provider p : new Provider[] { combined, raw }) {
            Signature v = Signature.getInstance("SHA256withECDSA", p);
            v.initVerify(hsm.certificate(SoftHsm.EC256).getPublicKey());
            v.update(DATA);
            assertTrue(v.verify(signature), p.getName());
        }
    }

    @Test
    void updateVariants() throws Exception {
        // byte, array and heap/direct ByteBuffer updates on the multi-part (C_SignUpdate) path
        for (String alg : new String[] { "SHA256withRSA", "SHA256withECDSA" }) {
            String alias = alg.endsWith("RSA") ? SoftHsm.RSA : SoftHsm.EC256;
            Signature s = Signature.getInstance(alg, combined);
            s.initSign(tokenKey(combinedKs, alias));
            s.update(DATA[0]);
            s.update(DATA, 1, 99);
            s.update(ByteBuffer.wrap(DATA, 100, 400));
            ByteBuffer direct = ByteBuffer.allocateDirect(DATA.length - 500);
            direct.put(DATA, 500, DATA.length - 500).flip();
            s.update(direct);
            assertTrue(verify(alg, hsm.certificate(alias).getPublicKey(), DATA, s.sign()), alg);
        }
    }

    @Test
    void repeatedSignaturesWithOneInstance() throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA", raw);
        s.initSign(tokenKey(rawKs, SoftHsm.RSA));
        for (int i = 0; i < 3; i++) {
            s.update(DATA);
            assertTrue(verify("SHA256withRSA", hsm.certificate(SoftHsm.RSA).getPublicKey(), DATA, s.sign()));
        }
    }

    static String mechanism(Provider p, String algorithm) {
        Provider.Service service = p.getService("Signature", algorithm);
        assertTrue(service != null, algorithm + " not supported by " + p.getName());
        return service.toString();
    }

    static PrivateKey tokenKey(KeyStore ks, String alias) throws Exception {
        Key key = ks.getKey(alias, SoftHsm.PIN);
        assertTrue(key instanceof P11Key, "Expected a token key: " + key);
        return (PrivateKey) key;
    }

    static byte[] sign(Provider p, String algorithm, PrivateKey key, byte[] data) throws Exception {
        Signature s = Signature.getInstance(algorithm, p);
        s.initSign(key);
        s.update(data);
        return s.sign();
    }

    /**
     * Verifies with the default JDK providers; JSignPKCS11 is never registered in the tests.
     */
    static boolean verify(String algorithm, PublicKey key, byte[] data, byte[] signature) throws Exception {
        Signature v = Signature.getInstance(algorithm);
        v.initVerify(key);
        assertFalse(v.getProvider() instanceof JSignPKCS11);
        v.update(data);
        return v.verify(signature);
    }
}
