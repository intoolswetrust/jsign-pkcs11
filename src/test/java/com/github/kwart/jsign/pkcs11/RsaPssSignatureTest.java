package com.github.kwart.jsign.pkcs11;

import static com.github.kwart.jsign.pkcs11.SignatureTest.DATA;
import static com.github.kwart.jsign.pkcs11.SignatureTest.tokenKey;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * RSASSA-PSS signatures (CKM_RSA_PKCS_PSS and CKM_SHA*_RSA_PKCS_PSS), verified with the JDK provider.
 */
class RsaPssSignatureTest {

    static SoftHsm hsm;
    static JSignPKCS11 provider;
    static KeyStore ks;

    @BeforeAll
    static void setup() throws Exception {
        hsm = SoftHsm.get();
        provider = hsm.combinedProvider();
        ks = SoftHsm.keyStore(provider);
    }

    @ParameterizedTest(name = "{0} {1}")
    @CsvSource({ "RSASSA-PSS, SHA-256", "RSASSA-PSS, SHA-384", "RSASSA-PSS, SHA-512", "SHA256withRSASSA-PSS, SHA-256",
            "SHA384withRSASSA-PSS, SHA-384", "SHA512withRSASSA-PSS, SHA-512" })
    void pss(String algorithm, String digest) throws Exception {
        Provider.Service service = provider.getService("Signature", algorithm);
        Assumptions.assumeTrue(service != null, algorithm + " is not supported by the token");
        int saltLen = Integer.parseInt(digest.substring(4)) / 8;
        PSSParameterSpec spec = new PSSParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), saltLen, 1);

        Signature s = Signature.getInstance(algorithm, provider);
        s.initSign(tokenKey(ks, SoftHsm.RSA));
        s.setParameter(spec);
        s.update(DATA);
        byte[] signature = s.sign();

        Signature v = Signature.getInstance("RSASSA-PSS", "SunRsaSign");
        v.initVerify(hsm.certificate(SoftHsm.RSA).getPublicKey());
        v.setParameter(spec);
        v.update(DATA);
        assertTrue(v.verify(signature), service.toString());
    }
}
