package com.github.kwart.jsign.pkcs11;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.HexFormat;

import javax.crypto.Cipher;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

/**
 * DigestInfo encoding for the raw RSA signature path.
 */
class DigestAlgorithmsTest {

    static KeyPair rsa;

    @BeforeAll
    static void setup() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsa = kpg.generateKeyPair();
    }

    // DigestInfo prefixes from RFC 8017, section 9.2, note 1
    @ParameterizedTest(name = "{0}")
    @CsvSource({ "MD5, 3020300c06082a864886f70d020505000410",
            "SHA-1, 3021300906052b0e03021a05000414",
            "SHA-224, 302d300d06096086480165030402040500041c",
            "SHA-256, 3031300d060960864801650304020105000420",
            "SHA-384, 3041300d060960864801650304020205000430",
            "SHA-512, 3051300d060960864801650304020305000440",
            "SHA-512/224, 302d300d06096086480165030402050500041c",
            "SHA-512/256, 3031300d060960864801650304020605000420" })
    void rfc8017Prefix(String digest, String prefix) throws Exception {
        byte[] hash = MessageDigest.getInstance(digest).digest(new byte[] { 1, 2, 3 });
        byte[] expected = HexFormat.of().parseHex(prefix + HexFormat.of().formatHex(hash));
        assertArrayEquals(expected, DigestAlgorithms.encodeDigestInfo(digest, hash));
    }

    // the encoding has to be the same as the JDK's RSAUtil.encodeSignature() (deterministic signatures)
    @ParameterizedTest(name = "{0}")
    @CsvSource({ "MD5withRSA", "SHA1withRSA", "SHA224withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA",
            "SHA512/224withRSA", "SHA512/256withRSA", "SHA3-224withRSA", "SHA3-256withRSA", "SHA3-384withRSA",
            "SHA3-512withRSA" })
    void sameAsJdk(String algorithm) throws Exception {
        byte[] data = "data".getBytes();
        String digest = DigestAlgorithms.fromSignatureAlgorithm(algorithm);
        Signature jdk = Signature.getInstance(algorithm, "SunRsaSign");
        jdk.initSign(rsa.getPrivate());
        jdk.update(data);

        // RSA encryption with the private key uses PKCS#1 block type 1, same as the raw signature path
        Cipher raw = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
        raw.init(Cipher.ENCRYPT_MODE, rsa.getPrivate());
        byte[] digestInfo = DigestAlgorithms.encodeDigestInfo(digest, MessageDigest.getInstance(digest).digest(data));
        assertArrayEquals(jdk.sign(), raw.doFinal(digestInfo));
    }

    @Test
    void names() throws Exception {
        assertEquals("SHA-256", DigestAlgorithms.toStdName("sha256"));
        assertEquals("SHA-1", DigestAlgorithms.toStdName("SHA"));
        assertEquals("SHA-512/224", DigestAlgorithms.toStdName("SHA512/224"));
        assertEquals("SHA3-256", DigestAlgorithms.toStdName("2.16.840.1.101.3.4.2.8"));
        assertNull(DigestAlgorithms.toStdName("SHAKE128"));
        assertEquals("MD2", DigestAlgorithms.fromSignatureAlgorithm("MD2withRSA"));
        assertEquals("SHA-384", DigestAlgorithms.fromSignatureAlgorithm("SHA384withECDSAinP1363Format"));
        assertThrows(NoSuchAlgorithmException.class, () -> DigestAlgorithms.fromSignatureAlgorithm("NONEwithRSA"));
        assertThrows(NoSuchAlgorithmException.class, () -> DigestAlgorithms.fromSignatureAlgorithm("RSASSA-PSS"));
    }
}
