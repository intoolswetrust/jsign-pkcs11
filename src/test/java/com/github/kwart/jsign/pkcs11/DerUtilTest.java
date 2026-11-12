package com.github.kwart.jsign.pkcs11;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class DerUtilTest {

    // r||s <-> DER must round trip with the JDK's own ECDSA signatures (incl. long form lengths for P-521)
    @ParameterizedTest
    @ValueSource(strings = { "secp256r1", "secp384r1", "secp521r1" })
    void ecdsaSignaturesFromJdk(String curve) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(curve));
        PrivateKey key = kpg.generateKeyPair().getPrivate();
        for (int i = 0; i < 20; i++) {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(key);
            s.update(new byte[] { (byte) i });
            byte[] der = s.sign();
            BigInteger[] rs = DerUtil.decodeIntegerPair(der);
            assertArrayEquals(der, DerUtil.encode(DerUtil.TAG_SEQUENCE, DerUtil.encodeInteger(rs[0]),
                    DerUtil.encodeInteger(rs[1])));
        }
    }

    @Test
    void encoding() {
        assertEquals("020100", hex(DerUtil.encodeInteger(BigInteger.ZERO)));
        assertEquals("02020080", hex(DerUtil.encodeInteger(BigInteger.valueOf(128))));
        assertEquals("0603550403", hex(DerUtil.encodeOid("2.5.4.3")));
        assertEquals("06092a864886f70d010101", hex(DerUtil.encodeOid("1.2.840.113549.1.1.1")));
        byte[] big = new byte[300];
        new SecureRandom().nextBytes(big);
        byte[] enc = DerUtil.encode(DerUtil.TAG_OCTET_STRING, big);
        assertEquals("0482012c", hex(enc).substring(0, 8));
    }

    @Test
    void decodingIsStrict() {
        // valid: SEQUENCE { INTEGER 1, INTEGER 2 }
        byte[] ok = HexFormat.of().parseHex("3006020101020102");
        assertDoesNotThrow(ok);
        // trailing data
        assertInvalid("300602010102010200");
        // trailing data inside the sequence
        assertInvalid("3009020101020102020103");
        // redundant leading zero
        assertInvalid("300702020001020102");
        // non-minimal length
        assertInvalid("30810602010102010200");
        // truncated
        assertInvalid("30060201010201");
        // wrong tag
        assertInvalid("3106020101020102");
    }

    @Test
    void octetString() throws IOException {
        assertArrayEquals(new byte[] { 4, 1, 2 }, DerUtil.decode(DerUtil.TAG_OCTET_STRING,
                HexFormat.of().parseHex("0403040102")));
        assertThrows(IOException.class, () -> DerUtil.decode(DerUtil.TAG_OCTET_STRING, new byte[] { 4, 3, 1 }));
        assertThrows(IOException.class, () -> DerUtil.decode(DerUtil.TAG_OCTET_STRING, new byte[] { 4, 1, 2, 3 }));
    }

    private static void assertDoesNotThrow(byte[] der) {
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> DerUtil.decodeIntegerPair(der));
    }

    private static void assertInvalid(String hex) {
        assertThrows(IOException.class, () -> DerUtil.decodeIntegerPair(HexFormat.of().parseHex(hex)), hex);
    }

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }
}
