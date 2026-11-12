package com.github.kwart.jsign.pkcs11;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Symmetric ciphers compared with SunJCE: covers the GCM init compatibility with older JDK 21 updates and the
 * ByteBuffer handling (direct buffers go through the CipherSpi defaults).
 */
class CipherTest {

    static JSignPKCS11 provider;
    static SecretKeySpec key;
    static byte[] data = new byte[1000];

    @BeforeAll
    static void setup() {
        provider = SoftHsm.get().combinedProvider();
        byte[] k = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(k);
        random.nextBytes(data);
        key = new SecretKeySpec(k, "AES");
    }

    @ParameterizedTest
    @ValueSource(booleans = { false, true })
    void aesGcm(boolean direct) throws Exception {
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        Cipher jdk = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
        jdk.init(Cipher.ENCRYPT_MODE, key, spec);
        jdk.updateAAD(new byte[] { 1, 2, 3 });
        byte[] expected = jdk.doFinal(data);

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", provider);
        enc.init(Cipher.ENCRYPT_MODE, key, spec);
        enc.updateAAD(new byte[] { 1, 2, 3 });
        assertArrayEquals(expected, doFinal(enc, data, direct));

        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", provider);
        dec.init(Cipher.DECRYPT_MODE, key, spec);
        dec.updateAAD(new byte[] { 1, 2, 3 });
        assertArrayEquals(data, doFinal(dec, expected, direct));
    }

    @org.junit.jupiter.api.Test
    void aesGcmUpdateAndDoFinalArrays() throws Exception {
        // the JDK SunPKCS11 (21.0.13, 25.0.5) drops the doFinal input after an update() here
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        Cipher jdk = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
        jdk.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] expected = jdk.doFinal(data);

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", provider);
        enc.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] first = enc.update(data, 0, 333);
        byte[] last = enc.doFinal(java.util.Arrays.copyOfRange(data, 333, data.length));
        assertArrayEquals(expected, P11Util.concat(first == null ? new byte[0] : first, last));
    }

    @ParameterizedTest
    @ValueSource(booleans = { false, true })
    void aesCbc(boolean direct) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);
        Cipher jdk = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
        jdk.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] expected = jdk.doFinal(data);

        Cipher enc = Cipher.getInstance("AES/CBC/PKCS5Padding", provider);
        enc.init(Cipher.ENCRYPT_MODE, key, iv);
        assertArrayEquals(expected, doFinal(enc, data, direct));

        Cipher dec = Cipher.getInstance("AES/CBC/PKCS5Padding", provider);
        dec.init(Cipher.DECRYPT_MODE, key, iv);
        assertArrayEquals(data, doFinal(dec, expected, direct));
    }

    private static byte[] doFinal(Cipher c, byte[] input, boolean direct) throws Exception {
        ByteBuffer in = direct ? ByteBuffer.allocateDirect(input.length) : ByteBuffer.allocate(input.length);
        in.put(input).flip();
        int size = c.getOutputSize(input.length);
        ByteBuffer out = direct ? ByteBuffer.allocateDirect(size) : ByteBuffer.allocate(size);
        // split into update + doFinal to cover both paths
        ByteBuffer first = in.duplicate().limit(input.length / 3);
        c.update(first, out);
        in.position(input.length / 3);
        c.doFinal(in, out);
        out.flip();
        byte[] result = new byte[out.remaining()];
        out.get(result);
        assertEquals(0, in.remaining());
        return result;
    }
}
