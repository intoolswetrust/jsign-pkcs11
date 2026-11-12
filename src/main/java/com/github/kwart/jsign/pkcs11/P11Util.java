/*
 * Copyright (c) 2003, 2023, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.github.kwart.jsign.pkcs11;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.ref.Cleaner;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.*;
import java.util.Arrays;

import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;
import static sun.security.pkcs11.wrapper.PKCS11Exception.RV.*;

/**
 * Collection of static utility methods.
 *
 * @author  Andreas Sterbenz
 * @since   1.5
 */
public final class P11Util {

    // A cleaner, shared within this module.
    public static final Cleaner cleaner = Cleaner.create();

    private static final Object LOCK = new Object();

    private static volatile Provider sun, sunRsaSign, sunJce;

    private P11Util() {
        // empty
    }

    static boolean isNSS(Token token) {
        char[] tokenLabel = token.tokenInfo.label;
        if (tokenLabel != null && tokenLabel.length >= 3) {
            return (tokenLabel[0] == 'N' && tokenLabel[1] == 'S'
                    && tokenLabel[2] == 'S');
        }
        return false;
    }

    static char[] encodePassword(char[] password, Charset cs,
            int nullTermBytes) {
        /*
         * When a Java char (2 bytes) is converted to CK_UTF8CHAR (1 byte) for
         * a PKCS #11 (native) call, the high-order byte is discarded (see
         * jCharArrayToCKUTF8CharArray in p11_util.c). In order to have an
         * encoded string passed to C_GenerateKey, we need to account for
         * truncation and expand beforehand: high and low parts of each char
         * are split into 2 chars. As an example, this is the transformation
         * for a NULL terminated password "a" that has to be encoded in
         * UTF-16 BE:
         *     char[] password       => [    0x0061,         0x0000    ]
         *                                   /    \          /    \
         * ByteBuffer passwordBytes  => [ 0x00,   0x61,   0x00,   0x00 ]
         *                                  |       |       |       |
         *     char[] encPassword    => [0x0000, 0x0061, 0x0000, 0x0000]
         *                                  |       |       |       |
         *     PKCS #11 call (bytes) => [ 0x00,   0x61,   0x00,   0x00 ]
         */
        ByteBuffer passwordBytes = cs.encode(CharBuffer.wrap(password));
        char[] encPassword =
                new char[passwordBytes.remaining() + nullTermBytes];
        int i = 0;
        while (passwordBytes.hasRemaining()) {
            encPassword[i] = (char) (passwordBytes.get() & 0xFF);
            // Erase password bytes as we read during encoding.
            passwordBytes.put(i++, (byte) 0);
        }
        return encPassword;
    }

    static Provider getSunProvider() {
        Provider p = sun;
        if (p == null) {
            synchronized (LOCK) {
                p = getProvider(sun, "SUN");
                sun = p;
            }
        }
        return p;
    }

    static Provider getSunRsaSignProvider() {
        Provider p = sunRsaSign;
        if (p == null) {
            synchronized (LOCK) {
                p = getProvider(sunRsaSign, "SunRsaSign");
                sunRsaSign = p;
            }
        }
        return p;
    }

    static Provider getSunJceProvider() {
        Provider p = sunJce;
        if (p == null) {
            synchronized (LOCK) {
                p = getProvider(sunJce, "SunJCE");
                sunJce = p;
            }
        }
        return p;
    }

    private static Provider getProvider(Provider p, String providerName) {
        if (p != null) {
            return p;
        }
        p = Security.getProvider(providerName);
        if (p == null) {
            throw new ProviderException("Could not find provider " + providerName);
        }
        return p;
    }

    /**
     * Starts a daemon thread with the minimum priority and no context class loader.
     */
    static void startDaemonThread(String name, Runnable runnable) {
        Thread t = new Thread(null, runnable, name, 0, false);
        t.setContextClassLoader(null);
        t.setPriority(Thread.MIN_PRIORITY);
        t.setDaemon(true);
        t.start();
    }

    private static final class RandomHolder {
        static final SecureRandom RANDOM = new SecureRandom();
    }

    /**
     * Returns a shared SecureRandom instance.
     */
    static SecureRandom getSecureRandom() {
        return RandomHolder.RANDOM;
    }

    /**
     * Returns the array without leading zero bytes.
     */
    static byte[] trimZeroes(byte[] b) {
        int i = 0;
        while ((i < b.length - 1) && (b[i] == 0)) {
            i++;
        }
        return i == 0 ? b : Arrays.copyOfRange(b, i, b.length);
    }

    // CK_MECHANISM.freeHandle() was removed in JDK 25
    private static final MethodHandle FREE_HANDLE = findWrapperMethod(
            CK_MECHANISM.class, "freeHandle", MethodType.methodType(void.class));

    // PKCS11.C_GCM{En,De}cryptInitWithRetry() exist since JDK 21.0.5
    private static final MethodType GCM_INIT_TYPE = MethodType.methodType(void.class,
            long.class, CK_MECHANISM.class, long.class, boolean.class);
    private static final MethodHandle GCM_ENCRYPT_INIT = findWrapperMethod(
            PKCS11.class, "C_GCMEncryptInitWithRetry", GCM_INIT_TYPE);
    private static final MethodHandle GCM_DECRYPT_INIT = findWrapperMethod(
            PKCS11.class, "C_GCMDecryptInitWithRetry", GCM_INIT_TYPE);

    private static MethodHandle findWrapperMethod(Class<?> c, String name, MethodType type) {
        try {
            return MethodHandles.publicLookup().findVirtual(c, name, type);
        } catch (NoSuchMethodException | IllegalAccessException e) {
            return null;
        }
    }

    /**
     * Frees the native memory of the mechanism parameters, if the running JDK
     * keeps it.
     */
    static void freeMechanism(CK_MECHANISM mechanism) {
        if (FREE_HANDLE != null) {
            try {
                FREE_HANDLE.invoke(mechanism);
            } catch (Throwable t) {
                throw new ProviderException(t);
            }
        }
    }

    /**
     * Calls C_GCMEncryptInitWithRetry or C_GCMDecryptInitWithRetry if the
     * running JDK has them, otherwise C_EncryptInit or C_DecryptInit.
     */
    static void gcmInit(PKCS11 p11, boolean encrypt, long session,
            CK_MECHANISM mechanism, long keyID, boolean useNormativeVerFirst)
            throws PKCS11Exception {
        MethodHandle mh = encrypt ? GCM_ENCRYPT_INIT : GCM_DECRYPT_INIT;
        if (mh == null) {
            if (encrypt) {
                p11.C_EncryptInit(session, mechanism, keyID);
            } else {
                p11.C_DecryptInit(session, mechanism, keyID);
            }
            return;
        }
        try {
            mh.invoke(p11, session, mechanism, keyID, useNormativeVerFirst);
        } catch (PKCS11Exception | RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new ProviderException(t);
        }
    }

    // limits of sun.security.rsa.RSAKeyFactory
    private static final int MAX_RSA_MODLEN = 16384;
    private static final int MAX_RSA_MODLEN_RESTRICT_EXP = 3072;
    private static final int MAX_RSA_RESTRICTED_EXPLEN = 64;
    private static final boolean RESTRICT_RSA_EXPONENT = Boolean.parseBoolean(
            System.getProperty("sun.security.rsa.restrictRSAExponent", "true"));

    /**
     * Same checks as sun.security.rsa.RSAKeyFactory.checkKeyLengths().
     */
    static void checkRSAKeyLengths(int modulusLen, BigInteger exponent,
            int minModulusLen, int maxModulusLen) throws InvalidKeyException {
        if ((minModulusLen > 0) && (modulusLen < minModulusLen)) {
            throw new InvalidKeyException("RSA keys must be at least " +
                minModulusLen + " bits long");
        }
        int maxLen = Math.min(maxModulusLen, MAX_RSA_MODLEN);
        if (modulusLen > maxLen) {
            throw new InvalidKeyException(
                "RSA keys must be no longer than " + maxLen + " bits");
        }
        if (RESTRICT_RSA_EXPONENT && (exponent != null) &&
                (modulusLen > MAX_RSA_MODLEN_RESTRICT_EXP) &&
                (exponent.bitLength() > MAX_RSA_RESTRICTED_EXPLEN)) {
            throw new InvalidKeyException(
                "RSA exponents can be no longer than " +
                MAX_RSA_RESTRICTED_EXPLEN + " bits " +
                " if modulus is greater than " +
                MAX_RSA_MODLEN_RESTRICT_EXP + " bits");
        }
    }

    // same as sun.security.util.KeyUtil.isSupportedKeyAgreementOutputAlgorithm()
    static boolean isSupportedKeyAgreementOutputAlgorithm(String alg) {
        return alg.equalsIgnoreCase("TlsPremasterSecret")
                || alg.equalsIgnoreCase("Generic");
    }

    /**
     * Same checks as sun.security.util.KeyUtil.validate() for DH public keys:
     * y in [2, p-2] and y is not a factor of p.
     */
    static void validateDHPublicKey(BigInteger p, BigInteger y)
            throws InvalidKeyException {
        if (y.compareTo(BigInteger.ONE) <= 0) {
            throw new InvalidKeyException(
                    "Diffie-Hellman public key is too small");
        }
        if (y.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
            throw new InvalidKeyException(
                    "Diffie-Hellman public key is too large");
        }
        if (p.remainder(y).signum() == 0) {
            throw new InvalidKeyException("Invalid Diffie-Hellman parameters");
        }
    }

    static byte[] convert(byte[] input, int offset, int len) {
        if ((offset == 0) && (len == input.length)) {
            return input;
        } else {
            byte[] t = new byte[len];
            System.arraycopy(input, offset, t, 0, len);
            return t;
        }
    }

    static byte[] subarray(byte[] b, int ofs, int len) {
        byte[] out = new byte[len];
        System.arraycopy(b, ofs, out, 0, len);
        return out;
    }

    static byte[] concat(byte[] b1, byte[] b2) {
        byte[] b = new byte[b1.length + b2.length];
        System.arraycopy(b1, 0, b, 0, b1.length);
        System.arraycopy(b2, 0, b, b1.length, b2.length);
        return b;
    }

    static long[] concat(long[] b1, long[] b2) {
        if (b1.length == 0) {
            return b2;
        }
        long[] b = new long[b1.length + b2.length];
        System.arraycopy(b1, 0, b, 0, b1.length);
        System.arraycopy(b2, 0, b, b1.length, b2.length);
        return b;
    }

    public static byte[] getMagnitude(BigInteger bi) {
        byte[] b = bi.toByteArray();
        if ((b.length > 1) && (b[0] == 0)) {
            int n = b.length - 1;
            byte[] newarray = new byte[n];
            System.arraycopy(b, 1, newarray, 0, n);
            b = newarray;
        }
        return b;
    }

    static byte[] sha1(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(data);
            return md.digest();
        } catch (GeneralSecurityException e) {
            throw new ProviderException(e);
        }
    }

    private static final char[] hexDigits = "0123456789abcdef".toCharArray();

    static String toString(byte[] b) {
        if (b == null) {
            return "(null)";
        }
        StringBuilder sb = new StringBuilder(b.length * 3);
        for (int i = 0; i < b.length; i++) {
            int k = b[i] & 0xff;
            if (i != 0) {
                sb.append(':');
            }
            sb.append(hexDigits[k >>> 4]);
            sb.append(hexDigits[k & 0xf]);
        }
        return sb.toString();
    }

    // returns true if successfully cancelled
    static boolean trySessionCancel(Token token, Session session, long flags)
            throws ProviderException {
        if (token.p11.getVersion().major == 3) {
            try {
                token.p11.C_SessionCancel(session.id(), flags);
                return true;
            } catch (PKCS11Exception e) {
                // return false for CKR_OPERATION_CANCEL_FAILED, so callers
                // can cancel in the pre v3.0 way, i.e. by finishing off the
                // current operation
                if (!e.match(CKR_OPERATION_CANCEL_FAILED)) {
                    throw new ProviderException("cancel failed", e);
                }
            }
        }
        return false;
    }
}
