/*
 * Copyright (c) 2026, Josef Cacek. All rights reserved.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation, with the "Classpath" exception
 * as provided in the LICENSE file of the OpenJDK project.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details.
 */

package com.github.kwart.jsign.pkcs11;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

/**
 * EC helpers built on the public SunEC APIs, replacing sun.security.util.ECUtil.
 */
final class P11ECUtil {

    private P11ECUtil() {
    }

    static Provider getSunECProvider() {
        Provider p = Security.getProvider("SunEC");
        if (p == null) {
            throw new ProviderException("Cannot load SunEC provider");
        }
        return p;
    }

    private static AlgorithmParameters newParameters() {
        try {
            return AlgorithmParameters.getInstance("EC", getSunECProvider());
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException(e);
        }
    }

    private static KeyFactory keyFactory() {
        try {
            return KeyFactory.getInstance("EC", getSunECProvider());
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException(e);
        }
    }

    /**
     * Returns the named curve parameters, or null if the curve is not known.
     */
    static ECParameterSpec getECParameterSpec(String name) {
        try {
            AlgorithmParameters parameters = newParameters();
            parameters.init(new ECGenParameterSpec(name));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (InvalidParameterSpecException e) {
            return null;
        }
    }

    /**
     * Returns parameters of the NIST prime curve with the given field size, or null.
     */
    static ECParameterSpec getECParameterSpec(int keySize) {
        String name = switch (keySize) {
            case 192 -> "secp192r1";
            case 224 -> "secp224r1";
            case 256 -> "secp256r1";
            case 384 -> "secp384r1";
            case 521 -> "secp521r1";
            default -> null;
        };
        return name == null ? null : getECParameterSpec(name);
    }

    /**
     * Returns the named curve matching the given parameters, or null if the
     * curve is not supported.
     */
    static ECParameterSpec getECParameterSpec(ECParameterSpec spec) {
        try {
            AlgorithmParameters parameters = newParameters();
            parameters.init(spec);
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (InvalidParameterSpecException e) {
            return null;
        }
    }

    static ECParameterSpec decodeParameters(byte[] encoded) throws IOException {
        try {
            AlgorithmParameters parameters = newParameters();
            parameters.init(encoded);
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (InvalidParameterSpecException e) {
            throw new IOException("Unsupported EC parameters", e);
        }
    }

    /**
     * Returns the DER encoded named curve OID, or null if not supported.
     */
    static byte[] encodeParameters(ECParameterSpec spec) {
        try {
            AlgorithmParameters parameters = newParameters();
            parameters.init(spec);
            return parameters.getEncoded();
        } catch (InvalidParameterSpecException | IOException e) {
            return null;
        }
    }

    /**
     * Decodes an uncompressed X9.62 point.
     */
    static ECPoint decodePoint(byte[] data, EllipticCurve curve) throws IOException {
        if ((data.length == 0) || (data[0] != 4)) {
            throw new IOException("Only uncompressed point format supported");
        }
        int n = (data.length - 1) / 2;
        if (n != ((curve.getField().getFieldSize() + 7) >> 3)) {
            throw new IOException("Point does not match field size");
        }
        byte[] xb = Arrays.copyOfRange(data, 1, 1 + n);
        byte[] yb = Arrays.copyOfRange(data, n + 1, n + 1 + n);
        return new ECPoint(new BigInteger(1, xb), new BigInteger(1, yb));
    }

    /**
     * Encodes the point in the uncompressed X9.62 format.
     */
    static byte[] encodePoint(ECPoint point, EllipticCurve curve) {
        int n = (curve.getField().getFieldSize() + 7) >> 3;
        byte[] xb = P11Util.trimZeroes(point.getAffineX().toByteArray());
        byte[] yb = P11Util.trimZeroes(point.getAffineY().toByteArray());
        if ((xb.length > n) || (yb.length > n)) {
            throw new ProviderException("Point coordinates do not match field size");
        }
        byte[] b = new byte[1 + (n << 1)];
        b[0] = 4; // uncompressed
        System.arraycopy(xb, 0, b, n - xb.length + 1, xb.length);
        System.arraycopy(yb, 0, b, b.length - yb.length, yb.length);
        return b;
    }

    static PublicKey decodeX509PublicKey(byte[] encoded) throws InvalidKeySpecException {
        return keyFactory().generatePublic(new X509EncodedKeySpec(encoded));
    }

    static PrivateKey decodePKCS8PrivateKey(byte[] encoded) throws InvalidKeySpecException {
        return keyFactory().generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    static PrivateKey generatePrivateKey(BigInteger s, ECParameterSpec params)
            throws InvalidKeySpecException {
        return keyFactory().generatePrivate(new ECPrivateKeySpec(s, params));
    }

    static byte[] x509EncodePublicKey(ECPoint w, ECParameterSpec params)
            throws InvalidKeySpecException {
        return keyFactory().generatePublic(new ECPublicKeySpec(w, params)).getEncoded();
    }
}
