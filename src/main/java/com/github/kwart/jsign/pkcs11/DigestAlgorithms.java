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

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Digest algorithm names and OIDs, replacing the digest related parts of
 * sun.security.util.KnownOIDs and sun.security.rsa.RSAUtil.
 */
final class DigestAlgorithms {

    // standard name -> OID
    private static final Map<String, String> OIDS = Map.ofEntries(
            Map.entry("MD2", "1.2.840.113549.2.2"),
            Map.entry("MD5", "1.2.840.113549.2.5"),
            Map.entry("SHA-1", "1.3.14.3.2.26"),
            Map.entry("SHA-224", "2.16.840.1.101.3.4.2.4"),
            Map.entry("SHA-256", "2.16.840.1.101.3.4.2.1"),
            Map.entry("SHA-384", "2.16.840.1.101.3.4.2.2"),
            Map.entry("SHA-512", "2.16.840.1.101.3.4.2.3"),
            Map.entry("SHA-512/224", "2.16.840.1.101.3.4.2.5"),
            Map.entry("SHA-512/256", "2.16.840.1.101.3.4.2.6"),
            Map.entry("SHA3-224", "2.16.840.1.101.3.4.2.7"),
            Map.entry("SHA3-256", "2.16.840.1.101.3.4.2.8"),
            Map.entry("SHA3-384", "2.16.840.1.101.3.4.2.9"),
            Map.entry("SHA3-512", "2.16.840.1.101.3.4.2.10"));

    // upper case name, alias or OID -> standard name
    private static final Map<String, String> NAMES = new HashMap<>();

    static {
        for (Map.Entry<String, String> e : OIDS.entrySet()) {
            NAMES.put(e.getKey(), e.getKey());
            NAMES.put(e.getValue(), e.getKey());
        }
        // aliases as defined in KnownOIDs
        NAMES.put("SHA", "SHA-1");
        NAMES.put("SHA1", "SHA-1");
        NAMES.put("SHA224", "SHA-224");
        NAMES.put("SHA256", "SHA-256");
        NAMES.put("SHA384", "SHA-384");
        NAMES.put("SHA512", "SHA-512");
        NAMES.put("SHA512/224", "SHA-512/224");
        NAMES.put("SHA512/256", "SHA-512/256");
    }

    private DigestAlgorithms() {
    }

    /**
     * Returns the standard digest name, or null if the digest is not known.
     */
    static String toStdName(String name) {
        return name == null ? null : NAMES.get(name.toUpperCase(Locale.ENGLISH));
    }

    /**
     * Returns the standard name of the digest in a "&lt;digest&gt;with&lt;encryption&gt;"
     * signature algorithm name, e.g. SHA-256 for SHA256withRSA.
     */
    static String fromSignatureAlgorithm(String sigAlg) throws NoSuchAlgorithmException {
        int with = sigAlg.toUpperCase(Locale.ENGLISH).indexOf("WITH");
        if (with <= 0) {
            throw new NoSuchAlgorithmException("Unknown signature: " + sigAlg);
        }
        String digest = sigAlg.substring(0, with);
        String std = toStdName(digest);
        if (std == null) {
            throw new NoSuchAlgorithmException("Unsupported digest algorithm: " + digest);
        }
        return std;
    }

    /**
     * Encodes the PKCS#1 v1.5 DigestInfo (RFC 8017, section 9.2):
     * {@code SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING digest }}.
     */
    static byte[] encodeDigestInfo(String stdName, byte[] digest) {
        String oid = OIDS.get(stdName);
        if (oid == null) {
            throw new IllegalArgumentException("Unsupported digest algorithm: " + stdName);
        }
        byte[] algId = DerUtil.encode(DerUtil.TAG_SEQUENCE,
                DerUtil.encodeOid(oid), new byte[] { DerUtil.TAG_NULL, 0 });
        return DerUtil.encode(DerUtil.TAG_SEQUENCE, algId,
                DerUtil.encode(DerUtil.TAG_OCTET_STRING, digest));
    }
}
