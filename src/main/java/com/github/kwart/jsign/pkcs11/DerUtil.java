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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * Minimal DER encoding and strict decoding of the structures the provider
 * needs (DigestInfo, DSA/ECDSA signatures, EC points), replacing
 * sun.security.util.DerValue and friends.
 */
final class DerUtil {

    static final int TAG_INTEGER = 0x02;
    static final int TAG_OCTET_STRING = 0x04;
    static final int TAG_NULL = 0x05;
    static final int TAG_OID = 0x06;
    static final int TAG_SEQUENCE = 0x30;

    private DerUtil() {
    }

    /**
     * Encodes a TLV with the given tag and content.
     */
    static byte[] encode(int tag, byte[]... contents) {
        int len = 0;
        for (byte[] c : contents) {
            len += c.length;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(len + 6);
        out.write(tag);
        if (len < 0x80) {
            out.write(len);
        } else {
            int bytes = (32 - Integer.numberOfLeadingZeros(len) + 7) / 8;
            out.write(0x80 | bytes);
            for (int i = bytes - 1; i >= 0; i--) {
                out.write(len >>> (8 * i));
            }
        }
        for (byte[] c : contents) {
            out.writeBytes(c);
        }
        return out.toByteArray();
    }

    static byte[] encodeInteger(BigInteger value) {
        return encode(TAG_INTEGER, value.toByteArray());
    }

    static byte[] encodeOid(String oid) {
        String[] parts = oid.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBase128(out, new BigInteger(parts[0]).multiply(BigInteger.valueOf(40))
                .add(new BigInteger(parts[1])));
        for (int i = 2; i < parts.length; i++) {
            writeBase128(out, new BigInteger(parts[i]));
        }
        return encode(TAG_OID, out.toByteArray());
    }

    private static void writeBase128(ByteArrayOutputStream out, BigInteger value) {
        int groups = Math.max(1, (value.bitLength() + 6) / 7);
        for (int i = groups - 1; i >= 0; i--) {
            int b = value.shiftRight(7 * i).intValue() & 0x7f;
            out.write(i == 0 ? b : (b | 0x80));
        }
    }

    /**
     * Returns the content of a single DER TLV with the expected tag. Trailing
     * data and non-minimal lengths are rejected.
     */
    static byte[] decode(int expectedTag, byte[] encoded) throws IOException {
        Reader r = new Reader(encoded);
        byte[] value = r.read(expectedTag);
        r.ensureEnd();
        return value;
    }

    /**
     * Decodes {@code SEQUENCE { INTEGER, INTEGER }} as used for DSA and ECDSA
     * signatures. Trailing data is rejected.
     */
    static BigInteger[] decodeIntegerPair(byte[] encoded) throws IOException {
        Reader seq = new Reader(decode(TAG_SEQUENCE, encoded));
        BigInteger[] result = { seq.readPositiveInteger(), seq.readPositiveInteger() };
        seq.ensureEnd();
        return result;
    }

    private static final class Reader {
        private final byte[] data;
        private int pos;

        Reader(byte[] data) {
            this.data = data;
        }

        byte[] read(int expectedTag) throws IOException {
            if (pos + 2 > data.length) {
                throw new IOException("Truncated DER data");
            }
            int tag = data[pos++] & 0xff;
            if (tag != expectedTag) {
                throw new IOException("Unexpected DER tag: " + tag + ", expected " + expectedTag);
            }
            int len = data[pos++] & 0xff;
            if (len >= 0x80) {
                int bytes = len & 0x7f;
                if (bytes == 0 || bytes > 3 || pos + bytes > data.length) {
                    throw new IOException("Unsupported DER length");
                }
                len = 0;
                for (int i = 0; i < bytes; i++) {
                    len = (len << 8) | (data[pos++] & 0xff);
                }
                if (len < 0x80 || (bytes > 1 && len < (1 << (8 * (bytes - 1))))) {
                    throw new IOException("Non-minimal DER length");
                }
            }
            if (len > data.length - pos) {
                throw new IOException("Truncated DER data");
            }
            byte[] value = new byte[len];
            System.arraycopy(data, pos, value, 0, len);
            pos += len;
            return value;
        }

        // same semantics as DerValue.getPositiveBigInteger()
        BigInteger readPositiveInteger() throws IOException {
            byte[] v = read(TAG_INTEGER);
            if (v.length == 0) {
                throw new IOException("Invalid encoding: zero length Int value");
            }
            if (v.length >= 2 && v[0] == 0 && v[1] >= 0) {
                throw new IOException("Invalid encoding: redundant leading 0s");
            }
            return new BigInteger(1, v);
        }

        void ensureEnd() throws IOException {
            if (pos != data.length) {
                throw new IOException("Extra data after DER value");
            }
        }
    }
}
