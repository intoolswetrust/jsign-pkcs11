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

import java.util.Locale;

/**
 * Debug output enabled by the {@code java.security.debug} system property,
 * replacing {@code sun.security.util.Debug}. The option names are the ones
 * the JDK PKCS#11 provider uses ({@code sunpkcs11}, {@code pkcs11},
 * {@code pkcs11keystore}); {@code all} enables everything.
 */
final class Debug {

    private final String prefix;

    private Debug(String prefix) {
        this.prefix = prefix;
    }

    /**
     * Returns a Debug instance if the given option is enabled, null otherwise.
     */
    static Debug getInstance(String option) {
        String args = System.getProperty("java.security.debug");
        if (args == null) {
            return null;
        }
        args = args.toLowerCase(Locale.ENGLISH);
        for (String arg : args.split("[,:;\\s]+")) {
            if (arg.equals("all") || arg.equals(option)) {
                return new Debug(option);
            }
        }
        return null;
    }

    void println(String message) {
        System.err.println(prefix + ": " + message);
    }
}
