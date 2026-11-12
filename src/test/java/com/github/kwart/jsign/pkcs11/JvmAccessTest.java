package com.github.kwart.jsign.pkcs11;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.management.ManagementFactory;
import java.util.List;

import org.junit.jupiter.api.Test;

import sun.security.pkcs11.wrapper.PKCS11;

/**
 * The tests have to run with only the documented JVM flags, so that a newly needed export fails the build.
 */
class JvmAccessTest {

    @Test
    void onlyDocumentedFlags() {
        List<String> access = ManagementFactory.getRuntimeMXBean().getInputArguments().stream()
                .filter(a -> a.startsWith("--add-") || a.startsWith("--illegal-access") || a.startsWith("-XX:+Ignore"))
                .toList();
        assertEquals(List.of(System.getProperty("jsign.jvm.access").split("\\s+")), access);
    }

    @Test
    void onlyWrapperIsExported() {
        Module unnamed = JvmAccessTest.class.getModule();
        Module cryptoki = PKCS11.class.getModule();
        assertEquals("jdk.crypto.cryptoki", cryptoki.getName());
        assertTrue(cryptoki.isExported("sun.security.pkcs11.wrapper", unnamed));
        assertFalse(cryptoki.isOpen("sun.security.pkcs11.wrapper", unnamed));
        assertFalse(cryptoki.isExported("sun.security.pkcs11", unnamed));
        Module base = Object.class.getModule();
        for (String pkg : List.of("sun.security.util", "sun.security.rsa", "sun.security.x509", "sun.security.action",
                "sun.security.provider", "sun.security.jca", "sun.security.internal.spec", "sun.nio.ch",
                "jdk.internal.access", "jdk.internal.misc", "com.sun.crypto.provider", "java.security")) {
            assertFalse(base.isOpen(pkg, unnamed), pkg);
            if (pkg.startsWith("java.")) {
                continue;
            }
            assertFalse(base.isExported(pkg, unnamed), pkg);
        }
    }
}
