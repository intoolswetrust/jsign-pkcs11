package com.github.kwart.jsign.pkcs11;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Provider construction, naming and KeyStore types.
 */
class ProviderTest {

    static SoftHsm hsm;

    @BeforeAll
    static void setup() {
        hsm = SoftHsm.get();
    }

    @Test
    void configureAndConstructors() throws Exception {
        Provider configured = new JSignPKCS11().configure(hsm.config("configured", ""));
        JSignPKCS11 fromString = new JSignPKCS11(hsm.config("fromString", ""));
        JSignPKCS11 fromStream = new JSignPKCS11(new ByteArrayInputStream(
                hsm.config("fromStream", "").substring(2).getBytes(StandardCharsets.UTF_8)));
        assertEquals("JSignPKCS11-configured", configured.getName());
        assertEquals("JSignPKCS11-fromString", fromString.getName());
        assertEquals("JSignPKCS11-fromStream", fromStream.getName());
        for (Provider p : List.of(configured, fromString, fromStream)) {
            assertTrue(p.isConfigured());
            List<String> aliases = Collections.list(SoftHsm.keyStore(p).aliases());
            assertTrue(aliases.containsAll(List.of(SoftHsm.RSA, SoftHsm.EC256, SoftHsm.EC384)), aliases.toString());
        }
    }

    @Test
    void keyStoreTypes() throws Exception {
        JSignPKCS11 p = hsm.provider("types", "");
        assertNotNull(KeyStore.getInstance("JSIGNPKCS11", p));
        assertNotNull(KeyStore.getInstance("JSIGNPKCS11-" + p.getName().substring("JSignPKCS11-".length()), p));
        assertThrows(Exception.class, () -> KeyStore.getInstance("PKCS11", p));
        assertNotNull(p.getService("SecureRandom", "JSIGNPKCS11"));
    }

    @Test
    void registeredProviderIsUsable() throws Exception {
        JSignPKCS11 p = hsm.provider("registered", "");
        Security.addProvider(p);
        try {
            KeyStore ks = KeyStore.getInstance("JSIGNPKCS11");
            assertEquals(p, ks.getProvider());
        } finally {
            Security.removeProvider(p.getName());
        }
    }

    @Test
    void nssModeIsRejected() {
        ProviderException e = assertThrows(ProviderException.class,
                () -> new JSignPKCS11("--name = nss\nnssLibraryDirectory = /usr/lib\nnssSecmodDirectory = /tmp\n"));
        assertTrue(e.getMessage().contains("NSS"), e.getMessage());
    }
}
