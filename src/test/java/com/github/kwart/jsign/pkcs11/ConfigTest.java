package com.github.kwart.jsign.pkcs11;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;

import org.junit.jupiter.api.Test;

class ConfigTest {

    private static Config config(String extra) throws Exception {
        return new Config("--name = test\nlibrary = /nonexistent/libtest.so\n" + extra);
    }

    @Test
    void contextSpecificLogin() throws Exception {
        assertEquals(Config.ContextLogin.AUTO, config("").getContextSpecificLogin());
        assertEquals(Config.ContextLogin.ALWAYS, config("contextSpecificLogin = always").getContextSpecificLogin());
        assertEquals(Config.ContextLogin.NEVER, config("contextSpecificLogin = never").getContextSpecificLogin());
        assertThrows(Exception.class, () -> config("contextSpecificLogin = sometimes"));
    }

    @Test
    void expand() {
        System.setProperty("jsign.test.dir", "/opt/token");
        assertEquals("/opt/token/lib.so", Config.expand("${jsign.test.dir}/lib.so"));
        assertEquals("a" + File.separator + "b", Config.expand("a${/}b"));
        assertEquals("${{keep}}", Config.expand("${{keep}}"));
        assertEquals("x${unterminated", Config.expand("x${unterminated"));
        assertEquals("plain", Config.expand("plain"));
        assertThrows(RuntimeException.class, () -> Config.expand("${jsign.test.undefined}"));
    }

    @Test
    void nameAndLibrary() throws Exception {
        Config c = config("description = test token");
        assertEquals("test", c.getName());
        assertEquals("/nonexistent/libtest.so", c.getLibrary());
    }
}
