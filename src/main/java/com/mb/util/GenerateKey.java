package com.mb.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.jose4j.base64url.Base64;

import java.io.Reader;
import java.io.StringReader;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author khanhhm.os
 * since 20/02/2020
 */
public class GenerateKey {
    public static PublicKey getPublicKey() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Reader rdr = new StringReader(
                "-----BEGIN PUBLIC KEY-----\n" +
                        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxu9RmDPckanLtpjsr3ix\n" +
                        "sDYAHa9rB4LZLEap6KIaB76RyNfRVEknDRmCH/KtOOexaQZRKqAFy3iW4V4sZ+3h\n" +
                        "GiI2bcWKwrkCYkmba4XQPwN76whuhphsvuSChhuy0A2zqS9EXvz3gMQARwxihJG2\n" +
                        "l8gKwBFjUwLymNDxDpenwACtmzBI3aJg4f1vfQTEyEh8G/GiZg73OCzaqAOP+tRs\n" +
                        "Tsy9k/gXbJ0qQ+ThTemw1VpUhtk9I3RGn6RNGBue6g0xmnvBMlU001Ay0vewP7mq\n" +
                        "9YW+M8Ipg5rUSoBfemKo9+WuedgLc1fFqHMocdiJpmRfcwMkKaWTd8d1VZ+D4MPg\n" +
                        "3QIDAQAB\n" +
                        "-----END PUBLIC KEY-----"
        ); // or from file etc.

        PemObject spk = new PemReader(rdr).readPemObject();
        return KeyFactory.getInstance("RSA", "BC").generatePublic(new X509EncodedKeySpec(spk.getContent()));
    }

    public static PrivateKey getPrivate() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());
        String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIEogIBAAKCAQEAxu9RmDPckanLtpjsr3ixsDYAHa9rB4LZLEap6KIaB76RyNfR\n" +
                "VEknDRmCH/KtOOexaQZRKqAFy3iW4V4sZ+3hGiI2bcWKwrkCYkmba4XQPwN76whu\n" +
                "hphsvuSChhuy0A2zqS9EXvz3gMQARwxihJG2l8gKwBFjUwLymNDxDpenwACtmzBI\n" +
                "3aJg4f1vfQTEyEh8G/GiZg73OCzaqAOP+tRsTsy9k/gXbJ0qQ+ThTemw1VpUhtk9\n" +
                "I3RGn6RNGBue6g0xmnvBMlU001Ay0vewP7mq9YW+M8Ipg5rUSoBfemKo9+WuedgL\n" +
                "c1fFqHMocdiJpmRfcwMkKaWTd8d1VZ+D4MPg3QIDAQABAoIBAAOoYNKwmWygN5uq\n" +
                "4iczy+iWhZgGIqynrkCPKA6b9GiSC3Iq7bFkCvDFuEvIFYFHWU66DAIBoTmlhPit\n" +
                "15ktmYb2fBO2nx+HcVDHU7E9a5/M+5lNtWKKKO21m+TFW5tRtSz2LoaklhRrBipI\n" +
                "QwN2/ml6ByCS8UWUd0tyBAylozL3h+mvNV5ybmLAfVGOw0/jMo9nG4BvYQ8jtqqN\n" +
                "irS2/SBBSYHvU93rzDZOtwOMy9d8xF381mXNj/sYHiptCuB44sCNwya2wvofH3rn\n" +
                "Uth04TgAGY6vQR/c0cFrsyh3smTF4cwH6EzwUdmUsn8Ka138TCI4QT/rDF4PUOmL\n" +
                "WjNJxU0CgYEA7vQNvuRuO97+1Jbodwo16srl4E46FwqzGKt5EqROeD5ZEGBHfQdg\n" +
                "6TxLa551yR02hU4lmuVJHb93iRc63lNY7T0eUntNODfzpu8PzxiBgq9u9N2K6dFI\n" +
                "1gFfx+qDqiqtqODt3W5wo23MKGiDDEWzqa3jlJW557CgWPtsgzZ1kKsCgYEA1SBq\n" +
                "wo7PRGpFVdfb9aaYUJrWB3LI36R+r3JnzjnoWcZuoNUvegztnrJsWjko0+a/xvz1\n" +
                "1fGyHDOlYYZASiVOq08Fiqgtp91pYMH0rf/5jdl12EEC0I+0A1VaQUXB6155jBhy\n" +
                "SeHt+hj4I5IrID1IX2f9C2X37q0WwhdvLf46pJcCgYBzG1mrxTpc2PUEz5U4EtEa\n" +
                "Q5cs0EIna14O2js+gavTPKWGv/pv/ifu8r6aHwE6WjozSQvQa/cmv18DyQ7wnlHO\n" +
                "Joz+yqrOFBXpKmwBJRruKzhV+Iq8S7a8cHkFQrEePeTd30x2SIc2EuQv6viF5uW/\n" +
                "LSbeIqolM+5qLuN86bUEdQKBgHeXrDCmgEnstCF6cjRDGn9Ik0c0suFD5c6/jN5d\n" +
                "AjO2NIfNeMmtDX2as1BheLaHah/X/H7kFETc+jViZxr0GlPokLyAqLXkeWhRDeLB\n" +
                "m6BsYUNLH7A2oxWnxHCSG0HfDqd9ZExvGeHYNw2GzOpXWRAoQwctXdWxjO62xa1y\n" +
                "VifbAoGADBTBPlaJvRQaa+4vCdRlPOkZzX3hlWaCUoB2PFHCBQnaCwPL1WV4njGI\n" +
                "SP0B476xGjh+nqkzJCuzNX60C93nFIlB3kkumuHlKd+F8twbOLz1WbkNCZG5Pq5O\n" +
                "GrbZdhFDpSNteYZ++4I5drL42dbeh4UdNRCtCa94mmIYBmRFhqs=\n" +
                "-----END RSA PRIVATE KEY-----";
        key = key.replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s+", "").replaceAll("\\r+", "").replaceAll("\\n+", "");
        byte[] keyByteArray = Base64.decode(key);
        return KeyFactory.getInstance("RSA", "BC").generatePrivate(new PKCS8EncodedKeySpec(keyByteArray));
    }
}
