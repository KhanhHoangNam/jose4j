package com.mb.util;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.lang.JoseException;

public class JWEUtility {
    private static final String JWK_JSON = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
    private static JsonWebKey jwk;

    static {
        try {
            jwk = JsonWebKey.Factory.newJwk(JWK_JSON);
        } catch (JoseException e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String data) throws JoseException {
        JsonWebEncryption senderJwe = new JsonWebEncryption();

        senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
        senderJwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        senderJwe.setKey(jwk.getKey());
        senderJwe.setPayload(data);

        return senderJwe.getCompactSerialization();
    }

    public static String decrypt(String jwe) throws JoseException {
        JsonWebEncryption receiverJwe = new JsonWebEncryption();

        AlgorithmConstraints algConstraints = new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, KeyManagementAlgorithmIdentifiers.DIRECT);
        receiverJwe.setAlgorithmConstraints(algConstraints);

        AlgorithmConstraints encConstraints = new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        receiverJwe.setContentEncryptionAlgorithmConstraints(encConstraints);

        receiverJwe.setKey(jwk.getKey());
        receiverJwe.setCompactSerialization(jwe);


        return receiverJwe.getPayload();
    }
}
