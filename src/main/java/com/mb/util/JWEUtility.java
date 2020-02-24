package com.mb.util;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;

public class JWEUtility {

    public static String encrypt(String data) throws Exception {
        JsonWebEncryption senderJwe = new JsonWebEncryption();

        senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        senderJwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
        senderJwe.setKey(GenerateKey.getPublicKey());
        senderJwe.setPayload(data);

        return senderJwe.getCompactSerialization();
    }

    public static String decrypt(String jwe) throws Exception {
        JsonWebEncryption receiverJwe = new JsonWebEncryption();

        AlgorithmConstraints algConstraints = new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        receiverJwe.setAlgorithmConstraints(algConstraints);

        AlgorithmConstraints encConstraints = new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
        receiverJwe.setContentEncryptionAlgorithmConstraints(encConstraints);

        receiverJwe.setKey(GenerateKey.getPrivate());
        receiverJwe.setCompactSerialization(jwe);


        return receiverJwe.getPayload();
    }
}
