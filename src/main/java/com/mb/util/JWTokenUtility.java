package com.mb.util;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

/**
 * @author khanhhm.os
 * Using RSA_USING_SHA256 generate private key and public key
 */
public class JWTokenUtility {

    public static String buildJWT(String authUser) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        JwtClaims claims = new JwtClaims();
        claims.setSubject("subject"); // the subject/principal is whom the token is about
        claims.setClaim("authUser", authUser);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(GenerateKey.getPrivate());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

        String jwt = null;
        try {
            jwt = jws.getCompactSerialization();
            System.out.println(jwt);
        } catch (JoseException ex) {
            System.out.println(ex);
        }

        return jwt;
    }

    public static String validate(String jwt) throws Exception {

        String authUser;

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireSubject() // the JWT must have a subject claim
                .setVerificationKey(GenerateKey.getPublicKey()) // verify the signature with the public key
                .build(); // create the JwtConsumer instance

        try {
            //  Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            authUser = (String) jwtClaims.getClaimValue("authUser");
        } catch (InvalidJwtException e) {
            e.printStackTrace(); //on purpose
            throw e;
        }

        return authUser;
    }
}
