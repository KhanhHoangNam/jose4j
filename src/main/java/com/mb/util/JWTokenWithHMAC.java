package com.mb.util;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

import javax.crypto.SecretKey;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JWTokenWithHMAC {
    private static final SecretKey secretKey;

    static {
        secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    public static String buildJWT(String authUser) {


        JwtClaims claims = new JwtClaims();
        claims.setSubject("subject"); // the subject/principal is whom the token is about
        claims.setClaim("authUser", authUser);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(secretKey);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);

        String jwt = null;
        try {
            jwt = jws.getCompactSerialization();
        } catch (JoseException ex) {
            Logger.getLogger(JWTokenUtility.class.getName()).log(Level.SEVERE, null, ex);
        }

        System.out.println("Claim:\n" + claims);
        System.out.println("JWS:\n" + jws);
//        System.out.println("JWT:\n" + jwt);

        return jwt;
    }

    public static String validate(String jwt) throws InvalidJwtException, MalformedClaimException {
        String authUser;
        RsaJsonWebKey rsaJsonWebKey = RsaKeyProducer.produce();

        System.out.println("RSA hash code... " + rsaJsonWebKey.hashCode());

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireSubject() // the JWT must have a subject claim
                .setVerificationKey(secretKey) // verify the signature with the public key
                .build(); // create the JwtConsumer instance

        try {
            //  Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            authUser = (String) jwtClaims.getClaimValue("authUser");
            System.out.println("JWT validation succeeded! " + jwtClaims);
        } catch (InvalidJwtException e) {
            e.printStackTrace(); //on purpose
            throw e;
        }

        return authUser;
    }
}
