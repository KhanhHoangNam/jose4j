package com.mb.util;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;

/**
 * @author khanhhm.os
 * Using HMAC_SHA256 generate secret key
 */
public class TokenProvider {
    private static String secret = "Xz91Jn4yNlU23Tn5RfR7TyZYT0knAokWftBwzR5LIvzGt9pGkqLICOYCxkNrlA1C"; // God forgive me for this

    public static String issueToken(String userData) throws JoseException {

        // Create the Claims, which will be the content of the JWT
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("server");  // who creates the token and signs it
        claims.setAudience("client"); // to whom the token is intended to be sent
        claims.setExpirationTimeMinutesInTheFuture(60 * 24); // time when the token will expire (10 minutes from now)
        claims.setGeneratedJwtId(); // a unique identifier for the token
        claims.setIssuedAtToNow();  // when the token was issued/created (now)
        claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
        claims.setSubject("orderTable"); // the subject/principal is whom the token is about
        claims.setClaim("userData", userData); // additional claims/attributes about the subject can be added

        // A JWT is a JWS and/or a JWE with JSON claims as the payload.
        // In this example it is a JWS so we create a JsonWebSignature object.
        JsonWebSignature jws = new JsonWebSignature();

        // The payload of the JWS is JSON content of the JWT Claims
        jws.setPayload(claims.toJson());

        // The JWT is signed using the private key
        jws.setKey(new HmacKey(secret.getBytes()));


        // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);

        // Sign the JWS and produce the compact serialization or the complete JWT/JWS
        // representation, which is a string consisting of three dot ('.') separated
        // base64url-encoded parts in the form Header.Payload.Signature
        // If you wanted to encrypt it, you can simply set this jwt as the payload
        // of a JsonWebEncryption object and set the cty (Content Type) header to "jwt".


        // Now you can do something with the JWT. Like send it to some other party
        // over the clouds and through the interwebs.
        return jws.getCompactSerialization();
    }

    public static String verifyToken(String data) {
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setMaxFutureValidityInMinutes(60 * 24) // but the  expiration time can't be too crazy
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer("server") // whom the JWT needs to have been issued by
                .setExpectedAudience("client") // to whom the JWT is intended for
                .setVerificationKey(new HmacKey(secret.getBytes())) // verify the signature with the public key
                .build(); // create the JwtConsumer instance

        try {
            //  Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(data);
            return (String) jwtClaims.getClaimValue("userData");
        } catch (Exception e) {
            return null;
        }

    }
}
