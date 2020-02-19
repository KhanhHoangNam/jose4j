package com.mb;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.mb.util.JWTokenUtility;
import com.mb.util.TokenProvider;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws InvalidJwtException, MalformedClaimException, JoseException, JsonProcessingException {
        System.out.println( "Hello World!" );
        System.out.println("------------------------------------");
//        AuthUser authUser = new AuthUser("KhanhHN", "123456");
        String authUser = "KhanhHN";
        String token = JWTokenUtility.buildJWT(authUser);
        System.out.println("Token is: " + token);

        System.out.println("Get credentials from token:  ");
        String authUser1 = JWTokenUtility.validate(token);
        System.out.println(authUser1);

        System.out.println("------------------------------------");
        String jwt = TokenProvider.issueToken("KhanhHN");
        System.out.println(jwt);
        String userData = TokenProvider.verifyToken(jwt);
        System.out.println(userData);
    }
}
