package com.mb;

import com.mb.domain.AuthUser;
import com.mb.util.JWTokenUtility;
import com.mb.util.JWTokenWithHMAC;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws InvalidJwtException, MalformedClaimException {
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
        String token1 = JWTokenWithHMAC.buildJWT(authUser);
        System.out.println("Token is: " + token);

        String authUser2 = JWTokenWithHMAC.validate(token1);
        System.out.println(authUser2);
    }
}
