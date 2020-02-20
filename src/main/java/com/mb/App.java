package com.mb;

import com.mb.util.JWTokenUtility;
import com.mb.util.TokenProvider;

import java.text.SimpleDateFormat;
import java.util.Date;


/**
 * Hello world!
 */
public class App {
    public static void main(String[] args) throws Exception {
        SimpleDateFormat sdfDate = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        String authUser = "{username: KhanhHN, password: 123456}";
        System.out.println("------------------------Using RSA------------------------");


        String token = JWTokenUtility.buildJWT(authUser);
        System.out.println("Token is: " + token);

        System.out.println(sdfDate.format(new Date()));
        String authUser1 = JWTokenUtility.validate(token);
        System.out.println(sdfDate.format(new Date()));
        System.out.println("Get credentials from token: " + authUser1);

        System.out.println("------------------------Using HMAC------------------------");

        String jwt = TokenProvider.issueToken(authUser);
        System.out.println("Toke is: " + jwt);

        System.out.println(sdfDate.format(new Date()));
        String authUser2 = TokenProvider.verifyToken(jwt);
        System.out.println(sdfDate.format(new Date()));
        System.out.println("Get credentials from token: " + authUser2);

    }
}
