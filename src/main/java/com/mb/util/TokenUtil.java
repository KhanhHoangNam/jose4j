package com.mb.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class TokenUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenUtil.class);
    private static final SecretKey secretKey;

    static {
        secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    public static String encrypt(Long userId, String username) {
        final Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("username", username);
        final Date CURRENT_DATE = new Date();
        final Date EXPIRED_DATE = new Date(CURRENT_DATE.getYear() + 1,
                CURRENT_DATE.getMonth(),
                CURRENT_DATE.getDay(),
                CURRENT_DATE.getHours(),
                CURRENT_DATE.getMinutes(),
                CURRENT_DATE.getSeconds());

        return Jwts.builder()
                .setHeaderParam("alg", "HS256")
                .setHeaderParam("typ", "JWT")
                .setSubject("http://localhost:4200")
                .setClaims(claims)
                .setExpiration(EXPIRED_DATE)
                .signWith(secretKey)
                .compact();
    }

    public static Optional<Long> decrypt(String jws) {
        try {
            Jws<Claims> claims = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(jws);
            String userId = claims.getBody().get("userId").toString();

            return Optional.of(Long.parseLong(userId));
        } catch (Exception e) {
//            e.printStackTrace();
            LOGGER.info("Exception: " + e.getMessage());

            return Optional.empty();
        }
    }
}
