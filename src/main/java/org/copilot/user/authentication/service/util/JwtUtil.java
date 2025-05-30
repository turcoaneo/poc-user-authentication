package org.copilot.user.authentication.service.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;

public class JwtUtil {
    private static final String SECRET_KEY = "someUsefulLargeEnoughSecretKeyToBeAtLeast256Bits";
    private static final long EXPIRATION_TIME = 86400000; // 1 day

    public static String generateToken(String role) {
        return Jwts.builder()
                .setSubject(role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    public static String getRoleFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(SECRET_KEY) // Use correct key type
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject(); // Extract the role from the subject field
    }
}