package org.copilot.user.authentication.service.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

public class JwtUtil {
    private static final String SECRET_KEY = "someUsefulLargeEnoughSecretKeyToBeAtLeast256Bits";
    private static final long EXPIRATION_TIME = 1; // day

    public static String generateToken(String role) {
        return Jwts.builder()
                .claims().subject(role).and()
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plus(Duration.ofDays(EXPIRATION_TIME))))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    private static SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    public static String getRoleFromToken(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }
}