package org.copilot.user.authentication.service.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Component
public class JwtUtil {
    @Value("${jwt.expirationMinutes}")
    private long expirationMinutes;

    public String generateToken(String role) {
        return Jwts.builder()
                .claims().subject(role).and()
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plus(Duration.ofMinutes(expirationMinutes))))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    private static SecretKey getSigningKey() {
        final String keyName = "SECRET_KEY";
        final String secretKey = System.getenv(keyName);
        final String SECRET_KEY = secretKey == null ? System.getProperty(keyName) : System.getenv(keyName);
        if (SECRET_KEY == null || SECRET_KEY.isEmpty()) {
            throw new IllegalStateException("SECRET_KEY environment variable is not set!");
        }
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    public static String getRoleFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // Check if token is expired
            if (claims.getExpiration().before(new Date())) {
                throw new JwtException("Token has expired"); // Or handle it gracefully
            }

            return claims.getSubject(); // Extract role if valid
        } catch (JwtException e) {
            throw new JwtException("Invalid or expired token", e);
        }
    }
}