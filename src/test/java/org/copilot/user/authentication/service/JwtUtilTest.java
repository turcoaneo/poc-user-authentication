package org.copilot.user.authentication.service;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.copilot.user.authentication.service.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class) // Initializes mocks automatically
public class JwtUtilTest {

    @InjectMocks
    private JwtUtil jwtUtil;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(jwtUtil, "SECRET_KEY", "someUsefulLargeEnoughSecretKeyToBeAtLeast256Bits");
        ReflectionTestUtils.setField(jwtUtil, "expirationMinutes", 60);
    }

    @Test
    void testGenerateToken_Valid() {
        String token = jwtUtil.generateToken("EMPLOYER");
        assertNotNull(token); // Token must not be null
    }

    @Test
    void testGetRoleFromValidToken() {
        String token = jwtUtil.generateToken("ADMIN");
        String role = JwtUtil.getRoleFromToken(token);

        assertEquals("ADMIN", role); // Token should extract the correct role
    }

    @Test
    void testExpiredToken_ThrowsException() {
        Instant issuedAt = Instant.now().minus(10, ChronoUnit.MINUTES); // Simulate an expired token
        Instant expiration = issuedAt.plus(1, ChronoUnit.MINUTES);

        String expiredToken = Jwts.builder()
                .claims().subject("USER").and()
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(expiration))
                .signWith(JwtUtil.getSigningKey(), Jwts.SIG.HS256)
                .compact();

        JwtException exception = assertThrows(JwtException.class, () -> JwtUtil.getRoleFromToken(expiredToken));
        assertEquals("Invalid or expired token", exception.getMessage());
    }

    @Test
    void testInvalidToken_ThrowsException() {
        JwtException exception = assertThrows(JwtException.class, () -> JwtUtil.getRoleFromToken("fakeToken"));
        assertEquals("Invalid or expired token", exception.getMessage());
    }
}