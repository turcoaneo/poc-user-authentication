package org.copilot.user.authentication.service;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import org.copilot.user.authentication.model.entity.Role;
import org.copilot.user.authentication.model.entity.User;
import org.copilot.user.authentication.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

@ExtendWith(MockitoExtension.class) // Initializes mocks automatically
public class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Spy // Spy ensures real encryption behavior is used
    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @InjectMocks
    private UserService userService;

    @BeforeEach
    void setUp() {
        // No need for openMocks() since @ExtendWith(MockitoExtension.class) is used
    }

    // Test authenticateUser() - Success Case
    @Test
    void testAuthenticateUser_Success() {
        User mockUser = new User(1L, "testUser", passwordEncoder.encode("correctPassword"), Role.ADMIN);
        
        when(userRepository.findByUsername("testUser")).thenReturn(Optional.of(mockUser));

        String token = userService.authenticateUser("testUser", "correctPassword");

        assertNotNull(token, "Token should not be null on successful authentication.");
    }

    // Test authenticateUser() - Incorrect Password
    @Test
    void testAuthenticateUser_IncorrectPassword() {
        User mockUser = new User(1L, "testUser", passwordEncoder.encode("correctPassword"), Role.ADMIN);

        when(userRepository.findByUsername("testUser")).thenReturn(Optional.of(mockUser));

        String token = userService.authenticateUser("testUser", "wrongPassword");

        assertNull(token, "Token should be null when authentication fails.");
    }

    // Test authenticateUser() - Non-Existent User
    @Test
    void testAuthenticateUser_UserNotFound() {
        when(userRepository.findByUsername("nonExistentUser")).thenReturn(Optional.empty());

        String token = userService.authenticateUser("nonExistentUser", "anyPassword");

        assertNull(token, "Token should be null when user does not exist.");
    }
}