package org.copilot.user.authentication.controller;

import org.copilot.user.authentication.model.dto.UserDTO;
import org.copilot.user.authentication.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpStatus.*;


@ExtendWith(MockitoExtension.class)
public class UserControllerTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private UserController userController;

    @BeforeEach
    void setUp() {
    }

    // Test for registerUser()
    @Test
    void testRegisterUser() {
        UserDTO mockUser = getUserDTO("user");
        when(userService.saveUser(any(UserDTO.class))).thenReturn(mockUser);

        UserDTO result = userController.registerUser(mockUser);

        assertNotNull(result);
        assertEquals("user", result.getUsername());
        verify(userService).saveUser(any(UserDTO.class));
    }

    private static UserDTO getUserDTO(String username) {
        UserDTO userDTO = new UserDTO();
        userDTO.setUsername(username);
        userDTO.setPassword("password");
        return userDTO;
    }

    // Test for getUser() with ADMIN role
    @Test
    void testGetUser_AdminRole() {
        Authentication mockAuth = mock(Authentication.class);
        when(mockAuth.isAuthenticated()).thenReturn(true);
        //noinspection rawtypes
        List roleAdmin = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
        //noinspection unchecked
        when(mockAuth.getAuthorities()).thenReturn(roleAdmin);
        SecurityContextHolder.getContext().setAuthentication(mockAuth);

        UserDTO mockUser = getUserDTO("adminUser");
        when(userService.findByUsername("adminUser")).thenReturn(mockUser);

        ResponseEntity<UserDTO> response = userController.getUser("adminUser");

        assertEquals(OK, response.getStatusCode());
        assertNotNull(response.getBody());
    }

    // Test for getUser() with NON-ADMIN role
    @Test
    void testGetUser_NonAdminRole() {
        Authentication mockAuth = mock(Authentication.class);
        when(mockAuth.isAuthenticated()).thenReturn(true);
        when(mockAuth.getAuthorities()).thenAnswer(invocation -> Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(mockAuth);

        ResponseEntity<UserDTO> response = userController.getUser("regularUser");

        assertEquals(FORBIDDEN, response.getStatusCode());
    }

    // Test for getUser() when unauthenticated
    @Test
    void testGetUser_Unauthenticated() {
        SecurityContextHolder.clearContext(); // No authentication

        ResponseEntity<UserDTO> response = userController.getUser("randomUser");

        assertEquals(UNAUTHORIZED, response.getStatusCode());
    }

    // Test for login()
    @Test
    void testLogin() {
        when(userService.authenticateUser("user", "password")).thenReturn("mockJWT");

        String token = userController.login("user", "password");

        assertEquals("mockJWT", token);
        verify(userService).authenticateUser("user", "password");
    }
}