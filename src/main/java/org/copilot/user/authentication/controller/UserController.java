package org.copilot.user.authentication.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.copilot.user.authentication.model.dto.UserDTO;
import org.copilot.user.authentication.service.UserService;
import org.springframework.web.bind.annotation.*;

@Tag(name = "User Management", description = "User authentication and management API")
@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @Operation(summary = "Register a new user")
    @PostMapping("/register")
    public UserDTO registerUser(@RequestBody UserDTO user) {
        return userService.saveUser(user);
    }

    @Operation(summary = "Fetch a user by username")
    @GetMapping("/{username}")
    public UserDTO getUser(@PathVariable String username) {
        return userService.findByUsername(username);
    }

    @Operation(summary = "Authenticate user and return JWT")
    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        return userService.authenticateUser(username, password);
    }
}