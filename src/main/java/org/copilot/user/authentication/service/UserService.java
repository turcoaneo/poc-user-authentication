package org.copilot.user.authentication.service;

import lombok.RequiredArgsConstructor;
import org.copilot.user.authentication.model.dto.UserDTO;
import org.copilot.user.authentication.model.entity.Role;
import org.copilot.user.authentication.model.entity.User;
import org.copilot.user.authentication.repository.UserRepository;
import org.copilot.user.authentication.service.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public UserDTO saveUser(UserDTO userDTO) {
        String password = passwordEncoder.encode(userDTO.getPassword());
        User user = new User(null, userDTO.getUsername(), password, Role.valueOf(userDTO.getRole()));
        User savedUser = userRepository.save(user);
        return new UserDTO(savedUser);
    }

    public String authenticateUser(String username, String rawPassword) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            if (passwordEncoder.matches(rawPassword, user.getPassword())) {
                return JwtUtil.generateToken(user.getRole().name()); // Return JWT token
            }
        }
        return null;
    }

    public UserDTO findByUsername(String username) {
        Optional<User> byUsername = userRepository.findByUsername(username);
        return new UserDTO(byUsername.orElse(new User()));
    }
}