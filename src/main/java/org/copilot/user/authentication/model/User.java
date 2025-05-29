package org.copilot.user.authentication.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "user_account")
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;
}
