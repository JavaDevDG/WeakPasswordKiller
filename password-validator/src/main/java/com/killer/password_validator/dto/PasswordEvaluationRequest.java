package com.killer.password_validator.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

// NOTE: username & email are optional (used only to check the password does not embed them);
// password stays required.

@Data
public class PasswordEvaluationRequest {
    private String username;

    @Email(message = "Email should be valid")
    private String email;

    @NotBlank(message = "Password cannot be empty")
    @Size(max = 256, message = "Password must not exceed 256 characters")
    private String password;
}
