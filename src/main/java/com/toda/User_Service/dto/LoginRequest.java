package com.toda.User_Service.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import io.swagger.v3.oas.annotations.media.Schema;
@Getter
@Setter
@Schema(description = "Request to login user")
public class LoginRequest {
    @NotBlank(message = "Email is required")
    @Schema(description = "Email for login", example = "user@example.com", requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;
    @NotBlank(message = "Password is required")
    @Schema(description = "User's password", example = "Pass@1234", requiredMode = Schema.RequiredMode.REQUIRED)
    private String password;
}
