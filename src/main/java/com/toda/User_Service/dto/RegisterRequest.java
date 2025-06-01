package com.toda.User_Service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema(description = "Request to register new user")
public class RegisterRequest {
    @NotBlank(message = "Email must not be blank")
    @Email(message = "Email format is invalid")
    @Schema(description = "User's email", example = "user@example.com", requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;
    @NotBlank(message = "Password must not be blank")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,}$",
            message = "Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 digit, 1 special character, and be at least 8 characters long"
    )
    @Schema(description = "Password (must meet complexity requirements)", example = "Pass@1234", requiredMode = Schema.RequiredMode.REQUIRED)
    private String password;
    @Schema(description = "Confirmation of the password", example = "Pass@1234", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "Confirm password must not be blank")
    private String confirmPassword;
}
