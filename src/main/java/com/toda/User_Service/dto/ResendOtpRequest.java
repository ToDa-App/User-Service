package com.toda.User_Service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema(description = "Request to resend OTP code")
public class ResendOtpRequest {
    @Schema(description = "User email", example = "user@example.com")
    @Email(message = "Invalid email format")
    @NotBlank(message = "Email is required")
    private String email;
}
