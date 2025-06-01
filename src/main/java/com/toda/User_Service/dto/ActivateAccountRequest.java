package com.toda.User_Service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema(description = "Request to activate an account using OTP")
public class ActivateAccountRequest {
    @NotBlank(message = "Email must not be blank")
    @Email(message = "Email format is invalid")
    @Schema(description = "User email", example = "user@example.com")
    private String email;
    @NotBlank
    @Schema(description = "One-time OTP", example = "123456")
    private String otp;
}
