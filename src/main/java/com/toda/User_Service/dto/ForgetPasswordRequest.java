package com.toda.User_Service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Schema(description = "Request to initiate password reset")
public class ForgetPasswordRequest {
    @Email
    @NotBlank(message = "email must be not blank")
    @Schema(description = "User email", example = "user@example.com")
    private String email;
}
