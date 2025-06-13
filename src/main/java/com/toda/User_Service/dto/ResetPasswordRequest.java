package com.toda.User_Service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Schema(description = "Request to reset password using reset code")
public class ResetPasswordRequest {
    @NotBlank(message = "email must not be blank")
    @Email
    @Schema(description = "User's email", example = "user@example.com", requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;
    @Schema(description = "Reset code sent to email", example = "123456", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "reset code must not be blank")
    private String resetCode;
    @Schema(description = "New password", example = "NewPass@1234", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "Password must not be blank")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,}$",
            message = "Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 digit, 1 special character, and be at least 8 characters long"
    )
    private String newPassword;
    @Schema(description = "Confirm new password", example = "NewPass@1234", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "Confirm password must not be blank")
    private String confirmPassword;
}
