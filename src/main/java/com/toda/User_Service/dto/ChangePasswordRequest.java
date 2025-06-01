package com.toda.User_Service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema(description = "Request to change user password")
public class ChangePasswordRequest {
    @NotBlank(message = "currentPassword must not be blank")
    @Schema(description = "Current password", example = "OldPass@123")
    private String currentPassword;
    @NotBlank(message = "newPassword must not be blank")
    @Schema(description = "New password", example = "NewPass@123")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,}$",
            message = "Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 digit, 1 special character, and be at least 8 characters long")
    private String newPassword;
    @NotBlank(message = "Confirm password must not be blank")
    @Schema(description = "Confirm new password", example = "NewPass@123")
    private String confirmPassword;
}
