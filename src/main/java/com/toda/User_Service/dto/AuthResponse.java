package com.toda.User_Service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Authentication response containing access and refresh tokens")
public class AuthResponse {
    @Schema(description = "JWT token", example = "eyJhbGciOiJIUzI1...")
    private String token;
    @Schema(description = "Refresh token", example = "d2ViLXNlc3Npb24tdG9rZW4=")
    private String refreshToken;
}
