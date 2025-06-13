package com.toda.User_Service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Schema(description = "Authentication response containing access and refresh tokens")
public class AuthResponse {
    @Schema(description = "JWT token", example = "eyJhbGciOiJIUzI1...")
    private String token;
    @Schema(description = "Refresh token", example = "d2ViLXNlc3Npb24tdG9rZW4=")
    private String refreshToken;
}
