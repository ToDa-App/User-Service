package com.toda.User_Service.controller;

import com.toda.User_Service.dto.*;
import com.toda.User_Service.exception.ApiGenericResponse;
import com.toda.User_Service.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication APIs", description = "Endpoints for user registration, activation, login, and token management")
public class AuthController {
    private final UserService userService;
    @Operation(summary = "Register a new user", description = "Creates a new user account and sends an OTP for verification")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User registered successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid input or email already exists")
    })
    @PostMapping("/register")
    public ResponseEntity<ApiGenericResponse<Object>> register(@RequestBody @Valid RegisterRequest request) {
        userService.register(request);
        return ResponseEntity.ok(ApiGenericResponse.success("User registered successfully", null));
    }
    @Operation(summary = "Activate account", description = "Activates user account using OTP code sent to email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Account activated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid OTP or email not found")
    })
    @PostMapping("/activate")
    public ResponseEntity<ApiGenericResponse<Object>> activate(@RequestBody @Valid ActivateAccountRequest request) {
        userService.activate(request);
        return ResponseEntity.ok(ApiGenericResponse.success("Account activated successfully.", null));
    }
    @Operation(summary = "Resend OTP", description = "Resends OTP code to the user's email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OTP resent successfully"),
            @ApiResponse(responseCode = "404", description = "Email not found or already activated")
    })
    @PostMapping("/resend-otp")
    public ResponseEntity<ApiGenericResponse<Object>> resendOtp(@Valid @RequestBody ResendOtpRequest request) {
        userService.resendOtp(request);
        return ResponseEntity.ok(ApiGenericResponse.success("OTP resent successfully", null));
    }
    @Operation(summary = "User login", description = "Authenticates user and returns access and refresh tokens")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User logged in successfully"),
            @ApiResponse(responseCode = "401", description = "Invalid credentials or account not activated")
    })
    @PostMapping("/login")
    public ResponseEntity<ApiGenericResponse<AuthResponse>> signIn(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = userService.login(request);
        return ResponseEntity.ok(ApiGenericResponse.success("User logged in successfully", response));
    }
    @Operation(summary = "Refresh access token", description = "Generates a new access token using a valid refresh token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token refreshed successfully"),
            @ApiResponse(responseCode = "401", description = "Invalid or expired refresh token")
    })
    @PostMapping("/refresh")
    public ResponseEntity<ApiGenericResponse<AuthResponse>> refreshToken(@RequestBody RefreshTokenRequest request) {
        AuthResponse authResponse = userService.refreshToken(request);
        return ResponseEntity.ok(ApiGenericResponse.success("Token refreshed successfully", authResponse));
    }

}
