package com.toda.User_Service.controller;

import com.toda.User_Service.dto.*;
import com.toda.User_Service.exception.ApiGenericResponse;
import com.toda.User_Service.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

public class AuthControllerTest {
    @Mock
    private UserService userService;
    @InjectMocks
    private AuthController authController;
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }
    @Test
    void testRegister() {
        RegisterRequest request = new RegisterRequest();
        doNothing().when(userService).register(request);
        ResponseEntity<ApiGenericResponse<Object>> response = authController.register(request);
        assertEquals(200, response.getStatusCodeValue());
        assertEquals("User registered successfully", response.getBody().getMessage());
        assertNull(response.getBody().getData());
    }
    @Test
    void testActivate() {
        ActivateAccountRequest request = new ActivateAccountRequest();
        doNothing().when(userService).activate(request);
        ResponseEntity<ApiGenericResponse<Object>> response = authController.activate(request);
        assertEquals(200, response.getStatusCodeValue());
        assertEquals("Account activated successfully.", response.getBody().getMessage());
        assertNull(response.getBody().getData());
    }
    @Test
    void testResendOtp() {
        ResendOtpRequest request = new ResendOtpRequest();
        doNothing().when(userService).resendOtp(request);
        ResponseEntity<ApiGenericResponse<Object>> response = authController.resendOtp(request);
        assertEquals(200, response.getStatusCodeValue());
        assertEquals("OTP resent successfully", response.getBody().getMessage());
        assertNull(response.getBody().getData());
    }
    @Test
    void testLogin() {
        LoginRequest request = new LoginRequest();
        AuthResponse expectedResponse = AuthResponse.builder()
                .token("access-token")
                .refreshToken("refresh-token")
                .build();
        when(userService.login(request)).thenReturn(expectedResponse);
        ResponseEntity<ApiGenericResponse<AuthResponse>> response = authController.signIn(request);
        assertEquals(200, response.getStatusCodeValue());
        assertEquals("User logged in successfully", response.getBody().getMessage());
        assertEquals(expectedResponse, response.getBody().getData());
    }
    @Test
    void testRefreshToken() {
        RefreshTokenRequest request = new RefreshTokenRequest();
        AuthResponse expectedResponse = AuthResponse.builder()
                .token("new-access-token")
                .refreshToken("refresh-token")
                .build();
        when(userService.refreshToken(request)).thenReturn(expectedResponse);
        ResponseEntity<ApiGenericResponse<AuthResponse>> response = authController.refreshToken(request);
        assertEquals(200, response.getStatusCodeValue());
        assertEquals("Token refreshed successfully", response.getBody().getMessage());
        assertEquals(expectedResponse, response.getBody().getData());
    }
}
