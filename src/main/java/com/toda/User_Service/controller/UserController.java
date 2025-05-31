package com.toda.User_Service.controller;

import com.toda.User_Service.dto.ChangePasswordRequest;
import com.toda.User_Service.dto.ForgetPasswordRequest;
import com.toda.User_Service.dto.ResetPasswordRequest;
import com.toda.User_Service.entity.User;
import com.toda.User_Service.exception.ApiGenericResponse;
import com.toda.User_Service.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    @PostMapping("/logout")
    public ResponseEntity<ApiGenericResponse<Object>> logout(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "");
        userService.logout(token);
        return ResponseEntity.ok(ApiGenericResponse.success("Logged out successfully", null));
    }
    @PostMapping("/change-password")
    public ResponseEntity<ApiGenericResponse<Object>> changePassword(
            @AuthenticationPrincipal User user,
            @RequestBody @Valid ChangePasswordRequest request) {
        userService.changePassword(user.getEmail(), request);
        return ResponseEntity.ok(ApiGenericResponse.success("Password changed successfully", null));
    }
    @PostMapping("/forget-password")
    public ResponseEntity<ApiGenericResponse<Object>> forgetPassword(@Valid @RequestBody ForgetPasswordRequest request) {
        userService.sendResetCode(request);
        return ResponseEntity.ok(ApiGenericResponse.success("Reset code sent to email", null));
    }
    @PostMapping("/reset-password")
    public ResponseEntity<ApiGenericResponse<Object>> resetPassword(@RequestBody @Valid ResetPasswordRequest request) {
        userService.resetPassword(request);
        return ResponseEntity.ok(ApiGenericResponse.success("Password reset successfully", null));
    }

}
