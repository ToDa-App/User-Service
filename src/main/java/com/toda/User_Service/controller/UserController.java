package com.toda.User_Service.controller;

import com.toda.User_Service.dto.*;
import com.toda.User_Service.entity.User;
import com.toda.User_Service.exception.ApiGenericResponse;
import com.toda.User_Service.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.util.Map;
@RestController
@RequestMapping("/api/user")
@SecurityRequirement(name = "bearerAuth")
@RequiredArgsConstructor
@Tag(name = "User Controller", description = "Manage user profile, password, and account operations")
public class UserController {
    private final UserService userService;
    @Operation(summary = "Logout user", description = "Logs out the currently authenticated user and invalidates the access token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User logged out successfully"),
            @ApiResponse(responseCode = "401", description = "Invalid or missing token", content = @Content)
    })
    @PostMapping("/logout")
    public ResponseEntity<ApiGenericResponse<Object>> logout(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "");
        userService.logout(token);
        return ResponseEntity.ok(ApiGenericResponse.success("Logged out successfully", null));
    }
    @Operation(summary = "Change password", description = "Changes the password for the currently authenticated user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password changed successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid input", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content)
    })
    @PostMapping("/change-password")
    public ResponseEntity<ApiGenericResponse<Object>> changePassword(
            @AuthenticationPrincipal User user,
            @RequestBody @Valid ChangePasswordRequest request) {
        userService.changePassword(user.getEmail(), request);
        return ResponseEntity.ok(ApiGenericResponse.success("Password changed successfully", null));
    }
    @Operation(summary = "Request password reset", description = "Sends a password reset code to the user's email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Reset code sent successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid email", content = @Content)
    })
    @PostMapping("/forget-password")
    public ResponseEntity<ApiGenericResponse<Object>> forgetPassword(@Valid @RequestBody ForgetPasswordRequest request) {
        userService.sendResetCode(request);
        return ResponseEntity.ok(ApiGenericResponse.success("Reset code sent to email", null));
    }
    @Operation(summary = "Reset password", description = "Resets the user's password using the reset code sent to email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password reset successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid reset code or password", content = @Content)
    })
    @PostMapping("/reset-password")
    public ResponseEntity<ApiGenericResponse<Object>> resetPassword(@RequestBody @Valid ResetPasswordRequest request) {
        userService.resetPassword(request);
        return ResponseEntity.ok(ApiGenericResponse.success("Password reset successfully", null));
    }
    @Operation(summary = "Get user profile", description = "Retrieves the profile of the currently authenticated user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Profile retrieved successfully",
                    content = @Content(schema = @Schema(implementation = UserProfileResponse.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content)
    })
    @GetMapping("/profile")
    public ResponseEntity<ApiGenericResponse<UserProfileResponse>> getProfile(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok(ApiGenericResponse.success("Profile retrieved successfully", userService.getProfile(user.getEmail())));

    }
    @Operation(summary = "Update user profile", description = "Updates the user's nickname and/or profile image")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Profile updated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid file format or input", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content)
    })
    @PutMapping("/profile")
    public ResponseEntity<ApiGenericResponse<Map<String, String>>> updateProfile(
            @AuthenticationPrincipal User user,
            @RequestPart(required = false) MultipartFile image,
            @RequestPart(required = false) String nickname) {
        userService.updateProfile(user, image, nickname);
        Map<String, String> data = Map.of(
                "nickname", user.getNickname(),
                "profileImageUrl", user.getProfileImageUrl()
        );
        return ResponseEntity.ok(ApiGenericResponse.success("Profile updated successfully", data));
    }
    @Operation(summary = "Delete user account", description = "Deletes the account of the currently authenticated user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Account deleted successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content)
    })
    @DeleteMapping
    public ResponseEntity<ApiGenericResponse<Map<String, String>>> deleteUserAccount(@AuthenticationPrincipal User user) {
        userService.deleteUserAccount(user.getEmail());
        return ResponseEntity.ok(ApiGenericResponse.success("User account deleted successfully", null));
    }
}
