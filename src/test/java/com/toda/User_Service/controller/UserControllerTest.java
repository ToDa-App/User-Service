package com.toda.User_Service.controller;

import com.toda.User_Service.dto.ChangePasswordRequest;
import com.toda.User_Service.dto.ForgetPasswordRequest;
import com.toda.User_Service.dto.ResetPasswordRequest;
import com.toda.User_Service.dto.UserProfileResponse;
import com.toda.User_Service.entity.User;
import com.toda.User_Service.exception.ApiGenericResponse;
import com.toda.User_Service.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserControllerTest {
    @InjectMocks
    private UserController userController;
    @Mock
    private UserService userService;
    @Mock
    private HttpServletRequest request;
    @Test
    void logout_ShouldReturnSuccess() {
        String token = "test-token";
        String header = "Bearer " + token;
        ResponseEntity<ApiGenericResponse<Object>> response =
                userController.logout(header);
        assertEquals(200, response.getStatusCodeValue());
        assertNotNull(response.getBody());
        assertEquals("Logged out successfully", response.getBody().getMessage());
        verify(userService).logout(token);
    }
    @Test
    void changePassword_ShouldSucceed() {
        User user = new User();
        user.setEmail("user@example.com");
        ChangePasswordRequest request = new ChangePasswordRequest();
        request.setCurrentPassword("oldPass123");
        request.setNewPassword("newPass456");
        ResponseEntity<ApiGenericResponse<Object>> response =
                userController.changePassword(user, request);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Password changed successfully", response.getBody().getMessage());
        verify(userService).changePassword(eq("user@example.com"), eq(request));
    }
    @Test
    void forgetPassword_ShouldReturnSuccess() {
        ForgetPasswordRequest request = new ForgetPasswordRequest();
        request.setEmail("user@example.com");
        ResponseEntity<ApiGenericResponse<Object>> response = userController.forgetPassword(request);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Reset code sent to email", response.getBody().getMessage());
        verify(userService).sendResetCode(eq(request));
    }
    @Test
    void resetPassword_ShouldReturnSuccess() {
        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setEmail("user@example.com");
        request.setResetCode("123456");
        request.setNewPassword("newSecurePassword");
        ResponseEntity<ApiGenericResponse<Object>> response = userController.resetPassword(request);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Password reset successfully", response.getBody().getMessage());
        assertNull(response.getBody().getData());
        verify(userService).resetPassword(request);
    }
    @Test
    void getProfile_ShouldReturnUserProfile() {
        String email = "user@example.com";
        User user = User.builder().email(email).build();
        UserProfileResponse profile = new UserProfileResponse("nickname", "image-url");
        when(userService.getProfile(email)).thenReturn(profile);
        ResponseEntity<ApiGenericResponse<UserProfileResponse>> response = userController.getProfile(user);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Profile retrieved successfully", response.getBody().getMessage());
        assertEquals(profile, response.getBody().getData());
        verify(userService).getProfile(email);
    }
    @Test
    void deleteUserAccount_ShouldReturnSuccess() {
        String email = "user@example.com";
        User user = User.builder().email(email).build();
        ResponseEntity<ApiGenericResponse<Map<String, String>>> response = userController.deleteUserAccount(user);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("User account deleted successfully", response.getBody().getMessage());
        assertNull(response.getBody().getData());
        verify(userService).deleteUserAccount(email);
    }
    @Test
    void updateProfile_ShouldUpdateSuccessfully() throws Exception {
        User user = User.builder()
                .email("user@example.com")
                .nickname("oldNick")
                .profileImageUrl("old-url")
                .build();
        String newNickname = "newNick";
        MockMultipartFile image = new MockMultipartFile("image", "test.jpg", "image/jpeg", "test".getBytes());
        doAnswer(invocation -> {
            user.setNickname(newNickname);
            user.setProfileImageUrl("new-url");
            return null;
        }).when(userService).updateProfile(user, image, newNickname);
        ResponseEntity<ApiGenericResponse<Map<String, String>>> response =
                userController.updateProfile(user, image, newNickname);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        Map<String, String> data = response.getBody().getData();
        assertEquals("newNick", data.get("nickname"));
        assertEquals("new-url", data.get("profileImageUrl"));
        verify(userService).updateProfile(user, image, newNickname);
    }


}
