package com.toda.User_Service.service;

import com.toda.User_Service.dto.*;
import com.toda.User_Service.entity.User;
import org.springframework.web.multipart.MultipartFile;

public interface UserService {
    void register(RegisterRequest request);
    void activate(ActivateAccountRequest request);
    void resendOtp(ResendOtpRequest request);
    AuthResponse login(LoginRequest request);
    String generateSixDigitOtp();
    void sendResetCode(ForgetPasswordRequest request);
    void logout(String token);
    void changePassword(String email, ChangePasswordRequest request);
    void resetPassword(ResetPasswordRequest request);
    AuthResponse refreshToken(RefreshTokenRequest request);
    UserProfileResponse getProfile(String email);
    void updateProfile(User user, MultipartFile image, String nickname);
    void deleteUserAccount(String email);
}
