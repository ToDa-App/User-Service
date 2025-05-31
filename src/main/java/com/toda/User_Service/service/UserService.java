package com.toda.User_Service.service;

import com.toda.User_Service.dto.*;

public interface UserService {
    void register(RegisterRequest request);
    void activate(ActivateAccountRequest request);
    void resendOtp(String email);
    AuthResponse login(LoginRequest request);
    String generateSixDigitOtp();
    void sendResetCode(ForgetPasswordRequest request);
    void logout(String token);
    void changePassword(String email, ChangePasswordRequest request);
    void resetPassword(ResetPasswordRequest request);
    AuthResponse refreshToken(RefreshTokenRequest request);
}
