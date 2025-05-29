package com.toda.User_Service.service;

import com.toda.User_Service.dto.ActivateAccountRequest;
import com.toda.User_Service.dto.AuthResponse;
import com.toda.User_Service.dto.LoginRequest;
import com.toda.User_Service.dto.RegisterRequest;

public interface UserService {
    void register(RegisterRequest request);
    void activate(ActivateAccountRequest request);
    void resendOtp(String email);
    AuthResponse login(LoginRequest request);
}
