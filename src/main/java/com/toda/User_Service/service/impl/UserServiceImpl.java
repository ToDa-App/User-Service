package com.toda.User_Service.service.impl;

import com.toda.User_Service.dto.ActivateAccountRequest;
import com.toda.User_Service.dto.RegisterRequest;
import com.toda.User_Service.entity.Otp;
import com.toda.User_Service.entity.User;
import com.toda.User_Service.repository.OtpRepository;
import com.toda.User_Service.repository.UserRepository;
import com.toda.User_Service.service.EmailService;
import com.toda.User_Service.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final OtpRepository otpRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    @Override
    public void register(RegisterRequest request) {
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Passwords do not match");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email is already Exist");
        }
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .enabled(false)
                .build();
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);
        String otpCode = generateSixDigitOtp();
        LocalDateTime expiry = LocalDateTime.now().plusMinutes(10);
        Otp otp = Otp.builder()
                .otp(otpCode)
                .expirationTime(expiry)
                .user(user)
                .build();
        otpRepository.save(otp);
        emailService.sendOtpToEmail(user.getEmail(), otpCode);
    }
    public String generateSixDigitOtp() {
        int otp = (int)(Math.random() * 900000) + 100000; // يولد رقم من 100000 لـ 999999
        return String.valueOf(otp);
    }
    @Override
    public void activate(ActivateAccountRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        if (user.isEnabled()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Account is already activated");
        }
        Otp latestOtp = otpRepository
                .findTopByUser_EmailOrderByExpirationTimeDesc(user.getEmail())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No OTP found"));
        if (latestOtp.getExpirationTime().isBefore(LocalDateTime.now())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "OTP is expired");
        }
        if (!latestOtp.getOtp().equals(request.getOtp())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid OTP");
        }
        user.setEnabled(true);
        userRepository.save(user);
    }
}
