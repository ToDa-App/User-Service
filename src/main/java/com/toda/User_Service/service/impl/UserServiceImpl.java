package com.toda.User_Service.service.impl;

import com.toda.User_Service.dto.ActivateAccountRequest;
import com.toda.User_Service.dto.AuthResponse;
import com.toda.User_Service.dto.LoginRequest;
import com.toda.User_Service.dto.RegisterRequest;
import com.toda.User_Service.entity.Otp;
import com.toda.User_Service.entity.User;
import com.toda.User_Service.repository.OtpRepository;
import com.toda.User_Service.repository.UserRepository;
import com.toda.User_Service.security.JwtUtil;
import com.toda.User_Service.service.EmailService;
import com.toda.User_Service.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final OtpRepository otpRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final JwtUtil jwtUtil;
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
        LocalDateTime expiry = LocalDateTime.now().plusMinutes(1);
        Otp otp = Otp.builder()
                .otp(otpCode)
                .expirationTime(expiry)
                .user(user)
                .build();
        otpRepository.save(otp);
        emailService.sendOtpToEmail(user.getEmail(), otpCode);
    }
    public String generateSixDigitOtp() {
        int otp = (int)(Math.random() * 900000) + 100000;
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
    public void resendOtp(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.isEnabled()) {
            throw new RuntimeException("Account is already activated");
        }
        Optional<Otp> latestOtpOpt = otpRepository.findTopByUser_EmailOrderByExpirationTimeDesc(email);
        if (latestOtpOpt.isPresent()) {
            Otp latestOtp = latestOtpOpt.get();
            LocalDateTime oneMinuteAgo = LocalDateTime.now().minusMinutes(1);
            if (latestOtp.getCreatedAt().isAfter(oneMinuteAgo)) {
                throw new RuntimeException("You can request a new OTP only after 1 minute");
            }
        }
        String newOtp = generateSixDigitOtp();
        LocalDateTime expiry = LocalDateTime.now().plusMinutes(1);
        Otp otp = Otp.builder()
                .otp(newOtp)
                .expirationTime(expiry)
                .createdAt(LocalDateTime.now())
                .user(user)
                .build();
        otpRepository.save(otp);
        emailService.sendOtpToEmail(email, newOtp);
    }
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email"));
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "password is incorrect");
        }
        String token = jwtUtil.generateToken(user.getEmail());
        return new AuthResponse(token);
    }
}
