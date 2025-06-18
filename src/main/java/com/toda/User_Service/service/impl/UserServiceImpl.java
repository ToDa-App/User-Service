package com.toda.User_Service.service.impl;

import com.toda.User_Service.dto.*;
import com.toda.User_Service.entity.JwtToken;
import com.toda.User_Service.entity.Otp;
import com.toda.User_Service.entity.ResetPasswordToken;
import com.toda.User_Service.entity.User;
import com.toda.User_Service.repository.JwtRepository;
import com.toda.User_Service.repository.OtpRepository;
import com.toda.User_Service.repository.ResetPasswordTokenRepository;
import com.toda.User_Service.repository.UserRepository;
import com.toda.User_Service.security.JwtUtil;
import com.toda.User_Service.service.EmailService;
import com.toda.User_Service.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final OtpRepository otpRepository;
    private final JwtRepository jwtRepository;
    private final PasswordEncoder passwordEncoder;
    private final ResetPasswordTokenRepository resetPasswordTokenRepository;
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
    @Override
    public String generateSixDigitOtp() {
        int otp = (int) (Math.random() * 900000) + 100000;
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
    @Override
    public void resendOtp(ResendOtpRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.isEnabled()) {
            throw new RuntimeException("Account is already activated");
        }
        Optional<Otp> latestOtpOpt = otpRepository.findTopByUser_EmailOrderByExpirationTimeDesc(request.getEmail());
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
        emailService.sendOtpToEmail(request.getEmail(), newOtp);
    }
    @Override
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> {
                    Map<String, String> errors = new HashMap<>();
                    errors.put("email", "Email not found");
                    throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Email not found", new Throwable(errors.toString()));
                });
        if (!user.isEnabled()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Account is not activated. Please check your email.");
        }
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            Map<String, String> errors = new HashMap<>();
            errors.put("password", "Password is incorrect");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password is incorrect", new Throwable(errors.toString()));
        }
        String accessToken = jwtUtil.generateToken(user.getEmail(), 1);
        String refreshToken = jwtUtil.generateToken(user.getEmail(), 7 * 24);
        jwtRepository.saveAll(List.of(
                JwtToken.builder().token(accessToken).tokenType("Bearer").createdAt(LocalDateTime.now())
                        .expirationDate(LocalDateTime.now().plusHours(1)).isRefreshToken(false).user(user).build(),
                JwtToken.builder().token(refreshToken).tokenType("Bearer").createdAt(LocalDateTime.now())
                        .expirationDate(LocalDateTime.now().plusDays(7)).isRefreshToken(true).user(user).build()
        ));
        return new AuthResponse(accessToken, refreshToken);
    }
    @Override
    public void sendResetCode(ForgetPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        String code = generateSixDigitOtp();
        LocalDateTime expiration = LocalDateTime.now().plusMinutes(5);
        ResetPasswordToken token = ResetPasswordToken.builder()
                .code(code)
                .createdAt(LocalDateTime.now())
                .expirationTime(expiration)
                .user(user)
                .build();
        resetPasswordTokenRepository.save(token);
        emailService.sendOtpToEmail(user.getEmail(), code);
    }
    @Override
    public void logout(String token) {
        JwtToken jwtToken = jwtRepository.findByToken(token)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Token not found"));

        jwtRepository.delete(jwtToken);
    }
    @Override
    public void changePassword(String email, ChangePasswordRequest request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Current password is incorrect");
        }

        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Passwords do not match");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }
    @Override
    public void resetPassword(ResetPasswordRequest request) {
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Passwords do not match");
        }
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        ResetPasswordToken token = resetPasswordTokenRepository
                .findTopByUserOrderByCreatedAtDesc(user)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Reset token not found"));
        if (token.getExpirationTime().isBefore(LocalDateTime.now())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token expired");
        }
        if (!token.getCode().equals(request.getResetCode())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid token");
        }
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }
    @Override
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();
        if (!jwtUtil.validateToken(refreshToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
        }
        String email = jwtUtil.getEmailFromToken(refreshToken);
        JwtToken token = jwtRepository.findByToken(refreshToken)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Refresh token not found"));
        if (!token.isRefreshToken() || token.getExpirationDate().isBefore(LocalDateTime.now())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token is expired or invalid");
        }
        String newAccessToken = jwtUtil.generateToken(email, 1);
        JwtToken newToken = JwtToken.builder()
                .token(newAccessToken)
                .tokenType("Bearer")
                .isRefreshToken(false)
                .user(token.getUser())
                .createdAt(LocalDateTime.now())
                .expirationDate(LocalDateTime.now().plusHours(1))
                .build();
        jwtRepository.save(newToken);
        return new AuthResponse(newAccessToken, refreshToken);
    }
    @Override
    public UserProfileResponse getProfile(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return new UserProfileResponse(
                user.getNickname(),
                user.getProfileImageUrl()
        );
    }
    @Override
    public void updateProfile(User user, MultipartFile image, String nickname) {
        if (nickname != null) {
            user.setNickname(nickname);
        }
        if (image != null && !image.isEmpty()) {
            try {
                String fileName = UUID.randomUUID() + "_" + image.getOriginalFilename();
                Path uploadPath = Paths.get("uploads");
                Files.createDirectories(uploadPath);
                Path filePath = uploadPath.resolve(fileName);
                Files.copy(image.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);
                String imageUrl = "/uploads/" + fileName;
                user.setProfileImageUrl(imageUrl);
            } catch (IOException e) {
                throw new RuntimeException("Failed to upload image", e);
            }
        }
        userRepository.save(user);
    }
    @Override
    public void deleteUserAccount(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
        userRepository.delete(user);
    }

}
