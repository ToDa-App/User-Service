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
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;


import java.time.LocalDateTime;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)

public class UserServiceTest {
    @InjectMocks
    private UserServiceImpl userService;
    @Mock
    private UserRepository userRepository;
    @Mock
    private OtpRepository otpRepository;
    @Mock
    private JwtRepository jwtRepository;
    @Mock
    private EmailService emailService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtUtil jwtUtil;
    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
    }
    @Test
    void testRegister_Success() {
        RegisterRequest req = new RegisterRequest();
        req.setEmail("test@example.com");
        req.setPassword("pass");
        req.setConfirmPassword("pass");

        when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
        when(passwordEncoder.encode("pass")).thenReturn("encodedPass");
        when(userRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        userService.register(req);

        verify(userRepository).save(any());
        verify(otpRepository).save(any());
        verify(emailService).sendOtpToEmail(eq("test@example.com"), anyString());
    }
    @Test
    void testRegister_PasswordMismatch() {
        RegisterRequest req = new RegisterRequest();
        req.setEmail("test@example.com");
        req.setPassword("pass1");
        req.setConfirmPassword("pass2");

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> {
            userService.register(req);
        });

        assertEquals("Passwords do not match", ex.getMessage());
        verify(userRepository, never()).save(any());
    }
    @Test
    void testRegister_EmailExists() {
        RegisterRequest req = new RegisterRequest();
        req.setEmail("test@example.com");
        req.setPassword("pass");
        req.setConfirmPassword("pass");

        when(userRepository.existsByEmail("test@example.com")).thenReturn(true);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> {
            userService.register(req);
        });

        assertEquals("Email is already Exist", ex.getMessage());
        verify(userRepository, never()).save(any());
    }
    @Test
    void testActivate_Success() {
        String email = "user@example.com";
        String otpCode = "123456";
        User user = User.builder().email(email).enabled(false).build();
        Otp otp = Otp.builder().otp(otpCode).expirationTime(LocalDateTime.now().plusMinutes(1)).user(user).build();
        ActivateAccountRequest req = new ActivateAccountRequest();
        req.setEmail(email);
        req.setOtp(otpCode);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(otpRepository.findTopByUser_EmailOrderByExpirationTimeDesc(email)).thenReturn(Optional.of(otp));
        when(userRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        userService.activate(req);

        assertTrue(user.isEnabled());
        verify(userRepository).save(user);
    }
    @Test
    void testActivate_UserNotFound() {
        ActivateAccountRequest req = new ActivateAccountRequest();
        req.setEmail("noone@example.com");
        req.setOtp("123456");

        when(userRepository.findByEmail("noone@example.com")).thenReturn(Optional.empty());

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> {
            userService.activate(req);
        });
        assertEquals("404 NOT_FOUND \"User not found\"", ex.getMessage());
    }
    @Test
    void testActivate_AlreadyActivated() {
        User user = User.builder().enabled(true).build();
        ActivateAccountRequest req = new ActivateAccountRequest();
        req.setEmail("test@example.com");
        req.setOtp("123456");

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> {
            userService.activate(req);
        });
        assertEquals("400 BAD_REQUEST \"Account is already activated\"", ex.getMessage());
    }
    @Test
    void testActivate_OtpExpired() {
        User user = User.builder().enabled(false).email("test@example.com").build();
        Otp otp = Otp.builder().otp("123456").expirationTime(LocalDateTime.now().minusMinutes(1)).user(user).build();
        ActivateAccountRequest req = new ActivateAccountRequest();
        req.setEmail("test@example.com");
        req.setOtp("123456");

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
        when(otpRepository.findTopByUser_EmailOrderByExpirationTimeDesc("test@example.com")).thenReturn(Optional.of(otp));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> {
            userService.activate(req);
        });

        assertEquals("400 BAD_REQUEST \"OTP is expired\"", ex.getMessage());
    }
    @Test
    void testActivate_InvalidOtp() {
        User user = User.builder().enabled(false).email("test@example.com").build();
        Otp otp = Otp.builder().otp("654321").expirationTime(LocalDateTime.now().plusMinutes(1)).user(user).build();
        ActivateAccountRequest req = new ActivateAccountRequest();
        req.setEmail("test@example.com");
        req.setOtp("123456");

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
        when(otpRepository.findTopByUser_EmailOrderByExpirationTimeDesc("test@example.com")).thenReturn(Optional.of(otp));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> {
            userService.activate(req);
        });

        assertEquals("400 BAD_REQUEST \"Invalid OTP\"", ex.getMessage());
    }
    @Test
    void testResendOtp_Success() {
        User user = User.builder().enabled(false).email("test@example.com").build();
        ResendOtpRequest req = new ResendOtpRequest();
        req.setEmail("test@example.com");

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
        when(otpRepository.findTopByUser_EmailOrderByExpirationTimeDesc("test@example.com")).thenReturn(Optional.empty());
        doNothing().when(emailService).sendOtpToEmail(anyString(), anyString());

        userService.resendOtp(req);

        verify(otpRepository).save(any());
        verify(emailService).sendOtpToEmail(eq("test@example.com"), anyString());
    }
    @Test
    void testResendOtp_RequestTooSoon() {
        User user = User.builder().enabled(false).email("test@example.com").build();
        Otp otp = Otp.builder().createdAt(LocalDateTime.now().minusSeconds(30)).user(user).build();
        ResendOtpRequest req = new ResendOtpRequest();
        req.setEmail("test@example.com");

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
        when(otpRepository.findTopByUser_EmailOrderByExpirationTimeDesc("test@example.com")).thenReturn(Optional.of(otp));

        RuntimeException ex = assertThrows(RuntimeException.class, () -> {
            userService.resendOtp(req);
        });

        assertEquals("You can request a new OTP only after 1 minute", ex.getMessage());
    }
    @Test
    void testLogin_Success() {
        User user = User.builder()
                .email("test@example.com")
                .enabled(true)
                .password("encodedPass")
                .build();

        LoginRequest req = new LoginRequest();
        req.setEmail("test@example.com");
        req.setPassword("pass");

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("pass", "encodedPass")).thenReturn(true);
        when(jwtUtil.generateToken("test@example.com", 1)).thenReturn("accessToken");
        when(jwtUtil.generateToken("test@example.com", 168)).thenReturn("refreshToken");
        when(jwtRepository.saveAll(anyList())).thenReturn(null);

        AuthResponse res = userService.login(req);

        assertEquals("accessToken", res.getToken());
        assertEquals("refreshToken", res.getRefreshToken());
    }
    @Test
    void testLogin_UserNotFound() {
        LoginRequest req = new LoginRequest();
        req.setEmail("noone@example.com");
        req.setPassword("pass");

        when(userRepository.findByEmail("noone@example.com")).thenReturn(Optional.empty());

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> {
            userService.login(req);
        });

        assertEquals("404 NOT_FOUND \"User not found\"", ex.getMessage());
    }
    @Test
    void testLogin_IncorrectPassword() {
        User user = User.builder().email("test@example.com").password("encodedPass").enabled(true).build();

        LoginRequest req = new LoginRequest();
        req.setEmail("test@example.com");
        req.setPassword("wrongPass");

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrongPass", "encodedPass")).thenReturn(false);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> {
            userService.login(req);
        });

        assertEquals("400 BAD_REQUEST \"Incorrect password\"", ex.getMessage());
    }
    @Test
    void testLogin_AccountNotActivated() {
        User user = User.builder().email("test@example.com").password("encodedPass").enabled(false).build();

        LoginRequest req = new LoginRequest();
        req.setEmail("test@example.com");
        req.setPassword("pass");

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> {
            userService.login(req);
        });

        assertEquals("400 BAD_REQUEST \"Account is not activated yet\"", ex.getMessage());
    }
    @Test
    void testLogout_TokenNotFound() {
        when(jwtRepository.findByToken("token")).thenReturn(Optional.empty());

        RuntimeException ex = assertThrows(RuntimeException.class, () -> {
            userService.logout("token");
        });

        assertEquals("Token not found", ex.getMessage());
    }
    @Test
    void testChangePassword_Success() {
        String email = "test@example.com";
        String oldEncodedPass = "oldEncodedPass";
        String oldRawPass = "OldP@ss1";
        String newRawPass = "NewP@ss1";
        String newEncodedPass = "newEncodedPass";

        User user = new User();
        user.setEmail(email);
        user.setPassword(oldEncodedPass);

        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setCurrentPassword(oldRawPass);
        req.setNewPassword(newRawPass);
        req.setConfirmPassword(newRawPass);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(oldRawPass, oldEncodedPass)).thenReturn(true);
        when(passwordEncoder.encode(newRawPass)).thenReturn(newEncodedPass);
        when(userRepository.save(user)).thenReturn(user);

        userService.changePassword(email,req);

        assertEquals(newEncodedPass, user.getPassword());
        verify(userRepository).save(user);
    }
}
