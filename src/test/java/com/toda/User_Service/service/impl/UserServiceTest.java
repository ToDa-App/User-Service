package com.toda.User_Service.service.impl;
import com.toda.User_Service.dto.*;
import com.toda.User_Service.entity.JwtToken;
import com.toda.User_Service.entity.Otp;
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;
@ExtendWith(MockitoExtension.class)
public class UserServiceTest {
    @Mock private UserRepository userRepository;
    @Mock private OtpRepository otpRepository;
    @Mock private JwtRepository jwtRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private ResetPasswordTokenRepository resetPasswordTokenRepository;
    @Mock private EmailService emailService;
    @Mock private JwtUtil jwtUtil;
    @InjectMocks
    private UserServiceImpl userService;
    @Test
    void testRegister_SuccessfulRegistration() {
        RegisterRequest request = new RegisterRequest();
        request.setEmail("test@example.com");
        request.setPassword("password123");
        request.setConfirmPassword("password123");
        when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encodedPassword");
        User user = new User();
        user.setEmail("test@example.com");
        when(userRepository.save(any(User.class))).thenReturn(user);
        userService.register(request);
        verify(userRepository).save(any(User.class));
        verify(otpRepository).save(any(Otp.class));
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
        LoginRequest request = new LoginRequest();
        request.setEmail("noone@example.com");
        request.setPassword("pass");
        when(userRepository.findByEmail("noone@example.com"))
                .thenReturn(Optional.empty());
        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
            userService.login(request);
        });
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        assertEquals("Invalid email", exception.getReason());
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

        assertEquals("400 BAD_REQUEST \"Password is incorrect\"", ex.getMessage());
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
        assertEquals("400 BAD_REQUEST \"Account is not activated. Please check your email.\"", ex.getMessage());
    }
    @Test
    void testLogout_Success() {
        String token = "validToken";
        JwtToken jwtToken = new JwtToken();
        jwtToken.setToken(token);
        when(jwtRepository.findByToken(token)).thenReturn(Optional.of(jwtToken));
        userService.logout(token);
        verify(jwtRepository).delete(jwtToken);
    }
    @Test
    void testLogout_TokenNotFound() {
        when(jwtRepository.findByToken("token")).thenReturn(Optional.empty());
        RuntimeException ex = assertThrows(RuntimeException.class, () -> {
            userService.logout("token");
        });
        assertEquals("404 NOT_FOUND \"Token not found\"", ex.getMessage());
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
    @Test
    void testChangePassword_UserNotFound() {
        String email = "notfound@example.com";
        ChangePasswordRequest request = new ChangePasswordRequest();
        request.setCurrentPassword("old");
        request.setNewPassword("new");
        request.setConfirmPassword("new");

        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> {
            userService.changePassword(email, request);
        });

        assertEquals("404 NOT_FOUND \"User not found\"", ex.getMessage());
    }
    @Test
    void testChangePassword_IncorrectCurrentPassword() {
        String email = "user@example.com";
        User user = new User();
        user.setPassword("encodedPassword");
        ChangePasswordRequest request = new ChangePasswordRequest();
        request.setCurrentPassword("wrongPassword");
        request.setNewPassword("new");
        request.setConfirmPassword("new");
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrongPassword", "encodedPassword")).thenReturn(false);
        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> {
            userService.changePassword(email, request);
        });
        assertEquals("400 BAD_REQUEST \"Current password is incorrect\"", ex.getMessage());
    }
    @Test
    void testChangePassword_NewPasswordsDoNotMatch() {
        String email = "user@example.com";
        User user = new User();
        user.setPassword("encodedPassword");
        ChangePasswordRequest request = new ChangePasswordRequest();
        request.setCurrentPassword("correctPassword");
        request.setNewPassword("newPass1");
        request.setConfirmPassword("newPass2");
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("correctPassword", "encodedPassword")).thenReturn(true);
        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> {
            userService.changePassword(email, request);
        });
        assertEquals("400 BAD_REQUEST \"Passwords do not match\"", ex.getMessage());
    }
    @Test
    void testGetProfile_Success() {
        User user = new User();
        user.setNickname("TestUser");
        user.setProfileImageUrl("/uploads/test.jpg");
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
        UserProfileResponse response = userService.getProfile("test@example.com");
        assertEquals("TestUser", response.getNickname());
        assertEquals("/uploads/test.jpg", response.getProfileImageUrl());
    }
    @Test
    void testGetProfile_UserNotFound() {
        when(userRepository.findByEmail("notfound@example.com")).thenReturn(Optional.empty());
        assertThrows(UsernameNotFoundException.class, () ->
                userService.getProfile("notfound@example.com")
        );
    }
    @Test
    void testUpdateProfile_UpdateNicknameAndImage() throws IOException {
        User user = new User();
        user.setNickname("OldName");
        MultipartFile image = mock(MultipartFile.class);
        when(image.isEmpty()).thenReturn(false);
        when(image.getOriginalFilename()).thenReturn("avatar.jpg");
        when(image.getInputStream()).thenReturn(new ByteArrayInputStream("fake image content".getBytes()));
        String newNickname = "NewNickname";
        userService.updateProfile(user, image, newNickname);
        assertEquals("NewNickname", user.getNickname());
        assertNotNull(user.getProfileImageUrl());
        assertTrue(user.getProfileImageUrl().startsWith("/uploads/"));
        verify(userRepository).save(user);
    }
    @Test
    void testDeleteUserAccount_Success() {
        User user=new User();
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
        userService.deleteUserAccount("test@example.com");
        verify(userRepository).delete(user);
    }
    @Test
    void testDeleteUserAccount_UserNotFound() {
        when(userRepository.findByEmail("notfound@example.com")).thenReturn(Optional.empty());
        assertThrows(UsernameNotFoundException.class, () ->
                userService.deleteUserAccount("notfound@example.com")
        );
    }

}
