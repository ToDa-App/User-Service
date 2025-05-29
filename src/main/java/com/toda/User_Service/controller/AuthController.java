package com.toda.User_Service.controller;

import com.toda.User_Service.dto.ActivateAccountRequest;
import com.toda.User_Service.dto.RegisterRequest;
import com.toda.User_Service.exception.ApiGenericResponse;
import com.toda.User_Service.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;
    @PostMapping("/register")
    public ResponseEntity<ApiGenericResponse<Object>> register(@RequestBody @Valid RegisterRequest request) {
        userService.register(request);
        return ResponseEntity.ok(ApiGenericResponse.success("User registered successfully", null));
    }
    @PostMapping("/activate")
    public ResponseEntity<ApiGenericResponse<Object>> activate(@RequestBody @Valid ActivateAccountRequest request) {
        userService.activate(request);
        return ResponseEntity.ok(ApiGenericResponse.success("Account activated successfully.", null));
    }
}
