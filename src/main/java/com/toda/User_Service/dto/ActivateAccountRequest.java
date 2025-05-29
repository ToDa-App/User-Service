package com.toda.User_Service.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ActivateAccountRequest {
    @NotBlank(message = "Email must not be blank")
    @Email(message = "Email format is invalid")
    private String email;
    @NotBlank
    private String otp;
}
