package com.toda.User_Service.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserProfileUpdateRequest {
    private String nickname;
    private String profileImageUrl;
}
