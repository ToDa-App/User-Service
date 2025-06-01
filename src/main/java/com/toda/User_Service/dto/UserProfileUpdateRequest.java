package com.toda.User_Service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema(description = "Request to update profile")
public class UserProfileUpdateRequest {
    @Schema(description = "New nickname", example = "Mohamed")
    private String nickname;
    @Schema(description = "New profile image URL", example = "https://domain.com/new-image.png")
    private String profileImageUrl;
}
