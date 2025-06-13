package com.toda.User_Service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Schema(description = "User profile response")
public class UserProfileResponse {
    @Schema(description = "User nickname", example = "Ahmed")
    private String nickname;
    @Schema(description = "Profile image URL", example = "https://domain.com/image.png")
    private String profileImageUrl;
}
