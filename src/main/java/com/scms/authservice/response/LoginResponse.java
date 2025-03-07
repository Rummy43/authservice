package com.scms.authservice.response;

import lombok.Data;

@Data
public class LoginResponse {
    private String accessToken;
    private String refreshToken;
    private String username;
    private String role;
    private String lastPasswordChange;
}
