package com.scms.authservice.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserResponse {
    private String userId;
    private String firstName;
    private String lastName;
    private String email;
}
