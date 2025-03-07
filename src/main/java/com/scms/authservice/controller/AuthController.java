package com.scms.authservice.controller;

import com.scms.authservice.request.LoginRequest;
import com.scms.authservice.request.RegisterRequest;
import com.scms.authservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public String register(@RequestBody RegisterRequest request) {
        return authService.registerUser(request);
    }

    @PostMapping("/login")
    public AccessTokenResponse login(@RequestBody LoginRequest request) {
        return authService.loginUser(request);
    }

    @PutMapping("/activate/{userId}")
    @PreAuthorize("hasAuthority('ROLE_scms_admin')")
    public String activateUser(@PathVariable String userId) {
        return authService.activateUser(userId);
    }
}
