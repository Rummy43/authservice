package com.scms.authservice.controller;

import com.scms.authservice.request.LoginRequest;
import com.scms.authservice.request.RegisterRequest;
import com.scms.authservice.response.UserResponse;
import com.scms.authservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

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
    public Map<String, Object> login(@RequestBody LoginRequest request) {
        return authService.loginUser(request);
    }

    @PutMapping("/activate/{userId}")
    @PreAuthorize("hasAuthority('ROLE_scms_admin')")
    public String activateUser(@PathVariable String userId) {
        return authService.activateUser(userId);
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('ROLE_scms_admin')")
    public List<UserResponse> getUsers(){
        return authService.getUsers();
    }

    @PutMapping("/verify-email/{userId}")
    @PreAuthorize("hasAuthority('ROLE_scms_admin')")
    public String verifyEmail(@PathVariable String userId) {
        return authService.markEmailAsVerified(userId);
    }

    @PostMapping("/role")
    @PreAuthorize("hasAuthority('ROLE_scms_admin')")
    public String createRole(@RequestParam String roleName) {
        return authService.createRole(roleName);
    }

    @GetMapping("/roles")
    @PreAuthorize("hasAuthority('ROLE_scms_admin')")
    public List<String> getRoles() {
        return authService.getRoles();
    }

    @PutMapping("/deactivate/{userId}")
    @PreAuthorize("hasAuthority('ROLE_scms_admin')")
    public String deactivateUser(@PathVariable String userId) {
        return authService.deactivateUser(userId);
    }

    @DeleteMapping("/user/{userId}")
    @PreAuthorize("hasAuthority('ROLE_scms_admin')")
    public String deleteUser(@PathVariable String userId) {
        return authService.deleteUser(userId);
    }

    @DeleteMapping("/role/{roleName}")
    @PreAuthorize("hasAuthority('ROLE_scms_admin')")
    public String deleteRole(@PathVariable String roleName) {
        return authService.deleteRole(roleName);
    }

    @PutMapping("/user/{userId}")
    @PreAuthorize("hasAuthority('ROLE_scms_admin')")
    public String updateUser(@PathVariable String userId, @RequestBody RegisterRequest request) {
        return authService.updateUser(userId, request);
    }


}
