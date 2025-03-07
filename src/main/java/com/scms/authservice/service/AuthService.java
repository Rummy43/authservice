package com.scms.authservice.service;

import com.scms.authservice.model.UserActivity;
import com.scms.authservice.repository.UserActivityRepository;
import com.scms.authservice.request.LoginRequest;
import com.scms.authservice.request.RegisterRequest;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Collections;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserActivityRepository userActivityRepository;

    @Value("${keycloak.auth-server-url}")
    private String keycloakServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String clientSecret;

    /**
     * Registers a new user in Keycloak.
     */
    public String registerUser(RegisterRequest request) {
        Keycloak keycloak = getKeycloakAdmin();
        UserRepresentation user = new UserRepresentation();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setEnabled(false);  // Pending status
        user.setCredentials(Collections.singletonList(createPasswordCredentials(request.getPassword())));

        Response response = keycloak.realm(realm).users().create(user);
        if (response.getStatus() == 201) {
            logActivity(request.getUsername(), "User Registered (Pending)");
            return "User Registered Successfully";
        } else {
            return "Registration Failed: " + response.getStatus();
        }
    }

    /**
     * Authenticates a user and returns token.
     */
    public AccessTokenResponse loginUser(LoginRequest request) {
        Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl(keycloakServerUrl)
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .username(request.getUsername())
                .password(request.getPassword())
                .grantType("password")
                .build();

        AccessTokenResponse tokenResponse = keycloak.tokenManager().getAccessToken();
        logActivity(request.getUsername(), "User Logged In");
        return tokenResponse;
    }

    /**
     * Updates user status from PENDING to ACTIVE.
     */
    public String activateUser(String userId) {
        Keycloak keycloak = getKeycloakAdmin();
        UserRepresentation user = keycloak.realm(realm).users().get(userId).toRepresentation();
        user.setEnabled(true);
        keycloak.realm(realm).users().get(userId).update(user);
        logActivity(userId, "User Activated");
        return "User Activated Successfully";
    }

    private Keycloak getKeycloakAdmin() {
        return KeycloakBuilder.builder()
                .serverUrl(keycloakServerUrl)
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .grantType("client_credentials")
                .build();
    }

    private CredentialRepresentation createPasswordCredentials(String password) {
        CredentialRepresentation passwordRep = new CredentialRepresentation();
        passwordRep.setType(CredentialRepresentation.PASSWORD);
        passwordRep.setValue(password);
        passwordRep.setTemporary(false);
        return passwordRep;
    }

    private void logActivity(String userId, String activity) {
        UserActivity log = new UserActivity();
        log.setUserId(userId);
        log.setActivity(activity);
        log.setTimestamp(LocalDateTime.now());
        userActivityRepository.save(log);
    }
}
