package com.scms.authservice.service;

import com.scms.authservice.model.UserActivity;
import com.scms.authservice.repository.UserActivityRepository;
import com.scms.authservice.request.LoginRequest;
import com.scms.authservice.request.RegisterRequest;
import com.scms.authservice.response.UserResponse;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

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

        // Create User Representation
        UserRepresentation user = new UserRepresentation();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setFirstName(request.getFirstName());  // Added First Name
        user.setLastName(request.getLastName());    // Added Last Name
        user.setEnabled(false);
        user.setCredentials(Collections.singletonList(createPasswordCredentials(request.getPassword())));

        // Create user in Keycloak
        Response response = keycloak.realm(realm).users().create(user);
        if (response.getStatus() != 201) {
            return "Registration Failed: " + response.getStatus();
        }

        // Get the created user ID
        String userId = getUserIdByUsername(request.getUsername());

        // Assign Role to User
        assignRoleToUser(userId, request.getRole(),keycloak);

        logActivity(request.getUsername(), "User Registered (Pending)");
        return "User Registered Successfully";
    }

    // Fetch User ID by Username
    private String getUserIdByUsername(String username) {
        Keycloak keycloak = getKeycloakAdmin();
        return keycloak.realm(realm).users().search(username).get(0).getId();
    }

    // Assign Role to User
    private void assignRoleToUser(String userId, String roleName,Keycloak keycloak) {
        RoleRepresentation role = keycloak.realm(realm).roles().get(roleName).toRepresentation();
        keycloak.realm(realm).users().get(userId).roles().realmLevel().add(Collections.singletonList(role));
    }

    /**
     * Authenticates a user and returns token.
     */
    public Map<String, Object> loginUser(LoginRequest request) {
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

        // Fetch user details
        UserRepresentation user = getUserByUsername(request.getUsername()); //keycloak.realm(realm).users().search(request.getUsername()).get(0);

        // Prepare response
        Map<String, Object> response = new HashMap<>();
        response.put("access_token", tokenResponse.getToken());
        response.put("refresh_token", tokenResponse.getRefreshToken());
        response.put("username", user.getUsername());
        response.put("email", user.getEmail());
        response.put("first_name", user.getFirstName());
        response.put("last_name", user.getLastName());

        logActivity(request.getUsername(), "User Logged In");
        return response;
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

    private UserRepresentation getUserByUsername(String username) {
        Keycloak keycloakAdmin = getKeycloakAdmin(); // Use admin client
        List<UserRepresentation> users = keycloakAdmin.realm(realm).users().search(username);
        if (users.isEmpty()) {
            throw new RuntimeException("User not found");
        }
        return users.get(0);
    }

    private void logActivity(String userId, String activity) {
        UserActivity log = new UserActivity();
        log.setUserId(userId);
        log.setActivity(activity);
        log.setTimestamp(LocalDateTime.now());
        userActivityRepository.save(log);
    }

    public String markEmailAsVerified(String userId) {
        Keycloak keycloak = getKeycloakAdmin();
        UserRepresentation user = keycloak.realm(realm).users().get(userId).toRepresentation();
        user.setEmailVerified(true);
        keycloak.realm(realm).users().get(userId).update(user);
        logActivity(userId, "Email Verified");
        return "Email marked as verified";
    }

    public String createRole(String roleName) {
        Keycloak keycloak = getKeycloakAdmin();
        RoleRepresentation role = new RoleRepresentation();
        role.setName(roleName);
        keycloak.realm(realm).roles().create(role);
        return "Role created: " + roleName;
    }

    public List<String> getRoles() {
        Keycloak keycloak = getKeycloakAdmin();
        return keycloak.realm(realm).roles().list().stream()
                .map(RoleRepresentation::getName)
                .collect(Collectors.toList());
    }

    public String deactivateUser(String userId) {
        Keycloak keycloak = getKeycloakAdmin();
        UserRepresentation user = keycloak.realm(realm).users().get(userId).toRepresentation();
        user.setEnabled(false);
        keycloak.realm(realm).users().get(userId).update(user);
        logActivity(userId, "User Deactivated");
        return "User Deactivated Successfully";
    }

    public String deleteUser(String userId) {
        Keycloak keycloak = getKeycloakAdmin();
        keycloak.realm(realm).users().get(userId).remove();
        logActivity(userId, "User Deleted");
        return "User Deleted Successfully";
    }

    public List<UserResponse> getUsers(){
        Keycloak keycloak = getKeycloakAdmin();
        List<UserRepresentation> usersList = keycloak.realm(realm).users().list();
        List<UserResponse> userResponses = new ArrayList<>();
        for(UserRepresentation userRepresentation : usersList){
            userResponses.add(UserResponse.builder().userId(userRepresentation.getId())
                         .firstName(userRepresentation.getFirstName())
                         .lastName(userRepresentation.getLastName())
                         .email(userRepresentation.getEmail())
                         .build());
        }
        return userResponses;
    }

    public String deleteRole(String roleName) {
        Keycloak keycloak = getKeycloakAdmin();
        keycloak.realm(realm).roles().deleteRole(roleName);
        return "Role Deleted Successfully";
    }

    public String updateUser(String userId, RegisterRequest request) {
        Keycloak keycloak = getKeycloakAdmin();
        UserRepresentation user = keycloak.realm(realm).users().get(userId).toRepresentation();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());

        // Update Role
        assignRoleToUser(userId, request.getRole(),keycloak);

        keycloak.realm(realm).users().get(userId).update(user);
        logActivity(userId, "User Updated");
        return "User Updated Successfully";
    }



}
